"""Loads a PCAP file and counts contents with various levels of storage"""

import os
import pickle
from enum import Enum
from logging import warning, info, error, debug
from collections import Counter, defaultdict
from scapy.all import sniff
from typing import Any, List
import dpkt
from rich import print


class PCAPDissectorType(Enum):
    COUNT_ONLY = 1
    THROUGH_IP = 2
    DETAILED = 10


class PCAPDissector:
    "loads a pcap file and counts the contents in both time and depth"
    TOTAL_COUNT: str = "__TOTAL__"
    TOTAL_SUBKEY: str = "packet"
    DISECTION_VERSION: int = 3

    def __init__(
        self,
        pcap_file: str,
        bin_size: int = 0,
        maximum_count: int = 0,
        dissector_level: PCAPDissectorType = PCAPDissectorType.DETAILED,
        pcap_filter: str | None = None,
        cache_results: bool = False,
    ):
        self.pcap_file = pcap_file
        self.bin_size = bin_size
        self.dissector_level = dissector_level
        self.pcap_filter = pcap_filter
        self.maximum_count = maximum_count
        self.cache_results = cache_results

        self.parameters = [
            "pcap_file",
            "bin_size",
            "dissector_level",
            "pcap_filter",
            "maximum_count",
        ]

        # TODO: convert to a factory
        self.data = {0: defaultdict(Counter)}

        if dissector_level == PCAPDissectorType.COUNT_ONLY and bin_size == 0:
            warning("counting packets only with no binning is unlikely to be helpful")

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = value

    @staticmethod
    def find_data(
        data,
        timestamps: List[int] | None = None,
        match_string: str | None = None,
        match_value: str | None = None,
        minimum_count: int | None = None,
        make_printable: bool = False,
    ):
        if not timestamps:
            timestamps = data.keys()
        for timestamp in timestamps:
            for key in sorted(data[timestamp]):
                if match_string and match_string not in key:
                    continue

                for subkey, count in sorted(
                    data[timestamp][key].items(), key=lambda x: x[1], reverse=True
                ):

                    if minimum_count and abs(count) < minimum_count:
                        continue

                    if make_printable:
                        subkey = PCAPDissector.make_printable(subkey)
                        count = PCAPDissector.make_printable(count)

                    if match_value and match_value not in subkey:
                        continue

                    yield (timestamp, key, subkey, count)

    def incr(self, key: str, value: Any, count: int = 1):
        # always save a total count at the zero bin
        # note: there should be no recorded tcpdump files from 1970 Jan 01 :-)
        self.data[0][key][value] += count
        if self.timestamp:
            if self.timestamp not in self.data:
                self.data[self.timestamp] = defaultdict(Counter)
            self.data[self.timestamp][key][value] += count

    def load(self) -> dict:
        cached_file = self.pcap_file + ".pkl"
        if self.cache_results and os.path.exists(cached_file):
            cached_contents = self.load_saved(cached_file, dont_overwrite=True)

            ok_to_load = True

            if cached_contents["PCAP_DISECTION_VERSION"] != self.DISECTION_VERSION:
                ok_to_load = False

            # a zero really is a 1 since bin(0) still does int(timestamp)
            if cached_contents["parameters"]["bin_size"] == 0:
                cached_contents["parameters"]["bin_size"] = 1

            for parameter in self.parameters:
                if (
                    getattr(self, parameter)
                    and getattr(self, parameter)
                    != cached_contents["parameters"][parameter]
                ):
                    debug(
                        f"parameter {parameter} doesn't match: {getattr(self, parameter)} != {cached_contents['parameters'][parameter]}"
                    )
                    ok_to_load = False

            if ok_to_load:
                info(f"loading cached pcap contents from {cached_file}")
                self.load_saved_contents(cached_contents)
                return self.data

            error(f"Failed to load cached data for {self.pcap_file} due to differences")
            error("refusing to continue -- remove the cache to recreate it")
            exit(1)

        if (
            self.dissector_level == PCAPDissectorType.DETAILED
            or self.dissector_level == PCAPDissectorType.DETAILED.value
        ):
            return self.load_via_scapy()
        else:
            return self.load_via_dpkt()

    def dpkt_callback(self, timestamp: float, packet: bytes):
        # if binning is requested, save it in a binned time slot
        self.timestamp = int(timestamp)
        if self.bin_size:
            self.timestamp = self.timestamp - self.timestamp % self.bin_size
        self.incr(self.TOTAL_COUNT, self.TOTAL_SUBKEY)

        if self.dissector_level == PCAPDissectorType.THROUGH_IP.value:
            eth = dpkt.ethernet.Ethernet(packet)
            # these names are designed to match scapy names
            self.incr("Ethernet.dst", eth.dst)
            self.incr("Ethernet.src", eth.src)
            self.incr("Ethernet.type", eth.type)

            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data

                IPVER = "IP"
                if ip.v == 6:
                    IPVER = "IPv6"

                # TODO: make sure all these match scapy
                self.incr(f"Ethernet.{IPVER}.dst", ip.dst)
                self.incr(f"Ethernet.{IPVER}.src", ip.src)
                self.incr(f"Ethernet.{IPVER}.df", ip.df)
                self.incr(f"Ethernet.{IPVER}.offset", ip.offset)
                self.incr(f"Ethernet.{IPVER}.tos", ip.tos)
                self.incr(f"Ethernet.{IPVER}.len", ip.len)
                self.incr(f"Ethernet.{IPVER}.id", ip.id)
                self.incr(f"Ethernet.{IPVER}.hl", ip.hl)
                self.incr(f"Ethernet.{IPVER}.rf", ip.rf)
                self.incr(f"Ethernet.{IPVER}.p", ip.p)
                self.incr(f"Ethernet.{IPVER}.chksum", ip.sum)
                self.incr(f"Ethernet.{IPVER}.tos", ip.tos)
                self.incr(f"Ethernet.{IPVER}.version", ip.v)
                self.incr(f"Ethernet.{IPVER}.ttl", ip.ttl)

                if isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    self.incr(f"Ethernet.{IPVER}.UDP.sport", udp.sport)
                    self.incr(f"Ethernet.{IPVER}.UDP.dport", udp.dport)
                    self.incr(f"Ethernet.{IPVER}.UDP.len", udp.ulen)
                    self.incr(f"Ethernet.{IPVER}.UDP.chksum", udp.sum)

                    # TODO: handle DNS and others for level 3

                elif isinstance(ip.data, dpkt.tcp.TCP):
                    # TODO
                    tcp = ip.data
                    self.incr(f"Ethernet.{IPVER}.TCP.sport", tcp.sport)
                    self.incr(f"Ethernet.{IPVER}.TCP.dport", tcp.dport)
                    self.incr(f"Ethernet.{IPVER}.TCP.seq", tcp.seq)
                    self.incr(f"Ethernet.{IPVER}.TCP.flags", tcp.flags)
                    # self.incr(f"Ethernet.{IPVER}.TCP.reserved", tcp.reserved)
                    self.incr(f"Ethernet.{IPVER}.TCP.window", tcp.win)
                    self.incr(f"Ethernet.{IPVER}.TCP.chksum", tcp.sum)
                    self.incr(f"Ethernet.{IPVER}.TCP.options", tcp.opts)

                    # TODO: handle DNS and others for level 3

    def load_via_dpkt(self) -> dict:
        self.data = {0: defaultdict(Counter)}
        pcap = dpkt.pcap.Reader(open(self.pcap_file, "rb"))
        if self.pcap_filter:
            pcap.setfilter(self.pcap_filter)
        pcap.dispatch(self.maximum_count, self.dpkt_callback)

        if self.cache_results:
            self.save(self.pcap_file + ".pkl")
        return self.data

    def add_scapy_item(self, field_value, prefix: str) -> None:
        "Adds an item to the self.data regardless of it's various types"
        if isinstance(field_value, list):
            if len(field_value) > 0:
                # if it's a list of tuples, count the (eg TCP option) names
                # TODO: values can be always the same or things like timestamps
                #       that will always change or are too unique
                if isinstance(field_value[0], tuple):
                    for item in field_value:
                        self.incr(prefix, item[0])
                else:
                    for item in field_value:
                        self.add_scapy_item(item, prefix)
            # else:
            #     debug(f"ignoring empty-list: {field_value}")
        elif (
            isinstance(field_value, str)
            or isinstance(field_value, int)
            or isinstance(field_value, float)
        ):
            self.incr(prefix, field_value)

        elif isinstance(field_value, bytes):
            try:
                converted = field_value.decode("utf-8")
                self.incr(prefix, converted)
            except Exception:
                converted = "0x" + field_value.hex()
                self.incr(prefix, converted)

    def add_scapy_layer(self, layer, prefix: str | None = "") -> None:
        "Analyzes a layer to add counts to each layer sub-component"

        if hasattr(layer, "fields_desc"):
            name_list = [field.name for field in layer.fields_desc]
        elif hasattr(layer, "fields"):
            name_list = [field.name for field in layer.fields]
        else:
            warning(f"unavailable to deep dive into: {layer}")
            return

        for field_name in name_list:
            field_value = getattr(layer, field_name)
            if hasattr(field_value, "fields"):
                self.add_scapy_layer(field_value, prefix + field_name + ".")
            else:
                self.add_scapy_item(field_value, prefix + field_name)

    def scapy_callback(self, packet):
        prefix = "."
        self.timestamp = int(packet.time)
        if self.bin_size:
            self.timestamp = self.timestamp - self.timestamp % self.bin_size

        self.incr(self.TOTAL_COUNT, self.TOTAL_SUBKEY)
        for payload in packet.iterpayloads():
            prefix = f"{prefix}{payload.name}."
            self.add_scapy_layer(payload, prefix[1:])

    def load_via_scapy(self) -> dict:
        "Loads a pcap file into a nested dictionary of statistical counts"
        sniff(
            offline=self.pcap_file,
            prn=self.scapy_callback,
            store=0,
            count=self.maximum_count,
            filter=self.pcap_filter,
        )
        if self.cache_results:
            self.save(self.pcap_file + ".pkl")
        return self.data

    def save(self, where: str) -> None:
        "Saves a generated dissection to a pickle file"

        # wrap the report in a version header
        versioned_cache = {
            "PCAP_DISECTION_VERSION": self.DISECTION_VERSION,
            "file": self.pcap_file,
            "parameters": {},
            "dissection": self.data,
        }

        for parameter in self.parameters:

            versioned_cache["parameters"][parameter] = getattr(self, parameter)
            # TODO: fix this hack

            # basically, bin_size of 0 is 1...  but it may be faster
            # to leave it at zero to avoid the bin_size math of 1,
            # which is actually a math noop that will still consume
            # cycles.  We save it as 1 though since the math is past
            # us and a 1 value is more informative to the user.
            if parameter == "bin_size" and self.bin_size == 0:
                versioned_cache["parameters"][parameter] = 1

        # save it
        info(f"caching PCAP data to '{where}'")
        pickle.dump(versioned_cache, open(where, "wb"))

    def load_saved_contents(self, versioned_cache):
        # set the local parameters from the cache
        for parameter in self.parameters:
            setattr(self, parameter, versioned_cache["parameters"][parameter])

        # load the data
        self.data = versioned_cache["dissection"]

    def load_saved(self, where: str, dont_overwrite: bool = False) -> dict:
        "Loads a previous saved report from a file instead of re-parsing pcaps"
        contents = pickle.load(open(where, "rb"))

        # check that the version header matches something we understand
        if contents["PCAP_DISECTION_VERSION"] != self.DISECTION_VERSION:
            raise ValueError(
                "improper saved dissection version: report version = "
                + str(contents["PCAP_COMPARE_VERSION"])
                + ", our version: "
                + str(self.DISECTION_VERSION)
            )

        if not dont_overwrite:
            self.load_saved_contents(contents)

        return contents

    @staticmethod
    def make_printable(value: Any) -> str:
        try:
            value = str(value)
        except Exception:
            if isinstance(value, bytes):
                value = "0x" + value.hex()
            else:
                value = ["unprintable"]
        return value

    def print(
        self,
        timestamps: List[int] | None = [0],
        match_string: str | None = None,
        match_value: str | None = None,
        minimum_count: int | None = None,
    ) -> None:
        for (timestamp, key, subkey, value) in self.find_data(
            self._data,
            timestamps=timestamps,
            match_string=match_string,
            match_value=match_value,
            minimum_count=minimum_count,
            make_printable=True,
        ):
            print(f"{key:<30} {subkey:<30} {value}")


def dissector_add_parseargs(parser, add_subgroup: bool = True):
    if add_subgroup:
        parser = parser.add_argument_group("Parsing Options")

    parser.add_argument(
        "-d",
        "--dissection-level",
        default=PCAPDissectorType.THROUGH_IP.value,
        type=int,
        help="Dump to various levels of detail (1-10, with 10 is the most detailed and slowest)",
    )

    parser.add_argument(
        "-n",
        "--packet-count",
        default=-1,
        type=int,
        help="Maximum number of packets to analyze",
    )

    parser.add_argument(
        "-s",
        "--save-report",
        default=None,
        type=str,
        help="Where to save a report file for quicker future loading",
    )

    parser.add_argument(
        "-l",
        "--load-report",
        default=None,
        type=str,
        help="Load a report from a pickle file rather than use pcaps",
    )

    parser.add_argument(
        "-C",
        "--cache-pcap-results",
        action="store_true",
        help="Cache and use PCAP results into/from a .pkl file",
    )

    return parser


def limitor_add_parseargs(parser, add_subgroup: bool = True):
    if add_subgroup:
        parser = parser.add_argument_group("Limiting options")

    parser.add_argument(
        "-m",
        "--match-string",
        default=None,
        type=str,
        help="Only report on data with this substring in the header",
    )

    parser.add_argument(
        "-M",
        "--match-value",
        default=None,
        type=str,
        help="Only report on data with this substring in the packet value field",
    )

    parser.add_argument(
        "-c",
        "--minimum-count",
        default=None,
        type=float,
        help="Don't include results without this high of a record count",
    )

    return parser


def check_dissector_level(level: int):
    current_dissection_levels = [
        PCAPDissectorType.COUNT_ONLY.value,
        PCAPDissectorType.THROUGH_IP.value,
        PCAPDissectorType.DETAILED.value,
    ]
    if level not in current_dissection_levels:
        error(f"currently supported dissection levels: {current_dissection_levels}")
        exit(1)
    return True


def main():
    from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
    import logging

    def parse_args():
        "Parse the command line arguments."
        parser = ArgumentParser(
            formatter_class=ArgumentDefaultsHelpFormatter,
            description=__doc__,
            epilog="Exmaple Usage: ",
        )

        parser.add_argument(
            "--log-level",
            "--ll",
            default="info",
            help="Define the logging verbosity level (debug, info, warning, error, fotal, critical).",
        )

        dissector_add_parseargs(parser)
        limitor_add_parseargs(parser)

        parser.add_argument("input_file", type=str, help="input pcap file")

        args = parser.parse_args()
        log_level = args.log_level.upper()
        logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")
        return args

    args = parse_args()

    check_dissector_level(args.dissection_level)

    pd = PCAPDissector(
        args.input_file,
        bin_size=0,
        dissector_level=args.dissection_level,
        maximum_count=args.packet_count,
        cache_results=args.cache_pcap_results,
    )
    pd.load()
    pd.print(
        timestamps=[0],
        match_string=args.match_string,
        match_value=args.match_value,
        minimum_count=args.minimum_count,
    )


if __name__ == "__main__":
    main()
