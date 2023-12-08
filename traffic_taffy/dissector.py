"""Loads a PCAP file and counts contents with various levels of storage"""

import ipaddress
from logging import warning, error
from collections import Counter, defaultdict
from scapy.all import sniff
from typing import Any, List
import dpkt
from rich import print
from pcap_parallel import PCAPParallel as pcapp
from dissection import Dissection, PCAPDissectorType


class PCAPDissector:
    "loads a pcap file and counts the contents in both time and depth"

    def print_mac_address(value):
        "Converts bytes to ethernet mac style address"

        # TODO: certainly inefficient
        def two_hex(value):
            return f"{value:02x}"

        return ":".join(map(two_hex, value))

    display_transformers = {
        "Ethernet.IP.src": ipaddress.ip_address,
        "Ethernet.IP.dst": ipaddress.ip_address,
        "Ethernet.IP6.src": ipaddress.ip_address,
        "Ethernet.IP6.dst": ipaddress.ip_address,
        "Ethernet.src": print_mac_address,
        "Ethernet.dst": print_mac_address,
    }

    def __init__(
        self,
        pcap_file: str,
        bin_size: int = 0,
        maximum_count: int = 0,
        dissector_level: PCAPDissectorType = PCAPDissectorType.DETAILED,
        pcap_filter: str | None = None,
        cache_results: bool = False,
        cache_file_suffix: str = "pkl",
    ):
        self.pcap_file = pcap_file
        self.dissector_level = dissector_level
        self.pcap_filter = pcap_filter
        self.maximum_count = maximum_count
        self.cache_results = cache_results
        self.bin_size = bin_size
        if cache_file_suffix[0] != ".":
            cache_file_suffix = "." + cache_file_suffix
        self.cache_file_suffix = cache_file_suffix

        self.init_dissection()

        if dissector_level == PCAPDissectorType.COUNT_ONLY and bin_size == 0:
            warning("counting packets only with no binning is unlikely to be helpful")

    @property
    def dissection(self):
        return self._dissection

    @dissection.setter
    def dissection(self, new_dissection):
        self._dissection = new_dissection

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

        # find timestamps/key values with at least one item above count
        # TODO: we should really use pandas for this
        usable = defaultdict(set)
        for timestamp in timestamps:
            for key in data[timestamp]:
                # if they requested a match string
                if match_string and match_string not in key:
                    continue

                # ensure at least one of the count valuse for the
                # stream gets above minimum_count
                for subkey, count in data[timestamp][key].items():
                    if (
                        not minimum_count
                        or minimum_count
                        and abs(count) > minimum_count
                    ):
                        usable[key].add(subkey)
                        break

        # TODO: move the timestamp inside the other fors for faster
        # processing of skipped key/subkeys
        for timestamp in timestamps:
            for key in sorted(data[timestamp]):
                if key not in usable:
                    continue

                for subkey, count in sorted(
                    data[timestamp][key].items(), key=lambda x: x[1], reverse=True
                ):
                    # check that this subkey can be usable at all
                    if subkey not in usable[key]:
                        continue

                    if make_printable:
                        subkey = PCAPDissector.make_printable(key, subkey)
                        count = PCAPDissector.make_printable(None, count)

                    if match_value and match_value not in subkey:
                        continue

                    yield (timestamp, key, subkey, count)

    def load_from_cache(self):
        if self.cache_results:
            cached_data = self.dissection.load_from_cache()
            if cached_data:
                return cached_data

    def load(self) -> dict:
        "Loads data from a pcap file or its cached results"
        cached_data = self.load_from_cache()
        if cached_data:
            return cached_data

        if (
            self.dissector_level == PCAPDissectorType.DETAILED
            or self.dissector_level == PCAPDissectorType.DETAILED.value
        ):
            return self.load_via_scapy()
        else:
            return self.load_via_dpkt()

    def dpkt_callback(self, timestamp: float, packet: bytes):
        # if binning is requested, save it in a binned time slot
        dissection: Dissection = self.dissection

        dissection.timestamp = int(timestamp)
        if dissection.bin_size:
            dissection.timestamp = (
                dissection.timestamp - dissection.timestamp % dissection.bin_size
            )

        dissection.incr(Dissection.TOTAL_COUNT, dissection.TOTAL_SUBKEY)

        level = self.dissector_level
        if isinstance(level, PCAPDissectorType):
            level = level.value
        if level >= PCAPDissectorType.THROUGH_IP.value:
            eth = dpkt.ethernet.Ethernet(packet)
            # these names are designed to match scapy names
            dissection.incr("Ethernet.dst", eth.dst)
            dissection.incr("Ethernet.src", eth.src)
            dissection.incr("Ethernet.type", eth.type)

            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data

                IPVER = "IP"
                if ip.v == 6:
                    IPVER = "IPv6"

                # TODO: make sure all these match scapy
                dissection.incr(f"Ethernet.{IPVER}.dst", ip.dst)
                dissection.incr(f"Ethernet.{IPVER}.src", ip.src)
                dissection.incr(f"Ethernet.{IPVER}.df", ip.df)
                dissection.incr(f"Ethernet.{IPVER}.offset", ip.offset)
                dissection.incr(f"Ethernet.{IPVER}.tos", ip.tos)
                dissection.incr(f"Ethernet.{IPVER}.len", ip.len)
                dissection.incr(f"Ethernet.{IPVER}.id", ip.id)
                dissection.incr(f"Ethernet.{IPVER}.hl", ip.hl)
                dissection.incr(f"Ethernet.{IPVER}.rf", ip.rf)
                dissection.incr(f"Ethernet.{IPVER}.p", ip.p)
                dissection.incr(f"Ethernet.{IPVER}.chksum", ip.sum)
                dissection.incr(f"Ethernet.{IPVER}.tos", ip.tos)
                dissection.incr(f"Ethernet.{IPVER}.version", ip.v)
                dissection.incr(f"Ethernet.{IPVER}.ttl", ip.ttl)

                if isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    dissection.incr(f"Ethernet.{IPVER}.UDP.sport", udp.sport)
                    dissection.incr(f"Ethernet.{IPVER}.UDP.dport", udp.dport)
                    dissection.incr(f"Ethernet.{IPVER}.UDP.len", udp.ulen)
                    dissection.incr(f"Ethernet.{IPVER}.UDP.chksum", udp.sum)

                    # TODO: handle DNS and others for level 3

                elif isinstance(ip.data, dpkt.tcp.TCP):
                    # TODO
                    tcp = ip.data
                    dissection.incr(f"Ethernet.{IPVER}.TCP.sport", tcp.sport)
                    dissection.incr(f"Ethernet.{IPVER}.TCP.dport", tcp.dport)
                    dissection.incr(f"Ethernet.{IPVER}.TCP.seq", tcp.seq)
                    dissection.incr(f"Ethernet.{IPVER}.TCP.flags", tcp.flags)
                    # dissection.incr(f"Ethernet.{IPVER}.TCP.reserved", tcp.reserved)
                    dissection.incr(f"Ethernet.{IPVER}.TCP.window", tcp.win)
                    dissection.incr(f"Ethernet.{IPVER}.TCP.chksum", tcp.sum)
                    dissection.incr(f"Ethernet.{IPVER}.TCP.options", tcp.opts)

                    # TODO: handle DNS and others for level 3

    def init_dissection(self) -> Dissection:
        self.dissection = Dissection(
            pcap_file=self.pcap_file,
            dissector_level=self.dissector_level,
            bin_size=self.bin_size,
            pcap_filter=self.pcap_filter,
            maximum_count=self.maximum_count,
            cache_file_suffix=self.cache_file_suffix,
        )
        return self.dissection

    def load_via_dpkt(self) -> Dissection:
        self.init_dissection()
        if isinstance(self.pcap_file, str):
            pcap = dpkt.pcap.Reader(pcapp.open_maybe_compressed(self.pcap_file))
        else:
            # it's an open handle already
            pcap = dpkt.pcap.Reader(self.pcap_file)
        if self.pcap_filter:
            pcap.setfilter(self.pcap_filter)
        pcap.dispatch(self.maximum_count, self.dpkt_callback)

        self.dissection.calculate_metadata()
        if self.cache_results:
            self.dissection.save_to_cache()
        return self.dissection

    def add_scapy_item(self, field_value, prefix: str) -> None:
        "Adds an item to the self.dissection regardless of it's various types"
        if isinstance(field_value, list):
            if len(field_value) > 0:
                # if it's a list of tuples, count the (eg TCP option) names
                # TODO: values can be always the same or things like timestamps
                #       that will always change or are too unique
                if isinstance(field_value[0], tuple):
                    for item in field_value:
                        self.dissection.incr(prefix, item[0])
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
            self.dissection.incr(prefix, field_value)

        elif isinstance(field_value, bytes):
            try:
                converted = field_value.decode("utf-8")
                self.dissection.incr(prefix, converted)
            except Exception:
                converted = "0x" + field_value.hex()
                self.dissection.incr(prefix, converted)

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
            try:
                field_value = getattr(layer, field_name)
                if hasattr(field_value, "fields"):
                    self.add_scapy_layer(field_value, prefix + field_name + ".")
                else:
                    self.add_scapy_item(field_value, prefix + field_name)
            except Exception:
                warning(f"scapy error at '{prefix}' in field '{field_name}'")

    def scapy_callback(self, packet):
        prefix = "."
        self.timestamp = int(packet.time)
        if self.bin_size:
            self.timestamp = self.timestamp - self.timestamp % self.bin_size

        self.dissection.incr(self.TOTAL_COUNT, self.TOTAL_SUBKEY)
        for payload in packet.iterpayloads():
            prefix = f"{prefix}{payload.name}."
            self.add_scapy_layer(payload, prefix[1:])

    def load_via_scapy(self) -> Dissection:
        "Loads a pcap file into a nested dictionary of statistical counts"
        load_this = self.pcap_file
        if isinstance(self.pcap_file, str):
            load_this = pcapp.open_maybe_compressed(self.pcap_file)
        sniff(
            offline=load_this,
            prn=self.scapy_callback,
            store=0,
            count=self.maximum_count,
            filter=self.pcap_filter,
        )
        self.dissection.calculate_metadata()
        if self.cache_results:
            self.save_to_cache()
        return self.dissection

    @staticmethod
    def make_printable(value_type: str, value: Any) -> str:
        try:
            if isinstance(value, bytes):
                if value_type in PCAPDissector.display_transformers:
                    value = str(PCAPDissector.display_transformers[value_type](value))
                else:
                    value = "0x" + value.hex()
            else:
                value = str(value)
        except Exception:
            if isinstance(value, bytes):
                value = "0x" + value.hex()
            else:
                value = "[unprintable]"
        if len(value) > 40:
            value = value[0:40] + "..."  # truncate to reasonable
        return value

    def print(
        self,
        timestamps: List[int] | None = [0],
        match_string: str | None = None,
        match_value: str | None = None,
        minimum_count: int | None = None,
    ) -> None:
        for timestamp, key, subkey, value in self.find_data(
            self.dissection.data,
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
        "-b",
        "--bin-size",
        type=int,
        help="Bin results into this many seconds",
    )

    parser.add_argument(
        "-C",
        "--cache-pcap-results",
        action="store_true",
        help="Cache and use PCAP results into/from a cache file file",
    )

    parser.add_argument(
        "--cache-file-suffix",
        "--cs",
        type=str,
        default="pkl",
        help="The suffix file to use when creating cache files",
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


def pcap_data_merge(d1: dict, d2: dict):
    "merges counters in deep d2 dict into d1 -- note destructive to d1"
    for key in d2:
        for subkey in d2[key]:
            if key not in d1:
                d1[key] = defaultdict(Counter)
            d1[key][subkey] += d2[key][subkey]
    return d1


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
        bin_size=args.bin_size,
        dissector_level=args.dissection_level,
        maximum_count=args.packet_count,
        cache_results=args.cache_pcap_results,
        cache_file_suffix=args.cache_file_suffix,
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
