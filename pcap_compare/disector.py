"""Loads a PCAP file and counts contents with various levels of storage"""

import os
import pickle
from enum import Enum
from logging import warning, info
from collections import Counter, defaultdict
from scapy.all import sniff
from typing import Any


class PCAPDisectorType(Enum):
    DETAILED = 1
    COUNT_ONLY = 2


class PCAPDisector:
    "loads a pcap file and counts the contents in both time and depth"
    TOTAL_COUNT: str = "__TOTAL__"
    TOTAL_SUBKEY: str = "packet"
    DISECTION_VERSION: int = 2

    def __init__(
        self,
        pcap_file: str,
        bin_size: int = 0,
        maximum_count: int = 0,
        disector_type: PCAPDisectorType = PCAPDisectorType.DETAILED,
        pcap_filter: str | None = None,
        cache_results: bool = False,
    ):
        self.pcap_file = pcap_file
        self.bin_size = bin_size
        self.disector_type = disector_type
        self.pcap_filter = pcap_filter
        self.maximum_count = maximum_count
        self.cache_results = cache_results

        self.parameters = [
            "pcap_file",
            "bin_size",
            "disector_type",
            "pcap_filter",
            "maximum_count",
        ]

        # TODO: convert to a factory
        self.data = {0: defaultdict(Counter)}

        if disector_type == PCAPDisectorType.COUNT_ONLY and bin_size == 0:
            warning("counting packets only with no binning is unlikely to be helpful")

    @property
    def data(self):
        return self.__data

    @data.setter
    def data(self, value):
        self.__data = value

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

            for parameter in self.parameters:
                if (
                    getattr(self, parameter)
                    and getattr(self, parameter)
                    != cached_contents["parameters"][parameter]
                ):
                    ok_to_load = False

            if ok_to_load:
                info(f"loading cached pcap contents from {cached_file}")
                self.load_saved_contents(cached_contents)
                return self.data

            warning(
                f"Failed to load cached data for {self.pcap_file} due to differences"
            )

        if self.disector_type == PCAPDisectorType.COUNT_ONLY:
            return self.load_via_dpkt()
        else:
            return self.load_via_scapy()

    def dpkt_callback(self, timestamp: float, packet: bytes):
        # if binning is requested, save it in a binned time slot
        self.timestamp = int(timestamp)
        if self.bin_size:
            self.timestamp = self.timestamp - self.timestamp % self.bin_size
        self.incr(self.TOTAL_COUNT, self.TOTAL_SUBKEY)

    def load_via_dpkt(self) -> dict:
        import dpkt

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
        "Saves a generated disection to a pickle file"

        # wrap the report in a version header
        versioned_cache = {
            "PCAP_DISECTION_VERSION": self.DISECTION_VERSION,
            "file": self.pcap_file,
            "parameters": {},
            "disection": self.data,
        }

        for parameter in self.parameters:
            versioned_cache["parameters"][parameter] = getattr(self, parameter)

        # save it
        info(f"caching PCAP data to '{where}'")
        pickle.dump(versioned_cache, open(where, "wb"))

    def load_saved_contents(self, versioned_cache):
        # set the local parameters from the cache
        for parameter in self.parameters:
            setattr(self, parameter, versioned_cache["parameters"][parameter])

        # load the data
        self.data = versioned_cache["disection"]

    def load_saved(self, where: str, dont_overwrite: bool = False) -> dict:
        "Loads a previous saved report from a file instead of re-parsing pcaps"
        contents = pickle.load(open(where, "rb"))

        # check that the version header matches something we understand
        if contents["PCAP_DISECTION_VERSION"] != self.DISECTION_VERSION:
            raise ValueError(
                "improper saved disection version: report version = "
                + str(contents["PCAP_COMPARE_VERSION"])
                + ", our version: "
                + str(self.DISECTION_VERSION)
            )

        if not dont_overwrite:
            self.load_saved_contents(contents)

        return contents


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
            "-b", "--bin-size", default=1, type=int, help="bin size to use"
        )

        parser.add_argument(
            "-f",
            "--full-dump",
            action="store_true",
            help="Full deep-inspect the packet",
        )

        parser.add_argument(
            "--log-level",
            "--ll",
            default="info",
            help="Define the logging verbosity level (debug, info, warning, error, fotal, critical).",
        )

        parser.add_argument("input_file", type=str, help="input pcap file")

        args = parser.parse_args()
        log_level = args.log_level.upper()
        logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")
        return args

    args = parse_args()
    disect_type = PCAPDisectorType.COUNT_ONLY
    if args.full_dump:
        disect_type = PCAPDisectorType.DETAILED
    pd = PCAPDisector(
        args.input_file,
        bin_size=args.bin_size,
        disector_type=disect_type,
        maximum_count=1000,
    )
    pd.load()
    import rich

    rich.print(pd.data)


if __name__ == "__main__":
    main()
