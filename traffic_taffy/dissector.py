import sys
from logging import warning, error
from collections import Counter, defaultdict
from typing import List
from rich import print
from dissection import PCAPDissectorLevel, Dissection


class PCAPDissector:
    "loads a pcap file and counts the contents in both time and depth"

    def __init__(
        self,
        pcap_file: str,
        bin_size: int = 0,
        maximum_count: int = 0,
        dissector_level: PCAPDissectorLevel = PCAPDissectorLevel.DETAILED,
        pcap_filter: str | None = None,
        cache_results: bool = False,
        cache_file_suffix: str = "pkl",
        ignore_list: list = [],
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
        self.ignore_list = ignore_list

        if dissector_level == PCAPDissectorLevel.COUNT_ONLY and bin_size == 0:
            warning("counting packets only with no binning is unlikely to be helpful")

    @property
    def dissection(self):
        return self._dissection

    @dissection.setter
    def dissection(self, new_dissection):
        self._dissection = new_dissection

    def dissection_args(self):
        return (
            self.pcap_file,
            self.dissector_level,
            self.bin_size,
            self.maximum_count,
            self.pcap_filter,
            self.cache_file_suffix,
            self.ignore_list,
        )

    def load_from_cache(self):
        import pdb

        pdb.set_trace()
        if self.cache_results:
            args = self.dissection_args()
            self.dissection = Dissection(*args)
            cached_data = self.dissection.load_from_cache()
            if cached_data:
                return cached_data

    def load(self) -> dict:
        "Loads data from a pcap file or its cached results"
        cached_data = self.load_from_cache()
        if cached_data:
            return cached_data

        engine = None
        args = self.dissection_args()
        if (
            self.dissector_level == PCAPDissectorLevel.DETAILED
            or self.dissector_level == PCAPDissectorLevel.DETAILED.value
        ):
            from traffic_taffy.dissector_engine.scapy import DissectionEngineScapy

            engine = DissectionEngineScapy(*args)
        else:
            from traffic_taffy.dissector_engine.dpkt import DissectionEngineDpkt

            engine = DissectionEngineDpkt(*args)

        self.dissection = engine.load()
        if self.cache_results:
            self.dissection.save_to_cache()
        return self.dissection

    def print(
        self,
        timestamps: List[int] | None = [0],
        match_string: str | None = None,
        match_value: str | None = None,
        minimum_count: int | None = None,
    ) -> None:
        for timestamp, key, subkey, value in self.dissection.find_data(
            timestamps=timestamps,
            match_string=match_string,
            match_value=match_value,
            minimum_count=minimum_count,
            make_printable=True,
        ):
            print(f"{key:<30} {subkey:<30} {value}")

    def print_to_fsdb(
        self,
        timestamps: List[int] | None = [0],
        match_string: str | None = None,
        match_value: str | None = None,
        minimum_count: int | None = None,
    ) -> None:
        import pyfsdb

        fh = pyfsdb.Fsdb(
            out_file_handle=sys.stdout,
            out_column_names=["key", "subkey", "value"],
            converters={"value": int},
        )
        for timestamp, key, subkey, value in self.dissection.find_data(
            timestamps=timestamps,
            match_string=match_string,
            match_value=match_value,
            minimum_count=minimum_count,
            make_printable=True,
        ):
            fh.append([key, subkey, value])
        fh.close()


def dissector_add_parseargs(parser, add_subgroup: bool = True):
    if add_subgroup:
        parser = parser.add_argument_group("Parsing Options")

    parser.add_argument(
        "-d",
        "--dissection-level",
        default=PCAPDissectorLevel.THROUGH_IP.value,
        type=int,
        help="Dump to various levels of detail (1-10, with 10 is the most detailed and slowest)",
    )

    parser.add_argument(
        "-I",
        "--ignore-list",
        default=",".join(
            [
                "Ethernet.IP.TCP.seq",
                "Ethernet.IP.TCP.ack",
                "Ethernet.IPv6.TCP.seq",
                "Ethernet.IPv6.TCP.ack",
                "Ethernet.IP.UDP.DNS.id",
                "Ethernet.IP.TCP.DNS.id",
                "Ethernet.IPv6.UDP.DNS.id",
                "Ethernet.IPv6.TCP.DNS.id",
                "Ethernet.IP.id",
                "Ethernet.IP.chksum",
                "Ethernet.IP.UDP.chksum",
                "Ethernet.IP.TCP.chksum",
                "Ethernet.IPv6.UDP.chksum" "Ethernet.IPv6.fl",
                "Ethernet.IP.ICMP.chksum",
                "Ethernet.IP.ICMP.id",
                "Ethernet.IP.ICMP.seq",
                "Ethernet.IP.TCP.Padding.load",
                "Ethernet.IPv6.TCP.chksum",
                "Ethernet.IPv6.plen",
            ]
        ),
        type=str,
        help="A comma separated list of (unlikely to be useful) data fields to ignore",
    )

    parser.add_argument(
        "-n",
        "--packet-count",
        default=0,
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
        PCAPDissectorLevel.COUNT_ONLY.value,
        PCAPDissectorLevel.THROUGH_IP.value,
        PCAPDissectorLevel.DETAILED.value,
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

        parser.add_argument(
            "-f",
            "--fsdb",
            action="store_true",
            help="Print results in an FSDB formatted output",
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
        ignore_list=args.ignore_list.split(","),
    )
    pd.load()

    if args.fsdb:
        pd.print_to_fsdb(
            timestamps=[0],
            match_string=args.match_string,
            match_value=args.match_value,
            minimum_count=args.minimum_count,
        )
    else:
        pd.print(
            timestamps=[0],
            match_string=args.match_string,
            match_value=args.match_value,
            minimum_count=args.minimum_count,
        )


if __name__ == "__main__":
    main()
