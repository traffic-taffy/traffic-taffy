"""A PCAP Dissector that can a pcap into enumerated pieces."""

from __future__ import annotations

import sys
from collections import Counter, defaultdict
from logging import error, warning
from typing import List
import importlib

from rich import print

from traffic_taffy.dissection import Dissection, PCAPDissectorLevel
from traffic_taffy.hooks import call_hooks

POST_DISSECT_HOOK: str = "post_dissect"


class PCAPDissector:
    """loads a pcap file and counts the contents in both time and depth."""

    def __init__(
        self,
        pcap_file: str,
        bin_size: int = 0,
        maximum_count: int = 0,
        dissector_level: PCAPDissectorLevel = PCAPDissectorLevel.DETAILED,
        pcap_filter: str | None = None,
        cache_results: bool = False,
        cache_file_suffix: str = "taffy",
        ignore_list: list | None = None,
        layers: List[str] | None = None,
        force_overwrite: bool = False,
        force_load: bool = False,
        merge_files: bool = False,  # Note: unused for a single load
    ) -> None:
        """Create a dissector object."""
        if ignore_list is None:
            ignore_list = []
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
        self.layers = layers
        self.force_overwrite = force_overwrite
        self.force_load = force_load

        if dissector_level == PCAPDissectorLevel.COUNT_ONLY and bin_size == 0:
            warning("counting packets only with no binning is unlikely to be helpful")

    @property
    def dissection(self: PCAPDissector) -> Dissection:
        """Dissection created by parsing the pcap."""
        return self._dissection

    @dissection.setter
    def dissection(self: PCAPDissector, new_dissection: Dissection) -> None:
        self._dissection = new_dissection

    def dissection_args(self: PCAPDissector) -> tuple:
        """Return arguments for creating a Dissection object."""
        return (
            self.pcap_file,
            self.pcap_filter,
            self.maximum_count,
            self.bin_size,
            self.dissector_level,
            self.cache_file_suffix,
            set(self.ignore_list),
            self.layers,
        )

    def load_from_cache(
        self: PCAPDissector, force_overwrite: bool = False, force_load: bool = False
    ) -> Dissection:
        if self.cache_results:
            args = self.dissection_args()
            self.dissection = Dissection(*args)
            cached_data = self.dissection.load_from_cache(
                force_overwrite=force_overwrite, force_load=force_load
            )
            if cached_data:
                return cached_data
            return None
        return None

    def load(
        self: PCAPDissector, force_overwrite: bool = False, force_load: bool = False
    ) -> dict:
        """Load data from a pcap file or its cached results."""
        cached_data = self.load_from_cache(
            force_overwrite=force_overwrite, force_load=force_load
        )
        if cached_data:
            return cached_data

        engine = None
        args = self.dissection_args()

        if isinstance(self.pcap_file, str) and (
            self.pcap_file.endswith(".dnstap") or self.pcap_file.endswith(".tap")
        ):
            # we delay loading until the module and its requirements are needed
            from traffic_taffy.dissector_engine.dnstap import DissectionEngineDNStap

            engine = DissectionEngineDNStap(*args)

        elif (
            self.dissector_level == PCAPDissectorLevel.DETAILED
            or self.dissector_level == PCAPDissectorLevel.DETAILED.value
        ):
            from traffic_taffy.dissector_engine.scapy import DissectionEngineScapy

            engine = DissectionEngineScapy(*args)
        else:
            from traffic_taffy.dissector_engine.dpkt import DissectionEngineDpkt

            engine = DissectionEngineDpkt(*args)

        self.dissection = engine.load()
        call_hooks(POST_DISSECT_HOOK, dissection=self.dissection)

        if self.cache_results:
            self.dissection.save_to_cache()
        return self.dissection

    def print(
        self: PCAPDissector,
        timestamps: list[int] | None = None,
        match_string: str | None = None,
        match_value: str | None = None,
        minimum_count: int | None = None,
    ) -> None:
        """Print the results to the console."""
        if timestamps is None:
            timestamps = [0]
        for _, key, subkey, value in self.dissection.find_data(
            timestamps=timestamps,
            match_string=match_string,
            match_value=match_value,
            minimum_count=minimum_count,
            make_printable=True,
        ):
            print(f"{key:<30} {subkey:<30} {value}")

    def print_to_fsdb(
        self: PCAPDissector,
        timestamps: list[int] | None = None,
        match_string: str | None = None,
        match_value: str | None = None,
        minimum_count: int | None = None,
    ) -> None:
        """Output the results in an FSDB file."""
        if timestamps is None:
            timestamps = [0]
        import pyfsdb

        fh = pyfsdb.Fsdb(
            out_file_handle=sys.stdout,
            out_column_names=["key", "subkey", "value"],
            converters={"value": int},
        )
        for _, key, subkey, value in self.dissection.find_data(
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
        default=[
            "Ethernet_IP_TCP_seq",
            "Ethernet_IP_TCP_ack",
            "Ethernet_IPv6_TCP_seq",
            "Ethernet_IPv6_TCP_ack",
            "Ethernet_IPv6_TCP_Raw_load",
            "Ethernet_IP_UDP_Raw_load",
            "Ethernet_IP_UDP_DNS_id",
            "Ethernet_IP_ICMP_IP in ICMP_UDP in ICMP_chksum",
            "Ethernet_IP_ICMP_IP in ICMP_UDP in ICMP_Raw_load",
            "Ethernet_IP_ICMP_IP in ICMP_chksum",
            "Ethernet_IP_ICMP_IP in ICMP_id",
            "Ethernet_IP_TCP_DNS_id",
            "Ethernet_IPv6_UDP_DNS_id",
            "Ethernet_IPv6_TCP_DNS_id",
            "Ethernet_IP_id",
            "Ethernet_IP_chksum",
            "Ethernet_IP_UDP_chksum",
            "Ethernet_IP_TCP_chksum",
            "Ethernet_IP_TCP_window",
            "Ethernet_IP_TCP_Raw_load",
            "Ethernet_IP_UDP_Raw_load",
            "Ethernet_IPv6_UDP_chksum",
            "Ethernet_IPv6_fl",
            "Ethernet_IP_ICMP_chksum",
            "Ethernet_IP_ICMP_id",
            "Ethernet_IP_ICMP_seq",
            "Ethernet_IP_TCP_Padding_load",
            "Ethernet_IP_TCP_window",
            "Ethernet_IPv6_TCP_chksum",
            "Ethernet_IPv6_plen",
            "Ethernet_IP_TCP_Encrypted Content_load",
            "Ethernet_IP_TCP_TLS_TLS_Raw_load",
        ],
        nargs="*",
        type=str,
        help="A list of (unlikely to be useful) packet fields to ignore",
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
        "-F",
        "--filter",
        default=None,
        type=str,
        help="filter to apply to the pcap file when processing",
    )

    parser.add_argument(
        "-L",
        "--layers",
        default=[],
        type=str,
        nargs="*",
        help="List of extra layers to load (eg: tls, http, etc)",
    )

    parser.add_argument(
        "-x",
        "--modules",
        default=None,
        type=str,
        nargs="*",
        help="Extra processing modules to load (currently: psl) ",
    )

    parser.add_argument(
        "--merge",
        "--merge-files",
        action="store_true",
        help="Dissect multiple files as one.  (compare by time)",
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
        default="taffy",
        help="The suffix file to use when creating cache files",
    )

    parser.add_argument(
        "--force-overwrite",
        action="store_true",
        help="Force continuing with an incompatible cache (and rewriting it)",
    )

    parser.add_argument(
        "--force-load",
        action="store_true",
        help="Force continuing with an incompatible cache (trying to load it anyway)",
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
        nargs="*",
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


def dissector_handle_arguments(args) -> None:
    check_dissector_level(args.dissection_level)
    dissector_load_extra_modules(args.modules)


def dissector_load_extra_modules(modules: List[str]) -> None:
    """Loads extra modules"""
    if not modules:
        return
    for module in modules:
        try:
            importlib.import_module(f"traffic_taffy.hooks.{module}")
        except Exception as exp:
            error(f"failed to load module {module}: {exp}")


def check_dissector_level(level: int):
    """Check that the dissector level is legal."""
    current_dissection_levels = [
        PCAPDissectorLevel.COUNT_ONLY.value,
        PCAPDissectorLevel.THROUGH_IP.value,
        PCAPDissectorLevel.COMMON_LAYERS.value,
        PCAPDissectorLevel.DETAILED.value,
    ]
    if level not in current_dissection_levels:
        error(f"currently supported dissection levels: {current_dissection_levels}")
        sys.exit(1)
    return True


def pcap_data_merge(d1: dict, d2: dict) -> dict:
    """Merge counters in deep d2 dict into d1 -- note destructive to d1."""
    for key in d2:
        for subkey in d2[key]:
            if key not in d1:
                d1[key] = defaultdict(Counter)
            d1[key][subkey] += d2[key][subkey]
    return d1
