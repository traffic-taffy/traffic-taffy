"""A PCAP Dissector that can a pcap into enumerated pieces."""

from __future__ import annotations

import sys
from collections import Counter, defaultdict
from logging import error, warning, debug, info
from typing import List
import importlib
from typing import TYPE_CHECKING, Any

from rich import print

from traffic_taffy.dissection import Dissection, PCAPDissectorLevel
from traffic_taffy.hooks import call_hooks
from traffic_taffy.taffy_config import TaffyConfig, taffy_default

if TYPE_CHECKING:
    from argparse import Parser


class TTD_CFG:
    KEY_DISSECTOR: str = "dissect"

    BIN_SIZE: str = "bin_size"
    CACHE_FILE_SUFFIX: str = "cache_file_suffix"
    CACHE_PCAP_RESULTS: str = "cache_pcap_results"
    DISSECTION_LEVEL: str = "dissection_level"
    FILTER: str = "filter"
    FILTER_ARGUMENTS: str = "filter_arguments"
    FORCE_LOAD: str = "force_load"
    FORCE_OVERWRITE: str = "force_overwrite"
    IGNORE_LIST: str = "ignore_list"
    LAYERS: str = "layers"
    MERGE: str = "merge"
    MODULES: str = "use_modules"
    PACKET_COUNT: str = "packet_count"


class TTL_CFG:
    KEY_LIMITOR: str = "limit_output"

    MATCH_EXPRESSION: str = "match_expression"
    MATCH_STRING: str = "match_string"
    MATCH_VALUE: str = "match_value"
    MINIMUM_COUNT: str = "minimum_count"


POST_DISSECT_HOOK: str = "post_dissect"
INIT_HOOK: str = "init_hooks"


def dissector_default(name: str, value: Any) -> None:
    taffy_default(TTD_CFG.KEY_DISSECTOR + "." + name, value)


dissector_default("dissection_level", PCAPDissectorLevel.THROUGH_IP.value)
dissector_default("packet_count", 0)
dissector_default("bin_size", None)
dissector_default("filter", None)
dissector_default("layers", [])
dissector_default("use_modules", None)
dissector_default("merge", False)
dissector_default("cache_pcap_results", False)
dissector_default("force_overwrite", False)
dissector_default("force_load", False)
dissector_default("cache_file_suffix", "taffy")
dissector_default("maximum_cores", 20)  # TODO(hardaker): fix double forking


def limitor_default(name: str, value: Any) -> None:
    taffy_default(TTL_CFG.KEY_LIMITOR + "." + name, value)


limitor_default("match_string", None)
limitor_default("match_value", None)
limitor_default("match_expression", None)
limitor_default("minimum_count", None)

dissector_default(
    "ignore_list",
    [
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
)


class PCAPDissector:
    """loads a pcap file and counts the contents in both time and depth."""

    def __init__(
        self,
        pcap_file: str,
        config: TaffyConfig | None = None,
    ) -> None:
        """Create a dissector object."""
        self.pcap_file = pcap_file
        self.config = config
        if not self.config:
            config = TaffyConfig()

        dissection_config = config[TTD_CFG.KEY_DISSECTOR]

        self.dissector_level = dissection_config[TTD_CFG.DISSECTION_LEVEL]
        self.pcap_filter = dissection_config[TTD_CFG.FILTER]
        self.maximum_count = dissection_config[TTD_CFG.PACKET_COUNT]
        self.cache_results = dissection_config[TTD_CFG.CACHE_PCAP_RESULTS]
        self.bin_size = dissection_config[TTD_CFG.BIN_SIZE]
        self.cache_file_suffix = dissection_config[TTD_CFG.CACHE_FILE_SUFFIX]
        if self.cache_file_suffix[0] != ".":
            self.cache_file_suffix = "." + self.cache_file_suffix
        self.ignore_list = dissection_config[TTD_CFG.IGNORE_LIST]
        if self.ignore_list is None:
            self.ignore_list = []
        self.layers = dissection_config[TTD_CFG.LAYERS]
        self.force_overwrite = dissection_config[TTD_CFG.FORCE_OVERWRITE]
        self.force_load = dissection_config[TTD_CFG.FORCE_LOAD]

        if self.dissector_level == PCAPDissectorLevel.COUNT_ONLY and self.bin_size == 0:
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
        """Load dissector contents from a cached file."""
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

        debug(f"dissecting using {engine}")
        self.dissection = engine.load()
        debug("done dissecting")
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
        match_expression: str | None = None,
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
            match_expression=match_expression,
        ):
            print(f"{key:<30} {subkey:<30} {value}")

    def print_to_fsdb(
        self: PCAPDissector,
        timestamps: list[int] | None = None,
        match_string: str | None = None,
        match_value: str | None = None,
        minimum_count: int | None = None,
        match_expression: str | None = None,
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
            match_expression=match_expression,
        ):
            fh.append([key, subkey, value])
        fh.close()


def dissector_add_parseargs(
    parser: Parser, config: TaffyConfig | None = None, add_subgroup: bool = True
) -> None:
    """Add arguments related to disection."""
    if add_subgroup:
        parser = parser.add_argument_group("Dissection Options", config_path="dissect")

    if not config:
        config = TaffyConfig()

    dissection_config = config[TTD_CFG.KEY_DISSECTOR]
    parser.add_argument(
        "-d",
        "--dissection-level",
        config_path=TTD_CFG.DISSECTION_LEVEL,
        default=dissection_config[TTD_CFG.DISSECTION_LEVEL],
        type=int,
        help="Dump to various levels of detail (1-10, with 10 is the most detailed and slowest)",
    )

    parser.add_argument(
        "-I",
        "--ignore-list",
        config_path=TTD_CFG.IGNORE_LIST,
        default=dissection_config[TTD_CFG.IGNORE_LIST],
        nargs="*",
        type=str,
        help="A list of (unlikely to be useful) packet fields to ignore",
    )

    parser.add_argument(
        "-n",
        "--packet-count",
        config_path=TTD_CFG.PACKET_COUNT,
        default=dissection_config[TTD_CFG.PACKET_COUNT],
        type=int,
        help="Maximum number of packets to analyze",
    )

    parser.add_argument(
        "-b",
        "--bin-size",
        config_path=TTD_CFG.BIN_SIZE,
        default=dissection_config[TTD_CFG.BIN_SIZE],
        type=int,
        help="Bin results into this many seconds",
    )

    parser.add_argument(
        "-F",
        "--filter",
        config_path=TTD_CFG.FILTER,
        default=dissection_config[TTD_CFG.FILTER],
        type=str,
        help="filter to apply to the pcap file when processing",
    )

    parser.add_argument(
        "-L",
        "--layers",
        config_path=TTD_CFG.LAYERS,
        default=dissection_config[TTD_CFG.LAYERS],
        type=str,
        nargs="*",
        help="List of extra layers to load (eg: tls, http, etc)",
    )

    parser.add_argument(
        "-x",
        "--modules",
        config_path=TTD_CFG.MODULES,
        default=dissection_config[TTD_CFG.MODULES],
        type=str,
        nargs="*",
        help="Extra processing modules to load (currently: psl) ",
    )

    parser.add_argument(
        "--merge",
        "--merge-files",
        config_path=TTD_CFG.MERGE,
        default=dissection_config[TTD_CFG.MERGE],
        action="store_true",
        help="Dissect multiple files as one.  (compare by time)",
    )

    parser.add_argument(
        "-C",
        "--cache-pcap-results",
        config_path=TTD_CFG.CACHE_PCAP_RESULTS,
        action="store_true",
        help="Cache and use PCAP results into/from a cache file file",
    )

    parser.add_argument(
        "--cache-file-suffix",
        "--cs",
        type=str,
        config_path=TTD_CFG.CACHE_FILE_SUFFIX,
        default=dissection_config[TTD_CFG.CACHE_FILE_SUFFIX],
        help="The suffix file to use when creating cache files",
    )

    parser.add_argument(
        "--force-overwrite",
        action="store_true",
        config_path="force_overwrite",
        help="Force continuing with an incompatible cache (and rewriting it)",
    )

    parser.add_argument(
        "--force-load",
        action="store_true",
        config_path="force_load",
        help="Force continuing with an incompatible cache (trying to load it anyway)",
    )

    return parser


def limitor_add_parseargs(
    parser, config: TaffyConfig = None, add_subgroup: bool = True
):
    if add_subgroup:
        parser = parser.add_argument_group(
            "Limiting options", config_path=TTL_CFG.KEY_LIMITOR
        )

    if not config:
        config = TaffyConfig()

    limitor_config = config[TTL_CFG.KEY_LIMITOR]
    parser.add_argument(
        "-m",
        "--match-string",
        config_path=TTL_CFG.MATCH_STRING,
        default=limitor_config[TTL_CFG.MATCH_STRING],
        type=str,
        help="Only report on data with this substring in the header",
    )

    parser.add_argument(
        "-M",
        "--match-value",
        config_path=TTL_CFG.MATCH_VALUE,
        default=limitor_config[TTL_CFG.MATCH_VALUE],
        type=str,
        nargs="*",
        help="Only report on data with this substring in the packet value field",
    )

    parser.add_argument(
        "-E",
        "--match-expression",
        config_path=TTL_CFG.MATCH_EXPRESSION,
        default=limitor_config[TTL_CFG.MATCH_EXPRESSION],
        type=str,
        help="Match expression to be evaluated at runtime for returning data",
    )

    parser.add_argument(
        "-c",
        "--minimum-count",
        config_path=TTL_CFG.MINIMUM_COUNT,
        default=limitor_config[TTL_CFG.MINIMUM_COUNT],
        type=float,
        help="Don't include results without this high of a record count",
    )

    return parser


def dissector_handle_arguments(args) -> None:
    """Handle checking and loading arguments."""
    check_dissector_level(args.dissection_level)
    dissector_load_extra_modules(args.modules)
    call_hooks(INIT_HOOK)


def dissector_load_extra_modules(modules: List[str]) -> None:
    """Load extra modules."""
    if not modules:
        return
    for module in modules:
        try:
            importlib.import_module(f"traffic_taffy.hooks.{module}")
            info(f"loaded module: {module}")
        except Exception as exp:
            error(f"failed to load module {module}: {exp}")


def check_dissector_level(level: int) -> bool:
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
