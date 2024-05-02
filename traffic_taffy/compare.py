"""The primary statistical packet comparison engine."""

from __future__ import annotations
from typing import List, TYPE_CHECKING
from logging import error

if TYPE_CHECKING:
    from traffic_taffy.dissection import Dissection
    from traffic_taffy.comparison import Comparison
    from argparse import ArgumentParser, Namespace

from traffic_taffy.dissectmany import PCAPDissectMany
from traffic_taffy.dissector import PCAPDissectorLevel
from traffic_taffy.algorithms.statistical import ComparisonStatistical
from traffic_taffy.algorithms.comparecorrelation import CompareCorrelation


class PcapCompare:
    """Take a set of PCAPs to then perform various comparisons upon."""

    REPORT_VERSION: int = 2

    def __init__(
        self,
        pcap_files: List[str],
        maximum_count: int = 0,  # where 0 == all
        deep: bool = True,
        pcap_filter: str | None = None,
        cache_results: bool = False,
        cache_file_suffix: str = "taffy",
        bin_size: int | None = None,
        dissection_level: PCAPDissectorLevel = PCAPDissectorLevel.COUNT_ONLY,
        between_times: List[int] | None = None,
        ignore_list: List[str] | None = None,
        layers: List[str] | None = None,
        force_load: bool = False,
        force_overwrite: bool = False,
        merge_files: bool = False,
        algorithm: str = "statistical",
    ) -> None:
        """Create a compare object."""
        self.pcap_files = pcap_files
        self.deep = deep
        self.maximum_count = maximum_count
        self.pcap_filter = pcap_filter
        self.cache_results = cache_results
        self.dissection_level = dissection_level
        self.between_times = between_times
        self.bin_size = bin_size
        self.cache_file_suffix = cache_file_suffix
        self.ignore_list = ignore_list or []
        self.layers = layers
        self.force_overwrite = force_overwrite
        self.force_load = force_load
        self.merge_files = merge_files

        if algorithm == "statistical":
            self.algorithm = ComparisonStatistical()
        elif algorithm == "correlation":
            self.algorithm = CompareCorrelation()
        else:
            error(f"unknown algorithm: {algorithm}")
            raise ValueError()

    @property
    def pcap_files(self) -> List[str]:
        """List of pcap files being compared."""
        return self._pcap_files

    @pcap_files.setter
    def pcap_files(self, new_pcap_files: List[str]) -> None:
        self._pcap_files = new_pcap_files

    @property
    def reports(self) -> List[dict]:
        """List of reports generated by the comparison."""
        return self._reports

    @reports.setter
    def reports(self, newvalue: List[dict]) -> None:
        self._reports = newvalue

    def load_pcaps(self) -> None:
        """Load all pcaps into memory and dissect them."""
        # load the first as a reference pcap
        pdm = PCAPDissectMany(
            self.pcap_files,
            bin_size=self.bin_size,
            maximum_count=self.maximum_count,
            pcap_filter=self.pcap_filter,
            cache_results=self.cache_results,
            cache_file_suffix=self.cache_file_suffix,
            dissector_level=self.dissection_level,
            ignore_list=self.ignore_list,
            layers=self.layers,
            force_load=self.force_load,
            force_overwrite=self.force_overwrite,
            merge_files=self.merge_files,
        )
        return pdm.load_all()

    def compare(self) -> List[Comparison]:
        """Compare each pcap as requested."""
        dissections = self.load_pcaps()
        self.compare_all(dissections)
        return self.reports

    def compare_all(self, dissections: List[Dissection]) -> List[Comparison]:
        """Compare all loaded pcaps."""

        self.reports = self.algorithm.compare_dissections(dissections)
        return self.reports


def compare_add_parseargs(
    compare_parser: ArgumentParser, add_subgroup: bool = True
) -> ArgumentParser:
    """Add common comparison arguments."""
    if add_subgroup:
        compare_parser = compare_parser.add_argument_group("Comparison result options")

    compare_parser.add_argument(
        "-t",
        "--print-threshold",
        default=0.0,
        type=float,
        help="Don't print results with abs(percent) less than this threshold",
    )

    compare_parser.add_argument(
        "-P", "--only-positive", action="store_true", help="Only show positive entries"
    )

    compare_parser.add_argument(
        "-N", "--only-negative", action="store_true", help="Only show negative entries"
    )

    compare_parser.add_argument(
        "-R",
        "--top-records",
        default=None,
        type=int,
        help="Show the top N records from each section.",
    )

    compare_parser.add_argument(
        "-r",
        "--reverse_sort",
        action="store_true",
        help="Reverse the sort order of reports",
    )

    compare_parser.add_argument(
        "-s",
        "--sort-by",
        default="delta%",
        type=str,
        help="Sort report entries by this column",
    )

    compare_parser.add_argument(
        "-A",
        "--algorithm",
        default="statistical",
        type=str,
        help="The algorithm to apply for data comparison (statistical, correlation)",
    )

    # compare_parser.add_argument(
    #     "-T",
    #     "--between-times",

    return compare_parser


def get_comparison_args(args: Namespace) -> dict:
    """Return a dict of comparison parameters from arguments."""
    return {
        "maximum_count": args.packet_count or 0,
        "print_threshold": float(args.print_threshold) / 100.0,
        "minimum_count": args.minimum_count,
        "match_string": args.match_string,
        "only_positive": args.only_positive,
        "only_negative": args.only_negative,
        "top_records": args.top_records,
        "reverse_sort": args.reverse_sort,
        "sort_by": args.sort_by,
        "merge_files": args.merge,
        "algorithm": args.algorithm,
    }
