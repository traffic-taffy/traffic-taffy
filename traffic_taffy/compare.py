"""Takes a set of pcap files to compare and creates a report"""

import logging
from logging import info, debug
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from typing import List
import datetime as dt
from datetime import datetime

from traffic_taffy.comparison import Comparison
from traffic_taffy.dissectmany import PCAPDissectMany
from traffic_taffy.output.console import Console
from traffic_taffy.output.fsdb import Fsdb
from traffic_taffy.dissector import (
    PCAPDissectorLevel,
    dissector_add_parseargs,
    limitor_add_parseargs,
    check_dissector_level,
)


class PcapCompare:
    "Takes a set of PCAPs to then perform various comparisons upon"

    REPORT_VERSION: int = 2

    def __init__(
        self,
        pcap_files: List[str],
        maximum_count: int = 0,  # where 0 == all
        deep: bool = True,
        pkt_filter: str | None = None,
        cache_results: bool = False,
        cache_file_suffix: str = "taffy",
        bin_size: int | None = None,
        dissection_level: PCAPDissectorLevel = PCAPDissectorLevel.COUNT_ONLY,
        between_times: List[int] | None = None,
    ) -> None:
        self.pcap_files = pcap_files
        self.deep = deep
        self.maximum_count = maximum_count
        self.pkt_filter = pkt_filter
        self.cache_results = cache_results
        self.dissection_level = dissection_level
        self.between_times = between_times
        self.bin_size = bin_size
        self.cache_file_suffix = cache_file_suffix

    @property
    def pcap_files(self):
        return self._pcap_files

    @pcap_files.setter
    def pcap_files(self, new_pcap_files):
        self._pcap_files = new_pcap_files

    @property
    def reports(self):
        return self._reports

    @reports.setter
    def reports(self, newvalue):
        self._reports = newvalue

    def compare_dissections(self, left_side: dict, right_side: dict) -> dict:
        "compares the results from two reports"

        report = {}

        # TODO: missing key in right_side (major items added)
        keys = set(left_side.keys())
        keys = keys.union(right_side.keys())
        for key in keys:
            report[key] = {}

            if key not in left_side:
                left_side[key] = {}
            left_side_total = sum(left_side[key].values())

            if key not in right_side:
                right_side[key] = {}
            right_side_total = sum(right_side[key].values())

            for subkey in left_side[key].keys():
                delta_percentage = 0.0
                total = 0
                if subkey in left_side[key] and subkey in right_side[key]:
                    delta_percentage = (
                        right_side[key][subkey] / right_side_total
                        - left_side[key][subkey] / left_side_total
                    )
                    total = right_side[key][subkey] + left_side[key][subkey]
                    left_count = left_side[key][subkey]
                    right_count = right_side[key][subkey]
                else:
                    delta_percentage = -1.0
                    total = -left_side[key][subkey]
                    left_count = left_side[key][subkey]
                    right_count = 0

                delta_absolute = right_count - left_count
                report[key][subkey] = {
                    "delta_percentage": delta_percentage,
                    "delta_absolute": delta_absolute,
                    "total": total,
                    "left_count": left_count,
                    "right_count": right_count,
                }

            for subkey in right_side[key].keys():
                if subkey not in report[key]:
                    delta_percentage = 1.0
                    total = right_side[key][subkey]
                    left_count = 0
                    right_count = right_side[key][subkey]

                    report[key][subkey] = {
                        "delta_percentage": delta_percentage,
                        "delta_absolute": right_count,
                        "total": total,
                        "left_count": left_count,
                        "right_count": right_count,
                    }

        return Comparison(report)

    def load_pcaps(self) -> None:
        # load the first as a reference pcap
        info(f"reading pcap files using level={self.dissection_level}")
        pdm = PCAPDissectMany(
            self.pcap_files,
            bin_size=self.bin_size,
            maximum_count=self.maximum_count,
            pcap_filter=self.pkt_filter,
            cache_results=self.cache_results,
            cache_file_suffix=self.cache_file_suffix,
            dissector_level=self.dissection_level,
        )
        results = pdm.load_all()
        return results

    def compare(self) -> List[Comparison]:
        "Compares each pcap against the original source"

        dissections = self.load_pcaps()
        self.compare_all(dissections)
        return self.reports

    def compare_all(self, dissections) -> List[Comparison]:
        reports = []
        if len(self.pcap_files) > 1:
            # multiple file comparison
            reference = next(dissections)
            for other in dissections:
                # compare the two global summaries

                report = self.compare_dissections(reference.data[0], other.data[0])
                report.title = f"{reference.pcap_file} vs {other.pcap_file}"

                reports.append(report)
        else:
            # deal with timestamps within a single file
            reference = list(dissections)[0].data
            timestamps = list(reference.keys())
            debug(
                f"found {len(timestamps)} timestamps from {timestamps[2]} to {timestamps[-1]}"
            )

            for timestamp in range(
                2, len(timestamps)
            ):  # second real non-zero timestamp to last
                time_left = timestamps[timestamp - 1]
                time_right = timestamps[timestamp]

                # see if we were asked to only use particular time ranges
                if self.between_times and (
                    time_left < self.between_times[0]
                    or time_right > self.between_times[1]
                ):
                    # debug(f"skipping timestamps {time_left} and {time_right}")
                    continue

                debug(f"comparing timestamps {time_left} and {time_right}")

                report = self.compare_dissections(
                    reference[time_left],
                    reference[time_right],
                )

                title_left = datetime.fromtimestamp(time_left, dt.UTC).strftime(
                    "%Y-%m-%d %H:%M"
                )
                title_right = datetime.fromtimestamp(time_right, dt.UTC).strftime(
                    "%Y-%m-%d %H:%M"
                )

                report.title = f"time {title_left} vs time {title_right}"
                reports.append(report)

                continue

                # takes way too much memory to do it "right"
                # reports.append(
                #     {
                #         "report": report,
                #         "title": f"time {time_left} vs time {time_right}",
                #     }
                # )

        self.reports = reports
        return reports


def compare_add_parseargs(compare_parser, add_subgroup: bool = True):
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
        "-x",
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
        "-T",
        "--between-times",
        nargs=2,
        type=int,
        help="For single files, only display results between these timestamps",
    )

    return compare_parser


def get_comparison_args(args):
    return {
        "maximum_count": args.packet_count or 0,
        "print_threshold": float(args.print_threshold) / 100.0,
        "minimum_count": args.minimum_count,
        "match_string": args.match_string,
        "only_positive": args.only_positive,
        "only_negative": args.only_negative,
        "top_records": args.top_records,
        "reverse_sort": args.reverse_sort,
    }


def parse_args():
    "Parse the command line arguments."
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description=__doc__,
        epilog="Exmaple Usage: ",
    )

    output_options = parser.add_argument_group("Output format")
    output_options.add_argument(
        "-f",
        "--fsdb",
        action="store_true",
        help="Print results in an FSDB formatted output",
    )

    limitor_parser = limitor_add_parseargs(parser)
    compare_add_parseargs(limitor_parser, False)
    dissector_add_parseargs(parser)

    debugging_group = parser.add_argument_group("Debugging options")

    debugging_group.add_argument(
        "--log-level",
        "--ll",
        default="info",
        help="Define the logging verbosity level (debug, info, warning, error, ...).",
    )

    parser.add_argument("pcap_files", type=str, nargs="*", help="PCAP files to analyze")

    args = parser.parse_args()
    log_level = args.log_level.upper()
    logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")

    check_dissector_level(args.dissection_level)

    return args


def main():
    args = parse_args()

    # setup output options
    printing_arguments = get_comparison_args(args)

    # get our files to compare (maybe just one)
    left = args.pcap_files.pop(0)
    right = None
    more_than_one = False

    if len(args.pcap_files) > 0:
        right = args.pcap_files.pop(0)
        more_than_one = True

    while left:
        files = [left]
        if right:
            files.append(right)

        pc = PcapCompare(
            files,
            cache_results=args.cache_pcap_results,
            cache_file_suffix=args.cache_file_suffix,
            maximum_count=printing_arguments["maximum_count"],
            dissection_level=args.dissection_level,
            between_times=args.between_times,
            bin_size=args.bin_size,
        )

        # compare the pcaps
        reports = pc.compare()

        if args.fsdb:
            output = Fsdb(None, printing_arguments)
        else:
            output = Console(None, printing_arguments)

        for report in reports:
            # output results to the console
            output.output(report)

        left = right
        right = None
        if len(args.pcap_files) > 0:
            right = args.pcap_files.pop(0)

        if left and not right and more_than_one:
            left = None


if __name__ == "__main__":
    main()
