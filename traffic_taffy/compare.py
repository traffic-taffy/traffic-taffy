"""Takes a set of pcap files to compare and creates a report"""

import logging
from logging import info, debug
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from typing import List

from traffic_taffy.comparison import Comparison
from traffic_taffy.dissectmany import PCAPDissectMany
from traffic_taffy.output.console import Console
from traffic_taffy.dissector import (
    PCAPDissectorType,
    dissector_add_parseargs,
    limitor_add_parseargs,
    check_dissector_level,
)


class PcapCompare:
    "Takes a set of PCAPs to then perform various comparisons upon"

    REPORT_VERSION: int = 2

    def __init__(
        self,
        pcaps: List[str],
        maximum_count: int | None = None,
        deep: bool = True,
        print_threshold: float = 0.0,
        minimum_count: int | None = None,
        print_match_string: str | None = None,
        pkt_filter: str | None = None,
        only_positive: bool = False,
        only_negative: bool = False,
        cache_results: bool = False,
        cache_file_suffix: str = "pkl",
        bin_size: int | None = None,
        dissection_level: PCAPDissectorType = PCAPDissectorType.COUNT_ONLY,
        between_times: List[int] | None = None,
    ) -> None:
        self.pcaps = pcaps
        self.deep = deep
        self.maximum_count = maximum_count
        self.print_threshold = print_threshold
        self.minimum_count = minimum_count
        self.print_match_string = print_match_string
        self.pkt_filter = pkt_filter
        self.only_positive = only_positive
        self.only_negative = only_negative
        self.cache_results = cache_results
        self.dissection_level = dissection_level
        self.between_times = between_times
        self.bin_size = bin_size
        self.cache_file_suffix = cache_file_suffix

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
            left_side_total = left_side[key].total()
            right_side_total = right_side[key].total()
            report[key] = {}

            for subkey in left_side[key].keys():
                delta = 0.0
                total = 0
                if subkey in left_side[key] and subkey in right_side[key]:
                    delta = (
                        right_side[key][subkey] / right_side_total
                        - left_side[key][subkey] / left_side_total
                    )
                    total = right_side[key][subkey] + left_side[key][subkey]
                    left_count = left_side[key][subkey]
                    right_count = right_side[key][subkey]
                else:
                    delta = -1.0
                    total = left_side[key][subkey]
                    left_count = left_side[key][subkey]
                    right_count = 0

                report[key][subkey] = {
                    "delta": delta,
                    "total": total,
                    "left_count": left_count,
                    "right_count": right_count,
                }

            for subkey in right_side[key].keys():
                if subkey not in report[key]:
                    delta = 1.0
                    total = right_side[key][subkey]
                    left_count = 0
                    right_count = right_side[key][subkey]

                    report[key][subkey] = {
                        "delta": delta,
                        "total": total,
                        "left_count": left_count,
                        "right_count": right_count,
                    }

        return Comparison(report)

    def load_pcaps(self) -> None:
        # load the first as a reference pcap
        info(f"reading pcap files using level={self.dissection_level}")
        pdm = PCAPDissectMany(
            self.pcaps,
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
        if len(self.pcaps) > 1:
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
                report.title = f"time {time_left} vs time {time_right}"
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

    def print(self) -> None:
        "outputs the results"
        printing_arguments = {
            "only_positive": self.only_positive,
            "only_negative": self.only_negative,
            "print_threshold": self.print_threshold,
            "minimum_count": self.minimum_count,
            "match_string": self.print_match_string,
            # "match_value": self.print_match_value,
        }
        for report in self.reports:
            report.print(printing_arguments)


def parse_args():
    "Parse the command line arguments."
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description=__doc__,
        epilog="Exmaple Usage: ",
    )

    limiting_parser = limitor_add_parseargs(parser)

    limiting_parser.add_argument(
        "-t",
        "--print-threshold",
        default=0.0,
        type=float,
        help="Don't print results with abs(percent) less than this threshold",
    )

    limiting_parser.add_argument(
        "-P", "--only-positive", action="store_true", help="Only show positive entries"
    )

    limiting_parser.add_argument(
        "-N", "--only-negative", action="store_true", help="Only show negative entries"
    )

    limiting_parser.add_argument(
        "-T",
        "--between-times",
        nargs=2,
        type=int,
        help="For single files, only display results between these timestamps",
    )

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
    pc = PcapCompare(
        args.pcap_files,
        cache_results=args.cache_pcap_results,
        cache_file_suffix=args.cache_file_suffix,
        dissection_level=args.dissection_level,
        between_times=args.between_times,
        bin_size=args.bin_size,
    )

    printing_arguments = {
        "maximum_count": args.packet_count,
        "print_threshold": float(args.print_threshold) / 100.0,
        "minimum_count": args.minimum_count,
        "print_match_string": args.match_string,
        "only_positive": args.only_positive,
        "only_negative": args.only_negative,
    }

    # compare the pcaps
    reports = pc.compare()
    console = Console(None, printing_arguments)
    for report in reports:
        # output results to the console
        console.output(report)


if __name__ == "__main__":
    main()
