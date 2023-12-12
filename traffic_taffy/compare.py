"""Takes a set of pcap files to compare and creates a report"""

import logging
from logging import info, debug
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from typing import List
from rich.console import Console
from traffic_taffy.dissectmany import PCAPDissectMany
from traffic_taffy.dissector import (
    PCAPDissectorType,
    dissector_add_parseargs,
    limitor_add_parseargs,
    check_dissector_level,
)
from traffic_taffy.dissection import Dissection


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
        self.console = None
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

        return report

    def filter_check(self, data: dict) -> bool:
        "Returns true if we should include it"
        delta: float = data["delta"]
        total: int = data["total"]

        if self.only_positive and delta <= 0:
            return False

        if self.only_negative and delta >= 0:
            return False

        if not self.print_threshold and not self.minimum_count:
            # always print
            return True

        if self.print_threshold and not self.minimum_count:
            # check print_threshold as a fraction
            if abs(delta) > self.print_threshold:
                return True
        elif not self.print_threshold and self.minimum_count:
            # just check minimum_count
            if total > self.minimum_count:
                return True
        else:
            # require both
            if total > self.minimum_count and abs(delta) > self.print_threshold:
                return True

        return False

    def init_console(self):
        if not self.console:
            self.console = Console()

    def print_report(self, report: dict) -> None:
        "prints a report to the console"

        self.init_console()
        for key in sorted(report):
            reported: bool = False

            if self.print_match_string and self.print_match_string not in key:
                continue

            for subkey, data in sorted(
                report[key].items(), key=lambda x: x[1]["delta"], reverse=True
            ):
                if not self.filter_check(data):
                    continue

                # print the header
                if not reported:
                    print(f"====== {key}")
                    reported = True

                delta: float = data["delta"]

                # apply some fancy styling
                style = ""
                if delta < -0.5:
                    style = "[bold red]"
                elif delta < 0.0:
                    style = "[red]"
                elif delta > 0.5:
                    style = "[bold green]"
                elif delta > 0.0:
                    style = "[green]"
                endstyle = style.replace("[", "[/")

                # construct the output line with styling
                subkey = Dissection.make_printable(key, subkey)
                line = f"  {style}{subkey:<50}{endstyle}"
                line += f"{100*delta:>7.2f} "
                line += f"{data['left_count']:>8} {data['right_count']:>8}"

                # print it to the rich console
                self.console.print(line)

    def print_header(self):
        # This should match the spacing in print_report()
        self.init_console()

        style = ""
        subkey = "Value"
        endstyle = ""
        delta = "Delta %"
        left_count = "Left"
        right_count = "Right"

        line = f"  {style}{subkey:<50}{endstyle}"
        line += f"{delta:>7} "
        line += f"{left_count:>8} {right_count:>8}"

        self.console.print(line)

    def print(self) -> None:
        "outputs the results"
        self.print_header()
        for n, report in enumerate(self.reports):
            title = report.get("title", f"report #{n}")
            print(f"************ {title}")
            self.print_report(report["report"])

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

    def compare(self) -> None:
        "Compares each pcap against the original source"

        results = self.load_pcaps()
        self.compare_all(results)

    def compare_all(self, results):
        reports = []
        if len(self.pcaps) > 1:
            # multiple file comparison
            reference = next(results)
            for other in results:
                # compare the two global summaries
                reports.append(
                    {
                        "report": self.compare_dissections(
                            reference["dissection"].data[0], other["dissection"].data[0]
                        ),
                        "title": f"{reference['file']} vs {other['file']}",
                    }
                )

        else:
            # deal with timestamps within a single file
            reference = list(results)[0]["dissection"].data
            timestamps = list(reference.keys())
            debug(
                f"found {len(timestamps)} timestamps from {timestamps[2]} to {timestamps[-1]}"
            )

            self.print_header()

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

                title = f"time {time_left} vs time {time_right}"
                print(f"************ {title}")
                self.print_report(report)

                continue

                # takes way too much memory to do it "right"
                # reports.append(
                #     {
                #         "report": report,
                #         "title": f"time {time_left} vs time {time_right}",
                #     }
                # )

        self.reports = reports


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
        maximum_count=args.packet_count,
        print_threshold=float(args.print_threshold) / 100.0,
        minimum_count=args.minimum_count,
        print_match_string=args.match_string,
        only_positive=args.only_positive,
        only_negative=args.only_negative,
        cache_results=args.cache_pcap_results,
        cache_file_suffix=args.cache_file_suffix,
        dissection_level=args.dissection_level,
        between_times=args.between_times,
        bin_size=args.bin_size,
    )

    # compare the pcaps
    pc.compare()

    # print the results
    pc.print()


if __name__ == "__main__":
    main()
