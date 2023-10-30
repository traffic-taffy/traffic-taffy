"""Takes a set of pcap files to compare and creates a report"""

import logging
from logging import info
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from typing import List
from rich.console import Console
from pcap_compare.dissectmany import PCAPDissectMany
from pcap_compare.dissector import (
    PCAPDissectorType,
    dissector_add_parseargs,
    limitor_add_parseargs,
    PCAPDissector,
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
        print_minimum_count: int | None = None,
        print_match_string: str | None = None,
        pkt_filter: str | None = None,
        only_positive: bool = False,
        only_negative: bool = False,
        cache_results: bool = False,
        dissection_level: PCAPDissectorType = PCAPDissectorType.COUNT_ONLY,
    ) -> None:

        self.pcaps = pcaps
        self.deep = deep
        self.maximum_count = maximum_count
        self.print_threshold = print_threshold
        self.print_minimum_count = print_minimum_count
        self.print_match_string = print_match_string
        self.pkt_filter = pkt_filter
        self.only_positive = only_positive
        self.only_negative = only_negative
        self.cache_results = cache_results
        self.dissection_level = dissection_level

    def compare_results(self, report1: dict, report2: dict) -> dict:
        "compares the results from two reports"

        # TODO: handle recursive depths, where items are subtrees rather than Counters

        report = {}

        # TODO: we're only (currently) doing full pcap compares
        report1 = report1[0]
        report2 = report2[0]

        for key in report1:
            # TODO: deal with missing keys from one set
            report1_total = report1[key].total()
            report2_total = report2[key].total()
            report[key] = {}

            for subkey in report1[key].keys():
                delta = 0.0
                total = 0
                if subkey in report1[key] and subkey in report2[key]:
                    delta = (
                        report2[key][subkey] / report2_total
                        - report1[key][subkey] / report1_total
                    )
                    total = report2[key][subkey] + report1[key][subkey]
                    ref_count = report1[key][subkey]
                    comp_count = report2[key][subkey]
                else:
                    delta = -1.0
                    total = report1[key][subkey]
                    ref_count = report1[key][subkey]
                    comp_count = 0

                report[key][subkey] = {
                    "delta": delta,
                    "total": total,
                    "ref_count": ref_count,
                    "comp_count": comp_count,
                }

            for subkey in report2[key].keys():
                if subkey not in report[key]:
                    delta = 1.0
                    total = report2[key][subkey]
                    ref_count = 0
                    comp_count = report2[key][subkey]

                    report[key][subkey] = {
                        "delta": delta,
                        "total": total,
                        "ref_count": ref_count,
                        "comp_count": comp_count,
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

        if not self.print_threshold and not self.print_minimum_count:
            # always print
            return True

        if self.print_threshold and not self.print_minimum_count:
            # check print_threshold as a fraction
            if abs(delta) > self.print_threshold:
                return True
        elif not self.print_threshold and self.print_minimum_count:
            # just check print_minimum_count
            if total > self.print_minimum_count:
                return True
        else:
            # require both
            if total > self.print_minimum_count and abs(delta) > self.print_threshold:
                return True

        return False

    def print_report(self, report: dict) -> None:
        "prints a report to the console"
        console = Console()
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
                subkey = PCAPDissector.make_printable(subkey)
                line = f"  {style}{subkey:<50}{endstyle}"
                line += f"{100*delta:>6.2f} {data['total']:>8} "
                line += f"{data['ref_count']:>8} {data['comp_count']:>8}"

                # print it to the rich console
                console.print(line)

    def print(self) -> None:
        "outputs the results"
        for n, report in enumerate(self.reports):
            print(f"************ report #{n}")
            self.print_report(report)

    def compare(self) -> None:
        "Compares each pcap against the original source"

        reports = []

        # TODO: use parallel processes to load multiple at a time

        # load the first as a reference pcap
        info(f"reading pcap files using level={self.dissection_level}")
        pdm = PCAPDissectMany(
            self.pcaps,
            bin_size=None,
            maximum_count=self.maximum_count,
            pcap_filter=self.pkt_filter,
            cache_results=self.cache_results,
            dissector_level=self.dissection_level,
        )
        results = pdm.load_all()

        reference = next(results)
        for other in results:
            # compare the two
            reports.append(self.compare_results(reference["data"], other["data"]))

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
        print_minimum_count=args.minimum_count,
        print_match_string=args.match_string,
        only_positive=args.only_positive,
        only_negative=args.only_negative,
        cache_results=args.cache_pcap_results,
        dissection_level=args.dissection_level,
    )

    # compare the pcaps
    pc.compare()

    # print the results
    pc.print()

    # maybe save them
    # TODO: loading and saving both makes more sense, throw error
    if args.save_report:
        pc.save_report(args.save_report)


if __name__ == "__main__":
    main()
