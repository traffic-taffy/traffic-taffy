from typing import List
from rich.console import Console
from pcap_disector import PCAPDisector
import pickle


class PcapCompare:
    "Takes a set of PCAPs to then perform various comparisons upon"

    REPORT_VERSION: int = 2

    def __init__(
        self,
        pcaps: List[str],
        maximum_count: int | None = None,
        deep: bool = True,
        print_threshold: float | None = None,
        print_minimum_count: int | None = None,
        print_match_string: str | None = None,
        only_positive: bool = False,
        only_negative: bool = False,
    ) -> None:

        self.pcaps = pcaps
        self.deep = deep
        self.maximum_count = maximum_count
        self.print_threshold = print_threshold
        self.print_minimum_count = print_minimum_count
        self.print_match_string = print_match_string
        self.only_positive = only_positive
        self.only_negative = only_negative

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

    def print_report(self, report: dict) -> None:
        "prints a report to the console"
        console = Console()
        for key in sorted(report):
            reported: bool = False

            if self.print_match_string and self.print_match_string not in key:
                continue

            for subkey, data in sorted(
                report[key].items(), key=lambda x: x[1]["delta"]
            ):
                delta: float = data["delta"]
                total: int = data["total"]
                comp_count: int = data["comp_count"]
                ref_count: int = data["ref_count"]
                print_it: bool = False

                if self.only_positive and delta <= 0:
                    continue

                if self.only_negative and delta >= 0:
                    continue

                if not self.print_threshold and not self.print_minimum_count:
                    # always print
                    print_it = True
                elif self.print_threshold and not self.print_minimum_count:
                    # check print_threshold as a fraction
                    if abs(delta) > self.print_threshold:
                        print_it = True
                elif not self.print_threshold and self.print_minimum_count:
                    # just check print_minimum_count
                    if total > self.print_minimum_count:
                        print_it = True
                else:
                    # require both
                    if (
                        total > self.print_minimum_count
                        and abs(delta) > self.print_threshold
                    ):
                        print_it = True

                if print_it:
                    # print the header
                    if not reported:
                        print(f"====== {key}")
                        reported = True

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
                    line = f"  {style}{subkey:<50}{endstyle}"
                    line += f"{delta:>6.3f} {total:>8} "
                    line += f"{ref_count:>8} {comp_count:>8}"

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
        pd = PCAPDisector(
            self.pcaps[0], bin_size=None, maximum_count=self.maximum_count
        )
        reference = pd.load()
        for pcap in self.pcaps[1:]:

            # load the next pcap
            pd = PCAPDisector(pcap, bin_size=None, maximum_count=self.maximum_count)
            other = pd.load()

            # compare the two
            reports.append(self.compare_results(reference, other))

        self.reports = reports

    def save_report(self, where: str) -> None:
        "Saves the generated reports to a pickle file"

        # wrap the report in a version header
        versioned_report = {
            "PCAP_COMPARE_VERSION": self.REPORT_VERSION,
            "reports": self.reports,
            "files": self.pcaps,
        }

        # save it
        pickle.dump(versioned_report, open(where, "wb"))

    def load_report(self, where: str) -> None:
        "Loads a previous saved report from a file instead of re-parsing pcaps"
        self.reports = pickle.load(open(where, "rb"))

        # check that the version header matches something we understand
        if self.reports["PCAP_COMPARE_VERSION"] != self.REPORT_VERSION:
            raise ValueError(
                "improper saved version: report version = "
                + str(self.reports["PCAP_COMPARE_VERSION"])
                + ", our version: "
                + str(self.REPORT_VERSION)
            )

        # proceed as normal beyond this
        self.reports = self.reports["reports"]
