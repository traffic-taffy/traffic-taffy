"""Takes a set of pcap files to compare and dumps a report"""

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from typing import List
import logging
from collections import defaultdict, Counter

# TODO: make scapy optional or use dpkt for shallow but faster
from scapy.all import rdpcap
from rich import print
from logging import debug, warning


def parse_args():
    "Parse the command line arguments."
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description=__doc__,
        epilog="Exmaple Usage: ",
    )

    parser.add_argument(
        "-n",
        "--packet-count",
        default=None,
        type=int,
        help="Maximum number of packets to analyze",
    )

    parser.add_argument(
        "-t",
        "--print-threshold",
        default=None,
        type=float,
        help="Don't print results with abs(value) less than threshold",
    )

    parser.add_argument(
        "-c",
        "--print-minimum-count",
        default=None,
        type=float,
        help="Don't print results without this high of a count",
    )

    parser.add_argument(
        "--log-level",
        "--ll",
        default="info",
        help="Define the logging verbosity level (debug, info, warning, error, ...).",
    )

    parser.add_argument("pcap_files", type=str, nargs="+", help="PCAP files to analyze")

    args = parser.parse_args()
    log_level = args.log_level.upper()
    logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")
    return args


class PcapCompare:
    "Takes a set of PCAPs to then perform various comparisons upon"

    def __init__(
        self,
        pcaps: List[str],
        maximum_count: int | None = None,
        deep: bool = True,
        print_threshold: float | None = None,
        print_minimum_count: int | None = None,
    ) -> None:

        self.pcaps = pcaps
        self.deep = deep
        self.maximum_count = maximum_count
        self.print_threshold = print_threshold
        self.print_minimum_count = print_minimum_count

        if len(self.pcaps) < 2:
            raise ValueError("Must pass at least two PCAP files")

    def add_layer(self, layer, storage: dict, prefix: str | None = ""):
        "Analyzes a layer to add counts to each layer sub-component"

        for field_name in [field.name for field in layer.fields_desc]:
            field_value = getattr(layer, field_name)
            if isinstance(field_value, list):
                if len(field_value) > 0:
                    # if it's a list of tuples, count the (eg TCP option) names
                    # TODO: values can be always the same or things like timestamps
                    #       that will always change
                    if isinstance(field_value[0], tuple):
                        for item in field_value:
                            storage[prefix + field_name][item[0]] += 1
                    else:
                        warning(f"ignoring non-zero list: {field_name}")
                else:
                    debug(f"ignoring empty-list: {field_name}")
            else:
                if isinstance(field_value, str) or isinstance(field_value, int):
                    storage[prefix + field_name][field_value] += 1
                else:
                    debug(f"ignoring field value of {str(field_value)}")

    def load_pcap(self, pcap_file: str | None = None) -> dict:
        "Loads a pcap file into a nested dictionary of statistical counts"
        results = defaultdict(Counter)
        packets = rdpcap(pcap_file, count=self.maximum_count)

        # for packet in packets:
        #     payload1 = packet.payload
        #     if payload1.name == "IP":
        #         self.add_layer(payload1, results, prefix + payload1.name + ".")

        for packet in packets:
            prefix = "."
            for payload in packet.iterpayloads():
                results[prefix[1:-1]][payload.name] += 1  # count the prefix itself too
                prefix = f"{prefix}{payload.name}."
                self.add_layer(payload, results, prefix[1:])

        return results

    def compare_results(self, report1: dict, report2: dict) -> dict:
        "compares the results from two reports"

        # TODO: handle recursive depths, where items are subtrees rather than Counters

        report = {}

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
                        report1[key][subkey] / report1_total
                        - report2[key][subkey] / report2_total
                    )
                    total = report1[key][subkey] + report2[key][subkey]
                else:
                    delta = report1[key][subkey] / report1_total
                    total = report1[key][subkey]

                report[key][subkey] = {"delta": delta, "total": total}

            for subkey in report2[key].keys():
                if subkey not in report[key]:
                    delta = 0.0 - report2[key][subkey] / report2_total
                    total = report2[key][subkey]

                    report[key][subkey] = {"delta": delta, "total": total}

        return report

    def print_report(self, report: dict) -> None:
        "prints a report to the console"
        for key in sorted(report):
            reported: bool = False
            for subkey, data in sorted(
                report[key].items(), key=lambda x: x[1]["delta"]
            ):
                delta: float = data["delta"]
                total: int = data["total"]
                print_it: bool = False

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
                    print(f" {subkey:<50} {delta:>6.3f} {total:>8}")

    def compare(self) -> None:
        "Compares each pcap against the original source"

        reports = []

        # TODO: use parallel processes to load multiple at a time

        # load the first as a reference pcap
        reference = self.load_pcap(self.pcaps[0])
        for pcap in self.pcaps[1:]:

            # load the next pcap
            other = self.load_pcap(pcap)

            # compare the two
            reports.append(self.compare_results(reference, other))

        for n, report in enumerate(reports):
            print(f"************ report #{n}")
            self.print_report(report)


def main():
    args = parse_args()
    pc = PcapCompare(
        args.pcap_files,
        maximum_count=args.packet_count,
        print_threshold=args.print_threshold,
        print_minimum_count=args.print_minimum_count,
    )
    pc.compare()


if __name__ == "__main__":
    main()
