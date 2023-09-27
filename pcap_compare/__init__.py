"""Takes a set of pcap files to compare and dumps a report"""

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from typing import List
import logging
from collections import defaultdict, Counter

# TODO: make scapy optional or use dpkt for shallow but faster
from scapy.all import rdpcap, IP
from rich import print


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
        maximum_count: int = None,
        deep: bool = True,
        print_threshold: float = None,
    ) -> None:

        self.pcaps = pcaps
        self.deep = deep
        self.maximum_count = maximum_count
        self.print_threshold = print_threshold

        if len(self.pcaps) < 2:
            raise ValueError("Must pass at least two PCAP files")

    def load_pcap(self, pcap_file: str = None) -> dict:
        "Loads a pcap file into a nested dictionary of statistical counts"
        results = defaultdict(Counter)
        packets = rdpcap(pcap_file, count=self.maximum_count)

        for packet in packets:
            if IP in packet:
                results["src"][packet[IP].src] += 1
                results["dst"][packet[IP].dst] += 1

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
                if subkey in report1[key] and subkey in report2[key]:
                    report[key][subkey] = (
                        report1[key][subkey] / report1_total
                        - report2[key][subkey] / report2_total
                    )
                else:
                    report[key][subkey] = report1[key][subkey] / report1_total

            for subkey in report2[key].keys():
                if subkey not in report[key]:
                    report[key][subkey] = 0.0 - report2[key][subkey] / report2_total

            return report

    def print_report(self, report: dict) -> None:
        "prints a report to the console"
        for key in report:
            print(f"====== {key}")
            for subkey, value in sorted(report[key].items(), key=lambda x: x[1]):
                if not self.print_threshold or abs(value) > self.print_threshold:
                    print(f"{subkey:<30} {value}")

    def compare(self) -> None:
        "Compares each pcap against the original source"

        reports = []

        reference = self.load_pcap(self.pcaps[0])
        for pcap in self.pcaps[1:]:
            other = self.load_pcap(pcap)

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
    )
    pc.compare()


if __name__ == "__main__":
    main()
