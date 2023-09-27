"""Takes a set of pcap files to compare and dumps a report"""

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from typing import List
import logging
from collections import defaultdict, Counter

# TODO: make scapy optional or use dpkt for shallow but faster
from scapy.all import rdpcap, IP


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
        self, pcaps: List[str], maximum_count: int = None, deep: bool = True
    ) -> None:

        self.pcaps = pcaps
        self.deep = deep
        self.maximum_count = maximum_count

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

    def compare(self) -> None:
        reference = self.load_pcap(self.pcaps[0])
        for pcap in self.pcaps[1:]:
            other = self.load_pcap(pcap)
        print(reference)
        print(other)


def main():
    args = parse_args()
    pc = PcapCompare(args.pcap_files, maximum_count=args.packet_count)
    pc.compare()


if __name__ == "__main__":
    main()
