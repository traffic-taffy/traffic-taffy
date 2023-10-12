"""Read a PCAP file and graph it or parts of it"""

import seaborn as sns
import matplotlib.pyplot as plt
import collections
from pandas import DataFrame, to_datetime
from scapy.all import rdpcap

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from logging import debug, info
import logging


def parse_args():
    "Parse the command line arguments."
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description=__doc__,
        epilog="Exmaple Usage: ",
    )

    parser.add_argument(
        "-g",
        "--graph-elements",
        default=None,
        type=str,
        help="Graph these particular elements; the default is packet counts",
    )

    parser.add_argument(
        "-n", "--packet-count", default=0, type=int, help="How many packets to read"
    )

    parser.add_argument(
        "-b", "--bin-size", default=15, type=int, help="Time bin size in seconds"
    )

    parser.add_argument(
        "--log-level",
        "--ll",
        default="info",
        help="Define verbosity level (debug, info, warning, error, fotal, critical).",
    )

    parser.add_argument("input_file", type=str, help="PCAP file to graph")

    parser.add_argument(
        "output_file", type=str, help="Where to store the resulting graph (png)"
    )

    args = parser.parse_args()
    log_level = args.log_level.upper()
    logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")
    return args


class PcapGraph:
    def __init__(
        self,
        pcap_file: str,
        output_file: str,
        maximum_count: int = None,
        bin_size: int = None,
    ):
        self.pcap_file = pcap_file
        self.output_file = output_file
        self.maximum_count = maximum_count
        self.bin_size = bin_size
        self.times = {"all": collections.Counter()}
        self.subsections = None
        self.pkt_filter = None

    def dpkt_counter(self, timestamp: float, packet: bytes):
        time_stamp = int(timestamp)
        time_stamp = time_stamp - time_stamp % self.bin_size
        self.times["all"][time_stamp] += 1

    def load_pcap(self):
        "loads the pcap and counts things into bins"
        info(f"reading {self.pcap_file}")

        if self.subsections:
            packets = rdpcap(self.pcap_file, count=self.maximum_count)
            for packet in packets:
                time_stamp = int(packet.time)
                time_stamp = time_stamp - time_stamp % self.bin_size
                self.times["all"][time_stamp] += 1
        else:  # use the faster dpkt
            import dpkt

            pcap = dpkt.pcap.Reader(open(self.pcap_file, "rb"))
            if self.pkt_filter:
                pcap.setfilter(self.pkt_filter)
            pcap.dispatch(self.maximum_count, self.dpkt_counter)

    def create_graph(self):
        "Graph the results of the data collection"
        sns.set_theme()

        df = DataFrame(
            {
                "time": to_datetime(list(self.times["all"].keys()), unit="s"),
                "counts": self.times["all"].values(),
            }
        )
        debug(df)

        sns.relplot(data=df, kind="line", x="time", y="counts", aspect=1.77)
        plt.xticks(rotation=45)
        info(f"saving to {self.output_file}")
        plt.savefig(self.output_file)

    def graph_it(self):
        self.load_pcap()
        self.create_graph()


def main():
    args = parse_args()

    pc = PcapGraph(
        args.input_file,
        args.output_file,
        maximum_count=args.packet_count,
        bin_size=args.bin_size,
    )
    pc.graph_it()


if __name__ == "__main__":
    main()
