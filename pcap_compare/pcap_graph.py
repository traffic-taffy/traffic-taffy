"""Read a PCAP file and graph it or parts of it"""

import seaborn as sns
import matplotlib.pyplot as plt
import collections
import pandas
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
        "-b", "--bin-size", default=1, type=int, help="Time bin size in seconds"
    )

    parser.add_argument(
        "-o",
        "--output-file",
        default=None,
        type=str,
        help="Where to save the output (png)",
    )

    parser.add_argument(
        "--log-level",
        "--ll",
        default="info",
        help="Define verbosity level (debug, info, warning, error, fotal, critical).",
    )

    parser.add_argument("input_file", type=str, help="PCAP file to graph", nargs="+")

    args = parser.parse_args()
    log_level = args.log_level.upper()
    logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")
    logging.getLogger("matplotlib.font_manager").setLevel(logging.ERROR)
    return args


class PcapGraph:
    def __init__(
        self,
        pcap_files: str,
        output_file: str,
        maximum_count: int = None,
        bin_size: int = None,
    ):
        self.pcap_files = pcap_files
        self.output_file = output_file
        self.maximum_count = maximum_count
        self.bin_size = bin_size
        self.subsections = None
        self.pkt_filter = None

    def dpkt_counter(self, timestamp: float, packet: bytes):
        time_stamp = int(timestamp)
        time_stamp = time_stamp - time_stamp % self.bin_size
        self.times["count"][time_stamp] += 1

    def load_pcaps(self):
        "loads the pcap and counts things into bins"
        self.data = {}
        for pcap_file in self.pcap_files:
            self.times = {"count": collections.Counter()}
            self.current_pcap = pcap_file
            info(f"reading {pcap_file}")

            if self.subsections:
                # TODO: actually break apart better
                packets = rdpcap(pcap_file, count=self.maximum_count)
                for packet in packets:
                    time_stamp = int(packet.time)
                    time_stamp = time_stamp - time_stamp % self.bin_size
                    self.times["count"][time_stamp] += 1
            else:  # use the faster dpkt
                import dpkt

                pcap = dpkt.pcap.Reader(open(pcap_file, "rb"))
                if self.pkt_filter:
                    pcap.setfilter(self.pkt_filter)
                pcap.dispatch(self.maximum_count, self.dpkt_counter)

            self.data[pcap_file] = self.times

    def normalize_bins(self, counters):
        results = {}
        first_key = list(counters.keys())[0]
        time_keys = list(counters[first_key])
        start_key = time_keys[0]
        end_key = time_keys[-1]

        results = {"time": list(range(start_key, end_key + 1, self.bin_size))}
        for key in counters:
            results[key] = [
                counters[key][x] for x in range(start_key, end_key + 1, self.bin_size)
            ]

        return results

    def merge_datasets(self):
        datasets = []
        for dataset in self.data:
            data = self.normalize_bins(self.data[dataset])
            data = DataFrame.from_records(data)
            data["filename"] = dataset
            data["time"] = to_datetime(data["time"], unit="s")
            datasets.append(data)
        datasets = pandas.concat(datasets)
        return datasets

    def create_graph(self):
        "Graph the results of the data collection"
        sns.set_theme()

        df = self.merge_datasets()
        debug(df)

        ax = sns.relplot(
            data=df, kind="line", x="time", y="count", hue="filename", aspect=1.77
        )
        ax.set(xlabel="time", ylabel="count")
        plt.xticks(rotation=45)
        info(f"saving to {self.output_file}")
        if self.output_file:
            plt.savefig(self.output_file)
        else:
            plt.show()

    def graph_it(self):
        self.load_pcaps()
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
