"""Read a PCAP file and graph it or parts of it"""

import os
import seaborn as sns
import matplotlib.pyplot as plt
import pandas
from pandas import DataFrame, to_datetime
from pcap_compare.disector import PCAPDisectorType
from pcap_compare.disectmany import PCAPDisectMany

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
        "-C",
        "--cache-pcap-results",
        action="store_true",
        help="Cache and use PCAP results into/from a .pkl file",
    )

    parser.add_argument(
        "-o",
        "--output-file",
        default=None,
        type=str,
        help="Where to save the output (png)",
    )

    parser.add_argument(
        "-m",
        "--match-key",
        default=None,
        type=str,
        help="Only report on data with this substring in the packet attribute name",
    )

    parser.add_argument(
        "-M",
        "--match-value",
        default=None,
        type=str,
        help="Only report on data with this substring in the packet value field",
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
        match_key: str = None,
        match_value: str = None,
        cache_pcap_results: bool = False,
    ):
        self.pcap_files = pcap_files
        self.output_file = output_file
        self.maximum_count = maximum_count
        self.bin_size = bin_size
        self.subsections = None
        self.pkt_filter = None
        self.match_key = match_key
        self.match_value = match_value
        self.cache_pcap_results = cache_pcap_results

    def load_pcaps(self):
        "loads the pcap and counts things into bins"
        self.data = {}

        disector_type: PCAPDisectorType = PCAPDisectorType.COUNT_ONLY
        if self.match_key or self.match_value:
            disector_type = PCAPDisectorType.DETAILED

        info("reading pcap files")
        pdm = PCAPDisectMany(
            self.pcap_files,
            bin_size=self.bin_size,
            maximum_count=self.maximum_count,
            disector_type=disector_type,
            pcap_filter=self.pkt_filter,
            cache_results=self.cache_pcap_results,
        )
        results = pdm.load_all()

        for result in results:
            self.data[result["file"]] = result["data"]
        info("done reading pcap files")

    def normalize_bins(self, counters):
        results = {}
        time_keys = list(counters.keys())
        if time_keys[0] == 0:  # likely always
            time_keys.pop(0)
        start_time = time_keys[0]
        end_time = time_keys[-1]

        results = {"time": [], "count": [], "index": []}

        # TODO: this could likely be made much more efficient and needs hole-filling
        for timestamp in range(start_time, end_time + 1, self.bin_size):
            if timestamp not in counters:
                continue
            for key in counters[timestamp]:
                if self.match_key and self.match_key not in key:
                    continue
                for subkey in counters[timestamp][key]:
                    subkey_s = str(subkey)
                    if self.match_value and self.match_value not in subkey_s:
                        continue
                    index = key + "=" + subkey_s
                    results["count"].append(counters[timestamp][key][subkey])
                    results["index"].append(index)
                    results["time"].append(timestamp)

        return results

    def merge_datasets(self):
        datasets = []
        for dataset in self.data:
            data = self.normalize_bins(self.data[dataset])
            data = DataFrame.from_records(data)
            data["filename"] = os.path.basename(dataset)
            data["time"] = to_datetime(data["time"], unit="s")
            datasets.append(data)
        datasets = pandas.concat(datasets)
        return datasets

    def create_graph(self):
        "Graph the results of the data collection"
        debug("creating the graph")
        sns.set_theme()

        df = self.merge_datasets()
        debug(df)

        hue_variable = "index"
        if df[hue_variable].nunique() == 1:
            hue_variable = None

        ax = sns.relplot(
            data=df,
            kind="line",
            x="time",
            y="count",
            hue=hue_variable,
            aspect=1.77,
        )
        ax.set(xlabel="time", ylabel="count")
        plt.xticks(rotation=45)

        info(f"saving graph to {self.output_file}")
        if self.output_file:
            plt.savefig(self.output_file)
        else:
            plt.show()

    def graph_it(self):
        debug("--- loading pcaps")
        self.load_pcaps()
        debug("--- creating graph")
        self.create_graph()


def main():
    args = parse_args()

    pc = PcapGraph(
        args.input_file,
        args.output_file,
        maximum_count=args.packet_count,
        bin_size=args.bin_size,
        match_key=args.match_key,
        match_value=args.match_value,
        cache_pcap_results=args.cache_pcap_results,
    )
    pc.graph_it()


if __name__ == "__main__":
    main()
