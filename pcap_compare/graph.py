"""Read a PCAP file and graph it or parts of it"""

import os
import seaborn as sns
import matplotlib.pyplot as plt
import pandas
from pandas import DataFrame, to_datetime
from pcap_compare.dissector import (
    PCAPDissectorType,
    dissector_add_parseargs,
    limitor_add_parseargs,
    check_dissector_level,
)
from pcap_compare.dissectmany import PCAPDissectMany, PCAPDissector

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

    parser.add_argument(
        "-b",
        "--bin-size",
        type=int,
        default=1,
        help="Bin results into this many seconds",
    )

    dissector_add_parseargs(parser)
    limitor_add_parseargs(parser)

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
        minimum_count: int = None,
        bin_size: int = None,
        match_key: str = None,
        match_value: str = None,
        cache_pcap_results: bool = False,
        dissector_level: PCAPDissectorType = PCAPDissectorType.COUNT_ONLY,
    ):
        self.pcap_files = pcap_files
        self.output_file = output_file
        self.maximum_count = maximum_count
        self.minimum_count = minimum_count
        self.bin_size = bin_size
        self.subsections = None
        self.pkt_filter = None
        self.match_key = match_key
        self.match_value = match_value
        self.cache_pcap_results = cache_pcap_results
        self.dissector_level = dissector_level

    def load_pcaps(self):
        "loads the pcap and counts things into bins"
        self.data = {}

        info("reading pcap files")
        pdm = PCAPDissectMany(
            self.pcap_files,
            bin_size=self.bin_size,
            maximum_count=self.maximum_count,
            dissector_level=self.dissector_level,
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
        time_keys[0]
        time_keys[-1]

        results = {"time": [], "count": [], "index": []}

        # TODO: this could likely be made much more efficient and needs hole-filling
        info(f"match value: {self.match_value}")
        for (timestamp, key, subkey, value) in PCAPDissector.find_data(
            counters,
            timestamps=time_keys,
            match_string=self.match_key,
            match_value=self.match_value,
            minimum_count=self.minimum_count,
            make_printable=True,
        ):
            index = key + "=" + subkey
            results["count"].append(int(value))
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

    check_dissector_level(args.dissection_level)

    pc = PcapGraph(
        args.input_file,
        args.output_file,
        maximum_count=args.packet_count,
        minimum_count=args.minimum_count,
        bin_size=args.bin_size,
        match_key=args.match_string,
        match_value=args.match_value,
        cache_pcap_results=args.cache_pcap_results,
        dissector_level=args.dissection_level,
    )
    pc.graph_it()


if __name__ == "__main__":
    main()
