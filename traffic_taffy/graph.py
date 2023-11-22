"""Read a PCAP file and graph it or parts of it"""

import seaborn as sns
import matplotlib.pyplot as plt
from traffic_taffy.dissector import (
    PCAPDissectorType,
    dissector_add_parseargs,
    limitor_add_parseargs,
    check_dissector_level,
)
from traffic_taffy.dissectmany import PCAPDissectMany
from traffic_taffy.graphdata import PcapGraphData

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
        "-i",
        "--interactive",
        action="store_true",
        help="Prompt repeatedly for graph data to create",
    )

    dissector_add_parseargs(parser)
    limitor_add_parseargs(parser)

    parser.add_argument("input_file", type=str, help="PCAP file to graph", nargs="+")

    args = parser.parse_args()
    log_level = args.log_level.upper()
    logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")
    logging.getLogger("matplotlib.font_manager").setLevel(logging.ERROR)
    return args


class PcapGraph(PcapGraphData):
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
        interactive: bool = False,
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
        self.interactive = interactive

        super().__init__()

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

    def create_graph(self):
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

    def show_graph(self):
        "Graph the results of the data collection"
        debug("creating the graph")
        sns.set_theme()

        first_run = True
        while first_run or self.interactive:
            first_run = False

            self.create_graph()

            if self.interactive:
                self.match_key = input("search key: ")
                self.match_value = input("value key: ")
                if not self.match_key and not self.match_value:
                    self.interactive = False

    def graph_it(self):
        debug("--- loading pcaps")
        self.load_pcaps()
        debug("--- creating graph")
        self.show_graph()


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
        interactive=args.interactive,
    )
    pc.graph_it()


if __name__ == "__main__":
    main()
