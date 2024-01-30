import seaborn as sns
import matplotlib.pyplot as plt
from logging import debug, info
from typing import List

from traffic_taffy.dissector import PCAPDissectorLevel
from traffic_taffy.dissectmany import PCAPDissectMany
from traffic_taffy.graphdata import PcapGraphData


class PcapGraph(PcapGraphData):
    def __init__(
        self,
        pcap_files: str,
        output_file: str,
        maximum_count: int = None,
        minimum_count: int = None,
        bin_size: int = None,
        match_string: str = None,
        match_value: str = None,
        cache_pcap_results: bool = False,
        dissector_level: PCAPDissectorLevel = PCAPDissectorLevel.COUNT_ONLY,
        interactive: bool = False,
        ignore_list: List[str] = [],
        by_percentage: bool = False,
        pcap_filter: str | None = None,
        cache_file_suffix: str = "taffy",
        layers: List[str] | None = None,
        force_overwrite: bool = False,
        force_load: bool = False,
    ):
        self.pcap_files = pcap_files
        self.output_file = output_file
        self.maximum_count = maximum_count
        self.minimum_count = minimum_count
        self.bin_size = bin_size
        self.subsections = None
        self.pcap_filter = None
        self.match_string = match_string
        self.match_value = match_value
        self.cache_pcap_results = cache_pcap_results
        self.dissector_level = dissector_level
        self.interactive = interactive
        self.ignore_list = ignore_list
        self.by_percentage = by_percentage
        self.pcap_filter = pcap_filter
        self.cache_file_suffix = cache_file_suffix
        self.layers = layers
        self.force_overwrite = force_overwrite
        self.force_load = force_load

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
            pcap_filter=self.pcap_filter,
            cache_results=self.cache_pcap_results,
            ignore_list=self.ignore_list,
            cache_file_suffix=self.cache_file_suffix,
            layers=self.layers,
            force_overwrite=self.force_overwrite,
            force_load=self.force_load,
        )
        self.dissections = pdm.load_all()
        info("done reading pcap files")

    def create_graph(self):
        df = self.get_dataframe(merge=True, calculate_load_fraction=self.by_percentage)

        hue_variable = "index"
        if df[hue_variable].nunique() == 1:
            hue_variable = None

        if self.by_percentage:
            df["load_fraction"]
            y_column = "load_fraction"
        else:
            y_column = "count"

        ax = sns.relplot(
            data=df,
            kind="line",
            x="time",
            y=y_column,
            hue=hue_variable,
            aspect=1.77,
        )
        ax.set(xlabel="time", ylabel=y_column)
        plt.xticks(rotation=45)

        info(f"saving graph to {self.output_file}")
        if self.output_file:
            plt.savefig(self.output_file, dpi=200)
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
                self.match_string = input("search key: ")
                self.match_value = input("value key: ")
                if not self.match_string and not self.match_value:
                    self.interactive = False

    def graph_it(self):
        debug("--- loading pcaps")
        self.load_pcaps()
        debug("--- creating graph")
        self.show_graph()
