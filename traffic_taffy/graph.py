"""Create an output graph from a dissection data."""

from __future__ import annotations

import seaborn as sns
import matplotlib.pyplot as plt
from logging import debug, info

from traffic_taffy.dissectmany import PCAPDissectMany
from traffic_taffy.graphdata import PcapGraphData
from traffic_taffy.taffy_config import TaffyConfig, taffy_default
from traffic_taffy.dissector import TTD_CFG, TTL_CFG


class TTG_CFG:
    KEY_GRAPH: str = "graph"
    OUTPUT_FILE: str = "output_file"
    BY_PERCENTAGE: str = "by_percentage"
    INTERACTIVE: str = "interactive"


taffy_default("graph.output_file", None)
taffy_default("graph.by_percentage", False)
taffy_default("graph.interactive", False)


class PcapGraph(PcapGraphData):
    """Create an output graph from a dissection data."""

    def __init__(
        self,
        pcap_files: str,
        output_file: str,
        config: TaffyConfig(),
    ):
        """Create an instance of a graphing object."""
        self.config = config

        dissector_config = config[TTD_CFG.KEY_DISSECTOR]
        limitor_config = config[TTL_CFG.KEY_LIMITOR]
        graph_config = config[TTG_CFG.KEY_GRAPH]
        super().__init__(
            match_string=limitor_config[TTL_CFG.MATCH_STRING],
            match_value=limitor_config[TTL_CFG.MATCH_VALUE],
            minimum_count=limitor_config[TTL_CFG.MINIMUM_COUNT],
            match_expression=limitor_config[TTL_CFG.MATCH_EXPRESSION],
        )

        self.pcap_files = pcap_files
        self.output_file = output_file
        self.maximum_count = dissector_config[TTD_CFG.PACKET_COUNT]
        self.bin_size = dissector_config[TTD_CFG.BIN_SIZE]
        self.pcap_filter = dissector_config[TTD_CFG.FILTER]
        self.cache_pcap_results = dissector_config[TTD_CFG.CACHE_PCAP_RESULTS]
        self.dissector_level = dissector_config[TTD_CFG.DISSECTION_LEVEL]
        self.ignore_list = dissector_config[TTD_CFG.IGNORE_LIST]
        self.cache_file_suffix = dissector_config[TTD_CFG.CACHE_FILE_SUFFIX]
        self.layers = dissector_config[TTD_CFG.LAYERS]
        self.force_overwrite = dissector_config[TTD_CFG.FORCE_OVERWRITE]
        self.force_load = dissector_config[TTD_CFG.FORCE_LOAD]
        self.merge_files = dissector_config[TTD_CFG.MERGE]

        self.interactive = graph_config[TTG_CFG.INTERACTIVE]
        self.by_percentage = graph_config[TTG_CFG.BY_PERCENTAGE]

    def load_pcaps(self) -> None:
        """Load the pcap and counts things into bins."""
        self.data = {}

        info("reading pcap files")
        pdm = PCAPDissectMany(
            self.pcap_files,
            self.config,
        )
        self.dissections = pdm.load_all()
        info("done reading pcap files")

    def create_graph(self, options: dict | None = None) -> None:
        """Create the graph itself and save it."""
        if not options:
            options = {}

        df = self.get_dataframe(merge=True, calculate_load_fraction=self.by_percentage)
        hue_variable = "index"
        if df[hue_variable].nunique() == 1:
            hue_variable = None

        if self.by_percentage:
            y_column = "load_fraction"
        else:
            y_column = "count"

        # TODO(hardaker): support re-indexing and hole filling (this doesn't work)
        # str(self.bin_size or 1) + "s"
        # df = df.set_index("time")
        # df.index = df.index.to_period(freq=freq)
        # timeindex = pd.period_range(min(df.index), max(df.index), freq=freq)
        # df = df.reindex(timeindex)  # , fill_value=0

        ax = sns.relplot(
            data=df,
            kind="line",
            x="time",
            y=y_column,
            hue=hue_variable,
            aspect=1.77,
        )
        ax.set(xlabel="time", ylabel=options.get("ylabel", y_column))
        plt.xticks(rotation=45)

        info(f"saving graph to {self.output_file}")
        if self.output_file:
            plt.savefig(self.output_file, dpi=200)
        else:
            plt.show()

    def show_graph(self) -> None:
        """Graph the results of the data collection."""
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

    def graph_it(self) -> None:
        """Load the pcaps and graph it."""
        debug("--- loading pcaps")
        self.load_pcaps()
        debug("--- creating graph")
        self.show_graph()
