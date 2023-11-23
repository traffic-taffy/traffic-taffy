import sys
import logging
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from traffic_taffy.dissector import (
    dissector_add_parseargs,
    limitor_add_parseargs,
    check_dissector_level,
)
from traffic_taffy.graphdata import PcapGraphData
from traffic_taffy.compare import PcapCompare
from PyQt6.QtCharts import QLineSeries, QChart, QChartView

# https://stackoverflow.com/questions/32476006/how-to-make-an-expandable-collapsable-section-widget-in-qt

# class Widget(QWidget):
#     def __init__(self):
#         super().__init__()
#         self.__initUi()

#     def __initUi(self):
#         addBtn = QPushButton('Add')
#         addBtn.clicked.connect(self.__add)
#         self.__foldableListWidget = FoldableListWidget()
#         lay = QVBoxLayout()
#         lay.addWidget(addBtn)
#         lay.addWidget(self.__foldableListWidget)
#         self.setLayout(lay)

#     def __add(self):
#         foldedItem = QLabel("folded")
# #        foldedItem.setPlaceholderText('Input...')

#         sublist = FoldableListWidget()
#         subitem1 = QLabel("main item")
#         subitem2 = QLabel("sub item")
#         sublist.setFoldableListWidgetItem(subitem1, subitem2)

#         self.__foldableListWidget.setFoldableListWidgetItem(foldedItem, sublist)


from PyQt6.QtWidgets import (
    QPushButton,
    QDialog,
    QGridLayout,
    QVBoxLayout,
    QHBoxLayout,
    QApplication,
    QWidget,
)


class TaffyExplorer(QDialog, PcapGraphData):
    """Explore PCAP files by comparison slices"""

    def __init__(self, args):
        super().__init__()

        # TODO: allow varying
        self.minimum_count = 2

        self.mainLayout = QVBoxLayout()
        self.setLayout(self.mainLayout)

        # create the graph at the top
        self.detail_graph = QChart()
        self.detail_graph_view = QChartView(self.detail_graph)
        self.mainLayout.addWidget(self.detail_graph_view)

        # create the mini graph next
        self.traffic_graph = QChart()
        self.traffic_graph.legend().hide()
        self.traffic_graph.setTitle("All Traffic")
        self.traffic_graph_view = QChartView(self.traffic_graph)
        self.mainLayout.addWidget(self.traffic_graph_view)

        # create the traffic source menu bar
        self.source_menus = QHBoxLayout()  # TODO: line graph
        self.source_menus_w = QWidget()
        self.source_menus_w.setLayout(self.source_menus)
        self.mainLayout.addWidget(self.source_menus_w)

        # the comparison panel contains deltas between them
        self.comparison_panel = QGridLayout()
        self.comparison_panel_w = QWidget()
        self.comparison_panel_w.setLayout(self.comparison_panel)
        self.mainLayout.addWidget(self.comparison_panel_w)

        self.quit_button = QPushButton("Quit")
        self.mainLayout.addWidget(self.quit_button)
        self.quit_button.clicked.connect(self.quit)

        # self.tree = QTreeWidget()
        # self.tree.setHeaderHidden(True)
        # self.tree.setIndentation(0)

        self.args = args

    def quit(self):
        exit()

    def create_comparison(self):
        self.pc = PcapCompare(
            self.args.pcap_files,
            maximum_count=self.args.packet_count,
            print_threshold=float(self.args.print_threshold) / 100.0,
            print_minimum_count=self.args.minimum_count,
            print_match_string=self.args.match_string,
            only_positive=self.args.only_positive,
            only_negative=self.args.only_negative,
            cache_results=self.args.cache_pcap_results,
            dissection_level=self.args.dissection_level,
            between_times=self.args.between_times,
            bin_size=self.args.bin_size,
        )

        # create the graph data storage
        # and load everything in
        datasets = list(self.pc.load_pcaps())

        self.data = {}
        for dataset in datasets:
            self.data[dataset["file"]] = dataset["data"]

    def update_chart(
        self, chart: QChart, match_key: str, match_value: str | None = None
    ):
        self.match_key = match_key
        self.match_value = match_value

        df = self.merge_datasets()

        series = QLineSeries()

        # TODO: there must be a better way!
        for index in df.index:
            series.append(
                df["time"][index].to_pydatetime().timestamp(), df["count"][index]
            )

        chart.addSeries(series)

    def update_detail_chart(
        self, match_key: str = "__TOTAL__", match_value: str | None = None
    ):
        self.update_chart(self.detail_graph, match_key, match_value)

    def update_traffic_chart(self):
        self.update_chart(self.traffic_graph, "__TOTAL__")

    # def show_comparison(self, pcap_one, timestamp_one, pcap_two, timestamp_two):


def parse_args():
    "Parse the command line arguments."
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description=__doc__,
        epilog="Exmaple Usage: ",
    )

    limiting_parser = limitor_add_parseargs(parser)

    limiting_parser.add_argument(
        "-t",
        "--print-threshold",
        default=0.0,
        type=float,
        help="Don't print results with abs(percent) less than this threshold",
    )

    limiting_parser.add_argument(
        "-P", "--only-positive", action="store_true", help="Only show positive entries"
    )

    limiting_parser.add_argument(
        "-N", "--only-negative", action="store_true", help="Only show negative entries"
    )

    limiting_parser.add_argument(
        "-T",
        "--between-times",
        nargs=2,
        type=int,
        help="For single files, only display results between these timestamps",
    )

    dissector_add_parseargs(parser)

    debugging_group = parser.add_argument_group("Debugging options")

    debugging_group.add_argument(
        "--log-level",
        "--ll",
        default="info",
        help="Define the logging verbosity level (debug, info, warning, error, ...).",
    )

    parser.add_argument("pcap_files", type=str, nargs="+", help="PCAP files to analyze")

    args = parser.parse_args()
    log_level = args.log_level.upper()
    logging.basicConfig(level=log_level, format="%(levelname)-10s:\t%(message)s")

    check_dissector_level(args.dissection_level)

    return args


def main():
    args = parse_args()

    app = QApplication(sys.argv)
    window = TaffyExplorer(args)
    window.create_comparison()
    window.update_traffic_chart()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
