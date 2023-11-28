import sys
import logging
from logging import debug
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from traffic_taffy.dissector import (
    dissector_add_parseargs,
    limitor_add_parseargs,
    check_dissector_level,
    PCAPDissector,
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
    QLabel,
    QScrollArea,
)


class CallWithParameter:
    def __init__(self, function, parameter):
        self.parameter = parameter
        self.function = function

    def __call__(self):
        self.function(self.parameter)


class TaffyExplorer(QDialog, PcapGraphData):
    """Explore PCAP files by comparison slices"""

    def testplot(self, area):
        print(area)
        # self.traffic_graph.setPlotArea(area)
        # self.detail_graph.setPlotArea(area)
        self.traffic_graph.zoomIn(area)

    def __init__(self, args):
        super().__init__()

        # TODO: allow varying
        self.minimum_count = 2

        self.mainLayout = QVBoxLayout()
        self.setLayout(self.mainLayout)

        # create the graph at the top
        self.detail_graph = QChart()
        self.detail_graph_view = QChartView(self.detail_graph)
        self.detail_graph_view.setRubberBand(QChartView.RubberBand.RectangleRubberBand)
        self.detail_graph.setMinimumSize(1000, 400)
        # this is the screen space not the zoom setting
        # self.detail_graph.plotAreaChanged.connect(self.testplot)
        self.mainLayout.addWidget(self.detail_graph_view)

        # create the mini graph next
        self.traffic_graph = QChart()
        self.traffic_graph.legend().hide()
        self.traffic_graph.setTitle("All Traffic")
        self.traffic_graph_view = QChartView(self.traffic_graph)
        self.traffic_graph_view.setRubberBand(QChartView.RubberBand.RectangleRubberBand)
        self.traffic_graph.setMinimumSize(1000, 200)
        self.mainLayout.addWidget(self.traffic_graph_view)

        # create the traffic source menu bar
        self.source_menus = QHBoxLayout()  # TODO: line graph
        self.source_menus_w = QWidget()
        self.source_menus_w.setLayout(self.source_menus)
        self.mainLayout.addWidget(self.source_menus_w)

        self.comparison_panel = QGridLayout()
        self.comparison_panel_w = QWidget()
        self.comparison_panel_w.setLayout(self.comparison_panel)

        # the comparison panel contains deltas between them
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidget(self.comparison_panel_w)
        self.scroll_area.setMinimumSize(1000, 200)
        self.scroll_area.setWidgetResizable(True)

        self.mainLayout.addWidget(self.scroll_area)

        self.quit_button = QPushButton("Quit")
        self.mainLayout.addWidget(self.quit_button)
        self.quit_button.clicked.connect(self.quit)

        # self.tree = QTreeWidget()
        # self.tree.setHeaderHidden(True)
        # self.tree.setIndentation(0)

        self.args = args

        self.only_positive = args.only_positive
        self.only_negative = args.only_negative
        self.print_threshold = args.print_threshold
        self.minimum_count = args.minimum_count

    def quit(self):
        exit()

    def create_comparison(self):
        self.pc = PcapCompare(
            self.args.pcap_files,
            maximum_count=self.args.packet_count,
            print_threshold=float(self.args.print_threshold) / 100.0,
            minimum_count=self.args.minimum_count,
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

        if len(datasets) == 1:
            keys = list(datasets[0]["data"].keys())
            self.compare_two(datasets[0]["data"][keys[1]], datasets[0]["data"][keys[2]])
        else:
            self.compare_two(datasets[0]["data"][0], datasets[1]["data"][0])

    def compare_two(self, reference, other):
        self.report = self.pc.compare_dissections(reference, other)

    def update_chart(
        self, chart: QChart, match_key: str, match_value: str | None = None
    ):
        self.match_key = match_key
        self.match_value = match_value

        df = self.merge_datasets()

        # TODO: there must be a better way! (key is duplicated)
        for key in df.key.unique():
            series = QLineSeries()

            for index in df[df["key"] == key].index:
                series.append(
                    df["time"][index].to_pydatetime().timestamp(), df["count"][index]
                )

            series.setName(key)
            series.setOpacity(0.5)
            chart.addSeries(series)

        self.saved_df = df

    def update_detail_chart(
        self, match_key: str = "__TOTAL__", match_value: str | None = None
    ):
        self.detail_graph.setTitle(match_key)
        self.detail_graph.removeAllSeries()
        self.update_chart(self.detail_graph, match_key, match_value)

    def update_traffic_chart(self):
        self.update_chart(self.traffic_graph, "__TOTAL__")

    # def show_comparison(self, pcap_one, timestamp_one, pcap_two, timestamp_two):

    def header_clicked(self, key):
        self.update_detail_chart(key, None)

    def update_report(self):
        # TODO: less duplication with this and compare:print_report()
        "fills in the grid table showing the differences from a saved report"

        current_grid_row = 0
        for key in self.report:
            reported: bool = False

            if self.match_key and self.match_key not in key:
                continue

            for subkey, data in sorted(
                self.report[key].items(), key=lambda x: x[1]["delta"], reverse=True
            ):
                if not self.filter_check(data):
                    continue

                # add the header
                if not reported:
                    debug(f"reporting on {key}")
                    report_label = QPushButton(key)
                    report_label.clicked.connect(
                        CallWithParameter(self.update_detail_chart, key)
                    )
                    self.comparison_panel.addWidget(
                        report_label, current_grid_row, 0, 1, 5
                    )
                    current_grid_row += 1
                    reported = True

                delta: float = data["delta"]

                # apply some fancy styling
                style = ""
                if delta < -0.5:
                    style = "[bold red]"
                elif delta < 0.0:
                    style = "[red]"
                elif delta > 0.5:
                    style = "[bold green]"
                elif delta > 0.0:
                    style = "[green]"
                endstyle = style.replace("[", "[/")

                # construct the output line with styling
                subkey = PCAPDissector.make_printable(key, subkey)
                line = f"  {style}{subkey:<50}{endstyle}"
                line += f"{100*delta:>7.2f} {data['total']:>8} "
                line += f"{data['ref_count']:>8} {data['comp_count']:>8}"

                subkey = PCAPDissector.make_printable(key, subkey)
                debug(f"  adding {subkey}")
                self.comparison_panel.addWidget(
                    QLabel("    " + subkey), current_grid_row, 0
                )
                self.comparison_panel.addWidget(
                    QLabel(f"{100*delta:>7.2f}"), current_grid_row, 1
                )
                self.comparison_panel.addWidget(
                    QLabel(f"{data['total']:>8}"), current_grid_row, 2
                )
                self.comparison_panel.addWidget(
                    QLabel(f"{data['ref_count']:>8}"), current_grid_row, 3
                )
                self.comparison_panel.addWidget(
                    QLabel(f"{data['comp_count']:>8}"), current_grid_row, 4
                )
                current_grid_row += 1

    # TODO: move to base class of compare and explore
    def filter_check(self, data: dict) -> bool:
        "Returns true if we should include it"
        delta: float = data["delta"]
        total: int = data["total"]

        if self.only_positive and delta <= 0:
            return False

        if self.only_negative and delta >= 0:
            return False

        if not self.print_threshold and not self.minimum_count:
            # always print
            return True

        if self.print_threshold and not self.minimum_count:
            # check print_threshold as a fraction
            if abs(delta) > self.print_threshold:
                return True
        elif not self.print_threshold and self.minimum_count:
            # just check minimum_count
            if total > self.minimum_count:
                return True
        else:
            # require both
            if total > self.minimum_count and abs(delta) > self.print_threshold:
                return True

        return False


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
    window.update_detail_chart()
    window.match_key = None
    window.match_value = None
    window.update_report()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
