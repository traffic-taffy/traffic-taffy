import sys
import logging
from logging import debug
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from traffic_taffy.dissector import (
    dissector_add_parseargs,
    limitor_add_parseargs,
    check_dissector_level,
)
from traffic_taffy.dissection import Dissection
from traffic_taffy.graphdata import PcapGraphData
from traffic_taffy.compare import PcapCompare, get_comparison_args
from traffic_taffy.output.memory import Memory

from PyQt6.QtCharts import QLineSeries, QChart, QChartView, QDateTimeAxis, QValueAxis
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QImage, QColor

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
    QSpinBox,
)


class CallWithParameter:
    def __init__(self, function, *args):
        self.parameters = args
        self.function = function

    def __call__(self):
        self.function(*self.parameters)


class TaffyExplorer(QDialog, PcapGraphData):
    """Explore PCAP files by comparison slices"""

    def testplot(self, area):
        print(area)
        # self.traffic_graph.setPlotArea(area)
        # self.detail_graph.setPlotArea(area)
        self.traffic_graph.zoomIn(area)

    def __init__(self, args):
        super().__init__()

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
        self.source_menus = QHBoxLayout()
        self.source_menus_w = QWidget()
        self.source_menus_w.setLayout(self.source_menus)
        self.mainLayout.addWidget(self.source_menus_w)

        self.comparison_panel_w = None  # place holder for update_report()

        # the comparison panel contains deltas between them
        self.scroll_area = QScrollArea()
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
        self.minimum_graph_count = args.minimum_count

        # other needed itmes
        self.min_changed_timer = QTimer(self)
        self.min_changed_timer.setSingleShot(True)
        self.min_changed_timer.setInterval(1000)
        self.min_changed_timer.timeout.connect(self.min_count_changed_actual)

        self.min_changed_timer = QTimer(self)
        self.min_changed_timer.setSingleShot(True)
        self.min_changed_timer.setInterval(1000)
        self.min_changed_timer.timeout.connect(self.min_graph_count_changed_actual)

        self.axisX = None
        self.axisY = None

    def quit(self):
        exit()

    def create_comparison(self):
        self.pc = PcapCompare(
            self.args.pcap_files,
            maximum_count=self.args.packet_count,
            cache_results=self.args.cache_pcap_results,
            cache_file_suffix=self.args.cache_file_suffix,
            dissection_level=self.args.dissection_level,
            between_times=self.args.between_times,
            bin_size=self.args.bin_size,
        )

        # create the graph data storage
        # and load everything in
        self.dissections = list(self.pc.load_pcaps())

        if len(self.dissections) == 1:
            keys = list(self.dissections[0].data.keys())
            self.compare_two(
                self.dissections[0].data[keys[1]],
                self.dissections[0].data[keys[2]],
            )
        else:
            self.compare_two(self.dissections[0].data[0], self.dissections[1].data[0])

    def compare_two(self, reference, other):
        self.comparison = self.pc.compare_dissections(reference, other)

    def update_chart(
        self, chart: QChart, match_string: str, match_value: str | None = None
    ):
        self.match_string = match_string
        self.match_value = match_value

        # for matching on a single value, don't do a minimum count at all
        tmpv = self.minimum_count
        self.minimum_count = self.minimum_graph_count
        if match_value is not None:
            self.minimum_count = 0

        df = self.get_dataframe()

        # TODO: there must be a better way! (key is duplicated)
        series_set = []
        maxv = -100
        for key in df.key.unique():
            series = QLineSeries()

            for index in df[df["key"] == key].index:
                series.append(
                    df["time"][index].to_pydatetime().timestamp() * 1000,
                    df["count"][index],
                )

                height = df["count"][index]
                maxv = max(maxv, height)

            series.setName(key)
            series.setOpacity(0.5)
            series_set.append(series)
            # axisx = QDateTimeAxis()
            # chart.setAxisX()

        df["time"].min().to_pydatetime().timestamp()
        df["time"].max().to_pydatetime().timestamp()

        grey = QColor("grey")

        # add another series for file ovelays
        for dissection in self.dissections:
            timestamps = list(dissection.data.keys())
            first_time = timestamps[1]  # skip the leading 0 timestamp
            last_time = timestamps[-1]

            # maxv = max(dict(dissection.data.values()))

            # tick-height:
            tick_height = int(0.01 * maxv)

            # time range with up/down markers
            series = QLineSeries()
            for timestamp in timestamps[1:]:
                series.append(timestamp * 1000, maxv + tick_height)
                series.append(timestamp * 1000, maxv + 1)
                series.append(timestamp * 1000, maxv + tick_height)
            series.setName(dissection.pcap_file)
            series.setColor(grey)
            series_set.append(series)
            # chart.addSeries(series)
            # series.attachAxis(axisX)
            # series.attachAxis(axisY)

            # beginning end markers
            series = QLineSeries()
            series.append(first_time * 1000, maxv + tick_height)
            series.append(last_time * 1000, maxv + tick_height)

            series.setMarkerSize(20)
            triangle = QImage("images/grey_triangle.png").scaled(10, 10)
            series.setLightMarker(triangle)
            # series.setColor(grey)
            series_set.append(series)
            # chart.addSeries(series)
            # series.attachAxis(axisX)
            # series.attachAxis(axisY)

        # we always add the real data last to keep file name coloring consistent

        if self.axisX:
            chart.removeAxis(self.axisX)
        self.axisX = QDateTimeAxis()
        self.axisX.setTickCount(5)
        self.axisX.setFormat("yyyy-MM-dd\nhh:mm")
        # self.axisX.setLabelsAngle(-45)
        chart.addAxis(self.axisX, Qt.AlignmentFlag.AlignBottom)

        if self.axisY:
            chart.removeAxis(self.axisY)
        self.axisY = QValueAxis()
        self.axisY.setLabelFormat("%i")
        chart.addAxis(self.axisY, Qt.AlignmentFlag.AlignLeft)

        # if these aren't all added at the very end then the axis are
        # all incorrectly zoomed.
        for series in series_set:
            chart.addSeries(series)
            series.attachAxis(self.axisX)
            series.attachAxis(self.axisY)

        # series = QLineSeries()
        # series.append(first_time, 0)
        # series.append(first_time, maxv)
        # series.attachAxis(axisX)
        # series.attachAxis(axisY)
        # chart.addSeries(series)

        # chart.createDefaultAxes()
        # chart.zoomIn(QRectF(QPointF(first_time/1000.0, maxv), QPointF(last_time/1000.0, 0)))

        self.saved_df = df
        self.minimum_count = tmpv

    def update_detail_chart(
        self, match_string: str = "__TOTAL__", match_value: str | None = None
    ):
        self.detail_graph.setTitle(match_string)
        self.detail_graph.removeAllSeries()
        self.update_chart(self.detail_graph, match_string, match_value)

    def update_traffic_chart(self):
        self.update_chart(self.traffic_graph, "__TOTAL__")

    # def show_comparison(self, pcap_one, timestamp_one, pcap_two, timestamp_two):

    def header_clicked(self, key):
        self.update_detail_chart(key, None)

    def min_count_changed_actual(self):
        self.update_report()
        self.update_detail_chart(self.match_string, self.match_value)
        debug(f"updating table with minimum count of {self.minimum_count}")

    def min_count_changed(self, value):
        self.minimum_count = value
        # in case we're running already, stop it first
        self.min_changed_timer.stop()
        self.min_changed_timer.start()
        debug(f"changed minimum count to {self.minimum_count}")

    def min_graph_count_changed_actual(self):
        self.update_report()
        self.update_detail_chart(self.match_string, self.match_value)
        debug(f"updating graph with minimum count of {self.minimum_graph_count}")

    def min_graph_count_changed(self, value):
        self.minimum_graph_count = value
        # in case we're running already, stop it first
        self.min_changed_timer.stop()
        self.min_changed_timer.start()
        debug(f"changed minimum count to {self.minimum_graph_count}")

    # def clearGridLayout(layout, deleteWidgets: bool = True):

    #     for widget in layout.something():
    #         layout.removeWidget(widget)
    #         widget.deletLater()

    # while (QLayoutItem* item = layout->takeAt(0))

    #     if (deleteWidgets)
    #     {
    #         if (QWidget* widget = item->widget())
    #             widget->deleteLater();
    #     }
    #     if (QLayout* childLayout = item->layout())
    #         clearLayout(childLayout, deleteWidgets);
    #     delete item;
    # }

    def add_control_widgets(self):
        self.source_menus.addWidget(QLabel("Minimum report count:"))
        self.minimum_count_w = QSpinBox()
        self.minimum_count_w.setMinimum(0)
        self.minimum_count_w.setMaximum(1000000)  # TODO: inf
        self.minimum_count_w.setValue(int(self.minimum_count))
        self.minimum_count_w.setSingleStep(5)

        self.minimum_count_w.valueChanged.connect(self.min_count_changed)
        self.source_menus.addWidget(self.minimum_count_w)

        self.source_menus.addWidget(QLabel("Minimum graph count:"))
        self.minimum_graph_count_w = QSpinBox()
        self.minimum_graph_count_w.setMinimum(0)
        self.minimum_graph_count_w.setMaximum(1000000)  # TODO: inf
        self.minimum_graph_count_w.setValue(int(self.minimum_graph_count))
        self.minimum_graph_count_w.setSingleStep(5)

        self.minimum_graph_count_w.valueChanged.connect(self.min_graph_count_changed)
        self.source_menus.addWidget(self.minimum_graph_count_w)

    def update_report(self):
        # TODO: less duplication with this and compare:print_report()
        "fills in the grid table showing the differences from a saved report"

        old_widget = self.comparison_panel_w

        # add a new one
        self.comparison_panel = QGridLayout()
        self.comparison_panel_w = QWidget()
        self.comparison_panel_w.setLayout(self.comparison_panel)
        self.scroll_area.setWidget(self.comparison_panel_w)

        del old_widget

        # we need to store the key/match values to reset
        (tmp_key, tmp_value) = (self.match_string, self.match_value)
        self.match_string = None
        self.match_value = None

        # add the header in row 0
        headers = ["Value", "Delta %", "Left Count", "Right Count"]
        for n, header in enumerate(headers):
            header = header.replace(" ", "**\n\n**")
            label = QLabel("**" + header + "**")
            label.setAlignment(Qt.AlignmentFlag.AlignRight)
            label.setTextFormat(Qt.TextFormat.MarkdownText)
            self.comparison_panel.addWidget(label, 0, n)

        current_grid_row = 1

        printing_arguments = get_comparison_args(self.args)
        memory_report = Memory(self.comparison.title, printing_arguments)
        memory_report.output(self.comparison)

        for key in memory_report.memory:
            reported = False
            for record in memory_report.memory[key]:
                # add the header
                if not reported:
                    debug(f"reporting on {key}")
                    report_button = QPushButton(key)
                    report_button.clicked.connect(
                        CallWithParameter(self.update_detail_chart, key)
                    )
                    self.comparison_panel.addWidget(
                        report_button, current_grid_row, 0, 1, 5
                    )
                    current_grid_row += 1
                    reported = True

                subkey = record["subkey"]
                delta: float = record["delta"]

                # apply some fancy styling
                style = ""
                if delta < -0.5:
                    style = "color: red"  # TODO bold
                elif delta < 0.0:
                    style = "color: red"
                elif delta > 0.5:
                    style = "color: lightgreen"  # TODO bold
                elif delta > 0.0:
                    style = "color: lightgreen"

                # construct the output line with styling
                subkey = Dissection.make_printable(key, subkey)
                debug(f"  adding {subkey}")

                subkey_button = QPushButton("    " + subkey)
                # subkey_button.setAlignment(Qt.AlignmentFlag.AlignLeft)
                subkey_button.clicked.connect(
                    CallWithParameter(self.update_detail_chart, key, subkey)
                )
                subkey_button.setStyleSheet(style)
                self.comparison_panel.addWidget(subkey_button, current_grid_row, 0)

                label = QLabel(f"{100*delta:>7.2f}")
                label.setAlignment(Qt.AlignmentFlag.AlignRight)
                self.comparison_panel.addWidget(label, current_grid_row, 1)

                label = QLabel(f"{record['left_count']:>8}")
                label.setAlignment(Qt.AlignmentFlag.AlignRight)
                self.comparison_panel.addWidget(label, current_grid_row, 2)

                label = QLabel(f"{record['right_count']:>8}")
                label.setAlignment(Qt.AlignmentFlag.AlignRight)
                self.comparison_panel.addWidget(label, current_grid_row, 3)
                current_grid_row += 1

        (self.match_string, self.match_value) = (tmp_key, tmp_value)


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
    window.add_control_widgets()
    window.update_traffic_chart()
    window.update_detail_chart()
    window.update_report()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
