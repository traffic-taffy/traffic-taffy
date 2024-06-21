"""A graphical PCAP comparison and graphing tool."""

import sys
from os.path import basename
import logging
from logging import debug
from datetime import datetime
import datetime as dt
from argparse import ArgumentParser, Namespace
from rich_argparse import RichHelpFormatter
from traffic_taffy.dissector import (
    dissector_add_parseargs,
    limitor_add_parseargs,
    dissector_handle_arguments,
)
from traffic_taffy.dissection import Dissection
from traffic_taffy.graphdata import PcapGraphData
from traffic_taffy.compare import (
    PcapCompare,
    get_comparison_args,
    compare_add_parseargs,
)
from traffic_taffy.output.memory import Memory

from PyQt6.QtCharts import QLineSeries, QChart, QChartView, QDateTimeAxis, QValueAxis
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QImage, QColor

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
    QToolButton,
    QMenu,
    QCheckBox,
)
from typing import Optional


class CallWithParameter:
    """A callable object that takes parameters."""

    def __init__(self, function: callable, *args: list):
        """Create a Callable object."""
        self.parameters = args
        self.function = function

    def __call__(self):
        """Call a registered callback routine and its parameters."""
        self.function(*self.parameters)


class TaffyExplorer(QDialog, PcapGraphData):
    """Explore PCAP files by comparison slices."""

    def testplot(self, area):
        print(area)
        self.traffic_graph.zoomIn(area)

    def __init__(self, args):
        """Create a TaffyExplorer UI."""
        super().__init__()

        self.mainLayout = QVBoxLayout()
        self.setLayout(self.mainLayout)

        # create the graph at the top
        self.detail_graph = QChart()
        self.detail_graph_view = QChartView(self.detail_graph)
        self.detail_graph_view.setRubberBand(QChartView.RubberBand.RectangleRubberBand)
        self.detail_graph.setMinimumSize(1000, 400)
        # this is the screen space not the zoom setting
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

        self.control_menus = QHBoxLayout()
        self.control_menus_w = QWidget()
        self.control_menus_w.setLayout(self.control_menus)
        self.mainLayout.addWidget(self.control_menus_w)

        self.comparison_panel_w = None  # place holder for update_report()

        # the comparison panel contains deltas between them
        self.scroll_area = QScrollArea()
        self.scroll_area.setMinimumSize(1000, 200)
        self.scroll_area.setWidgetResizable(True)

        self.mainLayout.addWidget(self.scroll_area)

        self.quit_button = QPushButton("Quit")
        self.mainLayout.addWidget(self.quit_button)
        self.quit_button.clicked.connect(self.quit)

        self.args = args

        self.only_positive = args.only_positive
        self.only_negative = args.only_negative
        self.print_threshold = args.print_threshold
        self.minimum_count = args.minimum_count
        self.minimum_graph_count = args.minimum_count
        self.top_records = args.top_records

        # other needed itmes
        self.min_count_changed_timer = QTimer(self)
        self.min_count_changed_timer.setSingleShot(True)
        self.min_count_changed_timer.setInterval(1000)
        self.min_count_changed_timer.timeout.connect(self.min_count_changed_actual)

        self.min_graph_changed_timer = QTimer(self)
        self.min_graph_changed_timer.setSingleShot(True)
        self.min_graph_changed_timer.setInterval(1000)
        self.min_graph_changed_timer.timeout.connect(
            self.min_graph_count_changed_actual
        )

        self.top_records_changed_timer = QTimer(self)
        self.top_records_changed_timer.setSingleShot(True)
        self.top_records_changed_timer.setInterval(1000)
        self.top_records_changed_timer.timeout.connect(self.top_records_changed_actual)

        self.axisX = None
        self.axisY = None

        self.printing_arguments = get_comparison_args(self.args)

        self.chart_column = "count"

    def quit(self):
        sys.exit()

    def create_initial_comparison_report_arguments(self):
        if len(self.dissections) == 1:
            self.dissection1 = self.dissections[0]
            self.dissection2 = self.dissection1

            keys = list(self.dissection1.data.keys())

            # skipping key 0 which is the full timestamp
            self.dissection_key1 = keys[1]
            self.dissection_key2 = keys[2]

        else:
            self.dissection1 = self.dissections[0]
            self.dissection2 = self.dissections[1]

            # comparing the full times
            self.dissection_key1 = 0
            self.dissection_key2 = 0

    def create_comparison(self):
        self.pc = PcapCompare(
            self.args.pcap_files,
            maximum_count=self.args.packet_count,
            cache_results=self.args.cache_pcap_results,
            cache_file_suffix=self.args.cache_file_suffix,
            dissection_level=self.args.dissection_level,
            # between_times=self.args.between_times,
            bin_size=self.args.bin_size,
            pcap_filter=self.args.filter,
            layers=self.args.layers,
            force_load=self.args.force_load,
            force_overwrite=self.args.force_overwrite,
            merge_files=self.args.merge,
        )

        # create the graph data storage
        # and load everything in
        self.dissections = list(self.pc.load_pcaps())

        self.create_initial_comparison_report_arguments()
        self.compare_two()

    def compare_two(self):
        self.comparison = self.pc.compare_dissections(
            self.dissection1.data[self.dissection_key1],
            self.dissection2.data[self.dissection_key2],
        )

    def update_chart(
        self,
        chart: QChart,
        match_string: str,
        match_value: str | None = None,
        chart_column: Optional[str] = None,
    ):
        self.match_string = match_string
        self.match_value = match_value

        if chart_column is None:
            chart_column = self.chart_column

        # for matching on a single value, don't do a minimum count at all
        tmpv = self.minimum_count
        self.minimum_count = self.minimum_graph_count
        if match_value is not None:
            self.minimum_count = 0

        df = self.get_dataframe(calculate_load_fraction=True)

        # TODO: there must be a better way! (key is duplicated)
        series_set = []
        maxv = -100
        for key in df.key.unique():
            series = QLineSeries()

            for index in df[df["key"] == key].index:
                series.append(
                    df["time"][index].to_pydatetime().timestamp() * 1000,
                    df[chart_column][index],
                )

                height = df["count"][index]
                maxv = max(maxv, height)

            series.setName(df["subkey"][index])
            series.setOpacity(0.5)
            series_set.append(series)

        if len(df) == 0:
            return  # TODO: handle displaying an error

        df["time"].min().to_pydatetime().timestamp()
        df["time"].max().to_pydatetime().timestamp()

        grey = QColor("grey")

        # add another series for file ovelays
        for dissection in self.dissections:
            timestamps = list(dissection.data.keys())
            first_time = timestamps[1]  # skip the leading 0 timestamp
            last_time = timestamps[-1]

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

            # beginning end markers
            series = QLineSeries()
            series.append(first_time * 1000, maxv + tick_height)
            series.append(last_time * 1000, maxv + tick_height)

            series.setMarkerSize(20)
            triangle = QImage("images/grey_triangle.png").scaled(10, 10)
            series.setLightMarker(triangle)
            series_set.append(series)

        # we always add the real data last to keep file name coloring consistent

        if self.axisX:
            chart.removeAxis(self.axisX)
        self.axisX = QDateTimeAxis()
        self.axisX.setTickCount(5)
        self.axisX.setFormat("yyyy-MM-dd\nhh:mm")
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

        self.saved_df = df
        self.minimum_count = tmpv

    def update_detail_chart(
        self, match_string: str = "__TOTAL__", match_value: str | None = None
    ):
        self.detail_graph.setTitle(match_string)
        self.detail_graph.removeAllSeries()
        self.update_chart(self.detail_graph, match_string, match_value)

    def update_traffic_chart(self):
        self.update_chart(self.traffic_graph, "__TOTAL__", chart_column="count")

    # def show_comparison(self, pcap_one, timestamp_one, pcap_two, timestamp_two):

    def graph_type_changed(self, value):
        if value == 0:
            self.chart_column = "count"
        else:
            self.chart_column = "load_fraction"
        self.update_detail_chart(self.match_string, self.match_value)

    def header_clicked(self, key):
        self.update_detail_chart(key, None)

    def min_count_changed_actual(self):
        self.printing_arguments["minimum_count"] = self.minimum_count
        self.update_report()
        self.update_detail_chart(self.match_string, self.match_value)
        debug(f"updating table with minimum count of {self.minimum_count}")

    def min_count_changed(self, value):
        self.minimum_count = value
        # in case we're running already, stop it first
        self.min_count_changed_timer.stop()
        self.min_count_changed_timer.start()
        debug(f"changed minimum count to {self.minimum_count}")

    def min_graph_count_changed_actual(self):
        self.update_detail_chart(self.match_string, self.match_value)
        debug(f"updating graph with minimum count of {self.minimum_graph_count}")

    def min_graph_count_changed(self, value):
        self.minimum_graph_count = value
        # in case we're running already, stop it first
        self.min_graph_changed_timer.stop()
        self.min_graph_changed_timer.start()
        debug(f"changed minimum count to {self.minimum_graph_count}")

    def top_records_changed_actual(self):
        self.printing_arguments["top_records"] = self.top_records
        self.update_report()
        self.update_detail_chart(self.match_string, self.match_value)
        debug(f"updating top report count with {self.top_records}")

    def top_records_changed(self, value):
        self.top_records = value
        # in case we're running already, stop it first
        self.top_records_changed_timer.stop()
        self.top_records_changed_timer.start()

    # def clearGridLayout(layout, deleteWidgets: bool = True):

    #     for widget in layout.something():

    # while (QLayoutItem* item = layout->takeAt(0))

    #     if (deleteWidgets)
    #         if (QWidget* widget = item->widget())
    #             widget->deleteLater();
    #     if (QLayout* childLayout = item->layout())
    #     delete item;

    def set_left_dissection(self, action):
        self.left_w.setText(basename(action.text()))
        selection = action.data()
        if isinstance(selection, tuple):
            (filenum, timestamp) = selection
            self.dissection1 = self.dissections[filenum]
            self.dissection1_key = timestamp
        else:
            self.dissection1 = self.dissections[selection]
            self.dissection1_key = 0
        self.compare_two()
        self.update_report()

    def set_right_dissection(self, action):
        self.right_w.setText(basename(action.text()))

        selection = action.data()
        if isinstance(selection, tuple):
            (filenum, timestamp) = selection
            self.dissection2 = self.dissections[filenum]
            self.dissection2_key = timestamp
        else:
            self.dissection2 = self.dissections[selection]
            self.dissection2_key = 0

        self.compare_two()
        self.update_report()

    def update_left_right_sources(self):
        self.left_menu = QMenu(basename(self.dissection1.pcap_file))
        for n, item in enumerate(self.dissections):
            # TODO: this should warn or be a configurable limit or something...
            if len(item.data) < 20:
                time_menu = self.left_menu.addMenu(item.pcap_file)
                for timestamp in item.data:
                    if timestamp == 0:
                        menu_name = item.pcap_file + " ALL"
                    else:
                        menu_name = datetime.fromtimestamp(timestamp, dt.UTC).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    submenu_action = time_menu.addAction(menu_name)
                    submenu_action.setData((n, timestamp))
            else:
                action = self.left_menu.addAction(item.pcap_file)
                action.setData(n)

        self.left_w.setMenu(self.left_menu)
        self.left_w.setText(basename(self.dissection1.pcap_file))

        self.right_menu = QMenu(basename(self.dissection2.pcap_file))
        for n, item in enumerate(self.dissections):
            # TODO: this should warn or be a configurable limit or something...
            if len(item.data) < 20:
                time_menu = self.right_menu.addMenu(item.pcap_file)
                for timestamp in item.data:
                    if timestamp == 0:
                        menu_name = basename(item.pcap_file) + " ALL"
                    else:
                        menu_name = datetime.fromtimestamp(timestamp, dt.UTC).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    submenu_action = time_menu.addAction(menu_name)
                    submenu_action.setData((n, timestamp))
            else:
                action = self.right_menu.addAction(item.pcap_file)
                action.setData(n)

        self.right_w.setMenu(self.right_menu)
        self.right_w.setText(basename(self.dissection2.pcap_file))

    def add_control_widgets(self):
        self.source_menus.addWidget(QLabel("Left:"))
        self.left_w = QToolButton(
            autoRaise=True, popupMode=QToolButton.ToolButtonPopupMode.InstantPopup
        )
        self.left_w.triggered.connect(self.set_left_dissection)
        self.source_menus.addWidget(self.left_w)

        self.source_menus.addStretch()

        self.source_menus.addWidget(QLabel("Right:"))
        self.right_w = QToolButton(
            autoRaise=True, popupMode=QToolButton.ToolButtonPopupMode.InstantPopup
        )
        self.right_w.triggered.connect(self.set_right_dissection)
        self.source_menus.addWidget(self.right_w)

        self.update_left_right_sources()

        self.control_menus.addWidget(QLabel("Minimum report count:"))
        self.minimum_count_w = QSpinBox()
        self.minimum_count_w.setMinimum(0)
        self.minimum_count_w.setMaximum(1000000)  # TODO: inf
        self.minimum_count_w.setValue(int(self.minimum_count))
        self.minimum_count_w.setSingleStep(5)

        self.minimum_count_w.valueChanged.connect(self.min_count_changed)
        self.control_menus.addWidget(self.minimum_count_w)

        self.control_menus.addWidget(QLabel("Report at most:"))
        self.top_records_w = QSpinBox()
        self.top_records_w.setMinimum(0)
        self.top_records_w.setMaximum(1000000)  # TODO: inf
        self.top_records_w.setValue(int(self.top_records or 0))
        self.top_records_w.setSingleStep(1)

        self.top_records_w.valueChanged.connect(self.top_records_changed)
        self.control_menus.addWidget(self.top_records_w)

        self.control_menus.addWidget(QLabel("Minimum graph count:"))
        self.minimum_graph_count_w = QSpinBox()
        self.minimum_graph_count_w.setMinimum(0)
        self.minimum_graph_count_w.setMaximum(1000000)  # TODO: inf
        self.minimum_graph_count_w.setValue(int(self.minimum_graph_count))
        self.minimum_graph_count_w.setSingleStep(5)

        self.minimum_graph_count_w.valueChanged.connect(self.min_graph_count_changed)
        self.control_menus.addWidget(self.minimum_graph_count_w)

        self.show_as_percent_w = QCheckBox("Percent")
        self.control_menus.addWidget(self.show_as_percent_w)
        self.show_as_percent_w.stateChanged.connect(self.graph_type_changed)

    def update_report(self):
        # TODO: less duplication with this and compare:print_report()
        "Fills in the grid table showing the differences from a saved report."
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
        headers = [
            "Value",
            "Left Count",
            "Right Count",
            "Delta",
            "Left %",
            "Right %",
            "Delta %",
        ]
        for n, header in enumerate(headers):
            header = header.replace(" ", "**\n\n**")
            label = QLabel("**" + header + "**")
            label.setAlignment(Qt.AlignmentFlag.AlignRight)
            label.setTextFormat(Qt.TextFormat.MarkdownText)
            self.comparison_panel.addWidget(label, 0, n)

        current_grid_row = 1

        printing_arguments = self.printing_arguments
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
                        report_button, current_grid_row, 0, 1, 6
                    )
                    current_grid_row += 1
                    reported = True

                subkey = record["subkey"]
                delta_percentage: float = record["delta_percentage"]

                # apply some fancy styling
                style = ""
                if delta_percentage < -0.5:
                    style = "color: red"  # TODO bold
                elif delta_percentage < 0.0:
                    style = "color: red"
                elif delta_percentage > 0.5:
                    style = "color: lightgreen"  # TODO bold
                elif delta_percentage > 0.0:
                    style = "color: lightgreen"

                # construct the output line with styling
                subkey = Dissection.make_printable(key, subkey)
                debug(f"  adding {subkey}")

                subkey_button = QPushButton("    " + subkey)
                subkey_button.clicked.connect(
                    CallWithParameter(self.update_detail_chart, key, subkey)
                )
                subkey_button.setStyleSheet(style)
                self.comparison_panel.addWidget(subkey_button, current_grid_row, 0)

                column = 0

                column += 1
                label = QLabel(f"{record['left_count']:>8}")
                label.setAlignment(Qt.AlignmentFlag.AlignRight)
                self.comparison_panel.addWidget(label, current_grid_row, column)

                column += 1
                label = QLabel(f"{record['right_count']:>8}")
                label.setAlignment(Qt.AlignmentFlag.AlignRight)
                self.comparison_panel.addWidget(label, current_grid_row, column)

                column += 1
                label = QLabel(f"{record['delta_absolute']:>8}")
                label.setAlignment(Qt.AlignmentFlag.AlignRight)
                self.comparison_panel.addWidget(label, current_grid_row, column)

                column += 1
                label = QLabel(f"{record['left_percentage']:>7.2f}")
                label.setAlignment(Qt.AlignmentFlag.AlignRight)
                self.comparison_panel.addWidget(label, current_grid_row, column)

                column += 1
                label = QLabel(f"{record['right_percentage']:>7.2f}")
                label.setAlignment(Qt.AlignmentFlag.AlignRight)
                self.comparison_panel.addWidget(label, current_grid_row, column)

                column += 1
                label = QLabel(f"{100*delta_percentage:>7.2f}")
                label.setAlignment(Qt.AlignmentFlag.AlignRight)
                self.comparison_panel.addWidget(label, current_grid_row, column)

                current_grid_row += 1

        (self.match_string, self.match_value) = (tmp_key, tmp_value)


def parse_args() -> Namespace:
    "Parse the command line arguments."
    parser = ArgumentParser(
        formatter_class=RichHelpFormatter,
        description=__doc__,
        epilog="Example Usage: taffy-explore -C file1.pcap file2.pcap",
    )

    limitor_add_parseargs(parser)
    compare_add_parseargs(parser)

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

    dissector_handle_arguments(args)

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
