import sys
import logging
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from traffic_taffy.dissector import (
    dissector_add_parseargs,
    limitor_add_parseargs,
    check_dissector_level,
)
from traffic_taffy.compare import PcapCompare

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
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QHBoxLayout,
    QFrame,
    QLabel,
    QApplication,
)


class SectionExpandButton(QPushButton):
    """a QPushbutton that can expand or collapse its section"""

    def __init__(self, item, text="", parent=None):
        super().__init__(text, parent)
        self.section = item
        self.clicked.connect(self.on_clicked)

    def on_clicked(self):
        """toggle expand/collapse of section by clicking"""
        if self.section.isExpanded():
            self.section.setExpanded(False)
        else:
            self.section.setExpanded(True)


class TaffyExplorer(QDialog):
    """Explore PCAP files by comparison slices"""

    def __init__(self, args):
        super().__init__()
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.mainLayout = QVBoxLayout()
        self.mainLayout.addWidget(self.tree)
        self.setLayout(self.mainLayout)
        self.tree.setIndentation(0)

        self.sections = []
        self.define_sections()
        self.add_sections()

        self.plusone = QPushButton("Add one")
        self.mainLayout.addWidget(self.plusone)
        self.plusone.clicked.connect(self.addone)

        self.args = args

    def addone(self):
        print("here")
        self.add_section("new item", QLabel("one thing"))

    def add_section(self, title, widget):
        button1 = self.add_button(title)
        section1 = self.add_widget(button1, widget)
        button1.addChild(section1)

    def add_sections(self):
        """adds a collapsible sections for every
        (title, widget) tuple in self.sections
        """
        # self.tree.clear()
        for title, widget in self.sections:
            self.add_section(title, widget)

    def define_sections(self):
        """reimplement this to define all your sections
        and add them as (title, widget) tuples to self.sections
        """
        widget = QFrame(self.tree)
        layout = QHBoxLayout(widget)
        layout.addWidget(QLabel("Bla"))
        layout.addWidget(QLabel("Blubb"))
        title = "Section 1"
        self.sections.append((title, widget))

    def add_button(self, title):
        """creates a QTreeWidgetItem containing a button
        to expand or collapse its section
        """
        item = QTreeWidgetItem()
        self.tree.addTopLevelItem(item)
        self.tree.setItemWidget(item, 0, SectionExpandButton(item, text=title))
        return item

    def add_widget(self, button, widget):
        """creates a QWidgetItem containing the widget,
        as child of the button-QWidgetItem
        """
        section = QTreeWidgetItem(button)
        section.setDisabled(True)
        self.tree.setItemWidget(section, 0, widget)
        return section

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
        )

        # compare the pcaps
        self.pcap_data = list(self.pc.load_pcaps())

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

    parser.add_argument("pcap_files", type=str, nargs="*", help="PCAP files to analyze")

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
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
