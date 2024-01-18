import sys
import pyfsdb

from traffic_taffy.output import Output
from traffic_taffy.dissection import Dissection


class Fsdb(Output):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.console = None
        self.have_done_header = False
        self.in_report = None

        self.fsdb = pyfsdb.Fsdb(out_file_handle=sys.stdout)
        self.fsdb.out_column_names = [
            "report",
            "Key",
            "subkey",
            "left",
            "right",
            "delta",
            "left_fraction",
            "right_fraction",
            "delta_fraction",
        ]
        self.fsdb.converters = [str, str, str, int, int, int, float, float, float]

    def output_start(self, report):
        "Prints the header about columns being displayed"
        # This should match the spacing in print_contents()
        self.in_report = report.title

    def output_record(self, key, subkey, data) -> None:
        "prints a report to the console"

        subkey = Dissection.make_printable(key, subkey)
        self.fsdb.append(
            [
                self.in_report,
                key,
                subkey,
                data["left_count"],
                data["right_count"],
                data["delta_absolute"],
                data["left_percentage"],
                data["right_percentage"],
                data["delta_percentage"],
            ]
        )
