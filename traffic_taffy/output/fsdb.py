"""A module to output comparison results to an FSDB output."""
import sys
import pyfsdb
from typing import Any

from traffic_taffy.output import Output
from traffic_taffy.dissection import Dissection
from traffic_taffy.comparison import Comparison
from traffic_taffy.reports import Report

import dataclasses


class Fsdb(Output):
    """An FSDB report generator."""

    def __init__(self, *args: list, **kwargs: dict):
        """Create an FSDB report generator."""
        super().__init__(*args, **kwargs)
        self.console = None
        self.have_done_header = False
        self.in_report = None
        self.fsdb = None

    def init_fsdb(self, firstreport):
        self.fields = dataclasses.fields(firstreport)
        self.columns = []
        self.converters = []

        for field in self.fields:
            self.columns.append(field.name)
            self.converters.append(field.type)

        self.fsdb = pyfsdb.Fsdb(out_file_handle=sys.stdout)

        self.fsdb.out_column_names = [
            "report",
            "key",
            "subkey",
        ] + self.columns
        self.fsdb.converters = [str, str, str] + self.converters

    def output_start(self, comparison: Comparison, report: Report) -> None:
        """Print the header about columns being displayed."""
        # This should match the spacing in print_contents()
        self.in_report = comparison.title

    def output_record(self, key: str, subkey: Any, data: dict) -> None:
        """Print a report to the console."""
        if self.fsdb is None:
            self.init_fsdb(data)

        subkey = Dissection.make_printable(key, subkey)
        self.fsdb.append(
            [
                self.in_report,
                key,
                subkey,
            ]
            + [getattr(data, field.name) for field in dataclasses.fields(data)]
        )
