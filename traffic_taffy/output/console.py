"""A module to output comparison results to the console."""

from __future__ import annotations
from typing import Dict, Any, TYPE_CHECKING
from rich.console import Console as RichConsole

from traffic_taffy.output import Output
from traffic_taffy.dissection import Dissection

import dataclasses

if TYPE_CHECKING:
    from traffic_taffy.comparison import Comparison
    from traffic_taffy.reports import Report


class Console(Output):
    """An output class for reporting to a console."""

    BOLD_LIMIT = 0.5
    POSITIVE = 0.0

    def __init__(self, *args: list, **kwargs: Dict[str, Any]):
        """Create a console reporting object."""
        super().__init__(*args, **kwargs)
        self.console = None
        self.have_done_header = False

    # actual routines to print stuff
    def init_console(self) -> None:
        """Initialize the rich console object."""
        if not self.console:
            self.console = RichConsole()

    def output_start(self, comparison: Comparison, report: Report) -> None:
        """Print the header about columns being displayed."""
        # This should match the spacing in print_contents()
        self.init_console()

        self.console.print(f"======== {comparison.title}")
        if self.have_done_header:
            return

        self.have_done_header = True

        style = ""
        subkey = "Value"
        endstyle = ""

        field_values = {field.name: field.name for field in dataclasses.fields(report)}

        line = report.header_string.format(
            style=style,
            endstyle=endstyle,
            subkey=subkey,
            **field_values,
        )

        self.console.print(line)

    def output_new_section(self, key: str) -> None:
        """Print a new section border."""
        self.console.print(f"----- {key}")

    def output_record(self, key: str, subkey: Any, data: Dict[str, Any]) -> None:
        """Print a report to the console."""

        style = ""
        endstyle = ""
        if getattr(data, "delta_percentage", None):
            delta_percentage: float = data.delta_percentage

            # apply some styling depending on range
            if delta_percentage < -Console.BOLD_LIMIT:
                style = "[bold red]"
            elif delta_percentage < Console.POSITIVE:
                style = "[red]"
            elif delta_percentage > Console.BOLD_LIMIT:
                style = "[bold green]"
            elif delta_percentage > Console.POSITIVE:
                style = "[green]"
            endstyle = style.replace("[", "[/")

        # construct the output line with styling
        subkey = Dissection.make_printable(key, subkey)

        field_values = {
            field.name: getattr(data, field.name) for field in dataclasses.fields(data)
        }

        line = data.format_string.format(
            style=style,
            endstyle=endstyle,
            subkey=subkey,
            **field_values,
        )

        # print it to the rich console
        self.console.print(line)
