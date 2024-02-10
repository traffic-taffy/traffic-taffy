"""A module to output comparison results to the console."""

from __future__ import annotations
from typing import Dict, Any
from rich.console import Console as RichConsole

from traffic_taffy.output import Output
from traffic_taffy.dissection import Dissection
from traffic_taffy.comparison import Comparison


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

    def output_start(self, report: Comparison) -> None:
        """Print the header about columns being displayed."""
        # This should match the spacing in print_contents()
        self.init_console()

        self.console.print(f"======== {report.title}")
        if self.have_done_header:
            return

        self.have_done_header = True

        style = ""
        subkey = "Value"
        endstyle = ""
        left_count = "Left"
        right_count = "Right"
        actual_delta = "Delta"

        left_percent = "Left %"
        right_percent = "Right %"
        percent_delta = "Delta-%"

        line = f"  {style}{subkey:<50}{endstyle}"
        line += f" {left_count:>8} {right_count:>8} {actual_delta:>8}"
        line += f" {left_percent:>8} {right_percent:>8}  {percent_delta:>7}"

        self.console.print(line)

    def output_new_section(self, key: str) -> None:
        """Print a new section border."""
        self.console.print(f"----- {key}")

    def output_record(self, key: str, subkey: Any, data: Dict[str, Any]) -> None:
        """Print a report to the console."""
        delta_percentage: float = data["delta_percentage"]

        # apply some fancy styling
        style = ""
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
        line = f"  {style}{subkey:<50}{endstyle}"
        line += f" {data['left_count']:>8} {data['right_count']:>8} {data['delta_absolute']:>8}"
        line += f" {100*data['left_percentage']:>7.2f} {100*data['right_percentage']:>7.2f}  {100*delta_percentage:>7.2f}"

        # print it to the rich console
        self.console.print(line)
