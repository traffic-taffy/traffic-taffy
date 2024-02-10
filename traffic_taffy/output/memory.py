"""Store contents of a report in memory."""
from collections import defaultdict
from typing import Any

from traffic_taffy.output import Output
from traffic_taffy.dissection import Dissection
from traffic_taffy.comparison import Comparison


class Memory(Output):
    """A class for storing report contents in memory."""

    def __init__(self, *args: list, **kwargs: dict):
        """Create a Memory object."""
        super().__init__(*args, **kwargs)
        self.console = None
        self.have_done_header = False
        self.title = kwargs.get("title", "")
        self.memory = None

    @property
    def title(self) -> str:
        """The title of the report."""
        return self._title

    @title.setter
    def title(self, new_title: str) -> None:
        self._title = new_title

    @property
    def memory(self) -> dict:
        """The data for the report."""
        return self._memory

    @memory.setter
    def memory(self, new_memory: dict) -> None:
        self._memory = new_memory

    def output_start(self, report: Comparison) -> None:
        """Print the header about columns being displayed."""
        # This should match the spacing in print_contents()
        self.title = report.title
        self.memory = defaultdict(list)

    def output_record(self, key: str, subkey: Any, data: dict) -> None:
        """Print a report to the console."""
        subkey = Dissection.make_printable(key, subkey)
        self.memory[key].append(
            {
                "subkey": subkey,
                "left_count": data.left_count,
                "right_count": data.right_count,
                "delta_absolute": data.delta_absolute,
                "left_percentage": data.left_percentage,
                "right_percentage": data.right_percentage,
                "delta_percentage": data.delta_percentage,
            }
        )
