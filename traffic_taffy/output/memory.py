from collections import defaultdict

from traffic_taffy.output import Output
from traffic_taffy.dissection import Dissection


class Memory(Output):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.console = None
        self.have_done_header = False
        self.title = kwargs.get("title", "")
        self.memory = None

    @property
    def title(self):
        return self._title

    @title.setter
    def title(self, new_title):
        self._title = new_title

    @property
    def memory(self):
        return self._memory

    @memory.setter
    def memory(self, new_memory):
        self._memory = new_memory

    def output_start(self, report):
        "Prints the header about columns being displayed"
        # This should match the spacing in print_contents()
        self.title = report.title
        self.memory = defaultdict(list)

    def output_record(self, key, subkey, data) -> None:
        "prints a report to the console"

        subkey = Dissection.make_printable(key, subkey)
        self.memory[key].append(
            {
                "subkey": subkey,
                "left_count": data["left_count"],
                "right_count": data["right_count"],
                "delta_absolute": data["delta_absolute"],
                "left_percentage": data["left_percentage"],
                "right_percentage": data["right_percentage"],
                "delta_percentage": data["delta_percentage"],
            }
        )
