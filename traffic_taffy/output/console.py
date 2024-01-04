from traffic_taffy.output import Output
from traffic_taffy.dissection import Dissection
from rich.console import Console as RichConsole


class Console(Output):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.console = None
        self.have_done_header = False

    # actual routines to print stuff
    def init_console(self):
        if not self.console:
            self.console = RichConsole()

    def output_start(self, report):
        "Prints the header about columns being displayed"
        # This should match the spacing in print_contents()
        self.init_console()

        self.console.print(f"======== {report.title}")
        if self.have_done_header:
            return

        self.have_done_header = True

        style = ""
        subkey = "Value"
        endstyle = ""
        actual_delta = "Delta"
        percent_delta = "Delta-%"
        left_count = "Left"
        right_count = "Right"

        line = f"  {style}{subkey:<50}{endstyle}"
        line += f" {left_count:>8} {right_count:>8} {actual_delta:>8}"
        line += f" {percent_delta:>7}"

        self.console.print(line)

    def output_new_section(self, key):
        print(f"----- {key}")

    def output_record(self, key, subkey, data) -> None:
        "prints a report to the console"

        percent_delta: float = data["delta"]
        actual_delta: int = data["right_count"] - data["left_count"]

        # apply some fancy styling
        style = ""
        if percent_delta < -0.5:
            style = "[bold red]"
        elif percent_delta < 0.0:
            style = "[red]"
        elif percent_delta > 0.5:
            style = "[bold green]"
        elif percent_delta > 0.0:
            style = "[green]"
        endstyle = style.replace("[", "[/")

        # construct the output line with styling
        subkey = Dissection.make_printable(key, subkey)
        line = f"  {style}{subkey:<50}{endstyle}"
        line += f" {data['left_count']:>8} {data['right_count']:>8} {actual_delta:>8}"
        line += f" {100*percent_delta:>7.2f}"

        # print it to the rich console
        self.console.print(line)
