from traffic_taffy.output import Output
from traffic_taffy.dissection import Dissection
from rich.console import Console as RichConsole


class Console(Output):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.console = None

    # actual routines to print stuff
    def init_console(self):
        if not self.console:
            self.console = RichConsole()

    def output(self, report=None, output_options=None):
        "outputs the results"
        self.print_header()

        if output_options:
            self.output_options = output_options
        if report:
            self.report = report

        print(f"************ {self.report.title}")

        self.print_contents()

    def print_header(self):
        "Prints the header about columns being displayed"
        # This should match the spacing in print_contents()
        self.init_console()

        style = ""
        subkey = "Value"
        endstyle = ""
        delta = "Delta %"
        left_count = "Left"
        right_count = "Right"

        line = f"  {style}{subkey:<50}{endstyle}"
        line += f"{delta:>7} "
        line += f"{left_count:>8} {right_count:>8}"

        self.console.print(line)

    def print_contents(self) -> None:
        "prints a report to the console"

        contents = self.report.contents

        self.init_console()

        for key in sorted(contents):
            reported: bool = False

            if (
                "match_string" in self.output_options
                and self.output_options["match_string"] not in key
            ):
                continue

            # TODO: we don't do match_value here?

            for subkey, data in sorted(
                contents[key].items(), key=lambda x: x[1]["delta"], reverse=True
            ):
                if not self.filter_check(data):
                    continue

                # print the header
                if not reported:
                    print(f"====== {key}")
                    reported = True

                delta: float = data["delta"]

                # apply some fancy styling
                style = ""
                if delta < -0.5:
                    style = "[bold red]"
                elif delta < 0.0:
                    style = "[red]"
                elif delta > 0.5:
                    style = "[bold green]"
                elif delta > 0.0:
                    style = "[green]"
                endstyle = style.replace("[", "[/")

                # construct the output line with styling
                subkey = Dissection.make_printable(key, subkey)
                line = f"  {style}{subkey:<50}{endstyle}"
                line += f"{100*delta:>7.2f} "
                line += f"{data['left_count']:>8} {data['right_count']:>8}"

                # print it to the rich console
                self.console.print(line)
