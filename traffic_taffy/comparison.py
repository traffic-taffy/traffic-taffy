from rich.console import Console
from traffic_taffy.dissection import Dissection


class Comparison:
    def __init__(self, contents: list, title: str = ""):
        self.contents = contents
        self.title = title
        self.console = None
        self.printing_arguments = {}

    # title
    @property
    def title(self):
        return self._title

    @title.setter
    def title(self, new_title):
        self._title = new_title

    # report contents -- actual data
    @property
    def contents(self):
        return self._contents

    @contents.setter
    def contents(self, new_contents):
        self._contents = new_contents

    # printing arguments
    @property
    def printing_arguments(self):
        return self._printing_arguments

    @printing_arguments.setter
    def printing_arguments(self, new_printing_arguments):
        self._printing_arguments = new_printing_arguments

    # actual routines to print stuff
    def init_console(self):
        if not self.console:
            self.console = Console()

    def print(self, printing_arguments) -> None:
        "outputs the results"
        self.print_header()

        print(f"************ {self.title}")
        self.printing_arguments = printing_arguments
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

        contents = self.contents

        self.init_console()

        for key in sorted(contents):
            reported: bool = False

            if (
                self.printing_arguments["match_string"]
                and self.printing_arguments["match_string"] not in key
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

    def filter_check(self, data: dict) -> bool:
        "Returns true if we should include it"
        delta: float = data["delta"]
        total: int = data["total"]

        if self.printing_arguments["only_positive"] and delta <= 0:
            return False

        if self.printing_arguments["only_negative"] and delta >= 0:
            return False

        if (
            not self.printing_arguments["print_threshold"]
            and not self.printing_arguments["minimum_count"]
        ):
            # always print
            return True

        if (
            self.printing_arguments["print_threshold"]
            and not self.printing_arguments["minimum_count"]
        ):
            # check printing_arguments["print_threshold"] as a fraction
            if abs(delta) > self.printing_arguments["print_threshold"]:
                return True
        elif (
            not self.printing_arguments["print_threshold"]
            and self.printing_arguments["minimum_count"]
        ):
            # just check printing_arguments["minimum_count"]
            if total > self.printing_arguments["minimum_count"]:
                return True
        else:
            # require both
            if (
                total > self.printing_arguments["minimum_count"]
                and abs(delta) > self.printing_arguments["print_threshold"]
            ):
                return True

        return False
