"""Base module for output classes."""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from traffic_taffy.comparison import Comparison


class Output:
    """Base class for outputting reports."""

    def __init__(self, report: Comparison, options: dict | None = None):
        """Initialize the base."""
        self.report = report
        self.output_options = options or {}

    @property
    def report(self) -> Comparison:
        """The report itself."""
        return self._report

    @report.setter
    def report(self, new_report: Comparison) -> None:
        self._report = new_report

    @property
    def output_options(self) -> dict:
        """A list of output options."""
        return self._output_options

    @output_options.setter
    def output_options(self, new_output_options: dict) -> None:
        self._output_options = new_output_options

    def output(self, report: Comparison | None = None) -> None:
        """Dump a report to the output stream."""
        if not report:
            report = self.report
        contents = report.contents

        first_of_anything: bool = True

        top_records = self.output_options.get("top_records")

        # intentionally reversed, as it should default to high to low
        sort_order = not self.output_options.get("reverse_sort", False)

        sort_by = self.output_options.get("sort_by", "delta_percentage")

        # convert to lower case, and remove spaces and dashes
        sort_by = sort_by.lower().replace(" ", "").replace("-", "")

        sort_map = {
            "delta%": "delta_percentage",
            "delta": "delta_absolute",
            "left": "left_count",
            "right": "right_count",
            "left%": "left_percentage",
            "right%": "right_percentage",
        }
        sort_by = sort_map.get(sort_by, sort_by)

        for key in sorted(contents):
            reported: bool = False

            if (
                self.output_options.get("match_string") is not None
                and self.output_options["match_string"] not in key
            ):
                continue

            # TODO(hardaker): we don't do match_value here?

            record_count = 0
            for subkey, data in sorted(
                contents[key].items(),
                key=lambda x: x[1][sort_by],
                reverse=sort_order,
            ):
                if not self.filter_check(data):
                    continue

                # print the header
                if not reported:
                    if first_of_anything:
                        self.output_start(report)
                        first_of_anything = False

                    self.output_new_section(key)
                    reported = True

                self.output_record(key, subkey, data)

                record_count += 1

                if top_records and record_count >= top_records:
                    break

        self.output_close()

    def output_new_section(self, key: str) -> None:
        """Create a new section header."""
        return

    def output_close(self) -> None:
        """Close the output stream."""
        return

    def filter_check(self, data: dict) -> bool:
        """Return true if we should include it."""
        delta: float = data["delta_percentage"]
        total: int = data["total"]

        if self.output_options["only_positive"] and delta <= 0:
            return False

        if self.output_options["only_negative"] and delta >= 0:
            return False

        if (
            not self.output_options["print_threshold"]
            and not self.output_options["minimum_count"]
        ):
            # always print
            return True

        if (
            self.output_options["print_threshold"]
            and not self.output_options["minimum_count"]
        ):
            # check output_options["print_threshold"] as a fraction
            if abs(delta) > self.output_options["print_threshold"]:
                return True
        elif (
            not self.output_options["print_threshold"]
            and self.output_options["minimum_count"]
        ):
            # just check output_options["minimum_count"]
            if total > self.output_options["minimum_count"]:
                return True
        elif (
            total > self.output_options["minimum_count"]
            and abs(delta) > self.output_options["print_threshold"]
        ):
            # require both
            return True

        return False
