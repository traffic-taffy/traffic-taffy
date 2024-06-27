"""Report for storing a comparison between two different dissections."""

from __future__ import annotations
from typing import Dict
from dataclasses import dataclass
from traffic_taffy.reports import Report


@dataclass
class CompareSlicesReport(Report):
    """Report for storing a comparison between two different dissections."""

    delta_percentage: float
    delta_absolute: int
    total: int
    left_count: int
    right_count: int
    left_percentage: float
    right_percentage: float

    @property
    def formatting(self) -> Dict[str, str]:
        """Formatting field recommendations."""
        return {
            "delta_percentage": ">7.2f",
            "delta_absolute": ">8",
            "total": None,
            "left_count": ">8",
            "right_count": ">8",
            "left_percentage": ">7.2f",
            "right_percentage": ">7.2f",
        }

    @property
    def header_string(self) -> str:
        """Header string."""
        line = "  {style}{subkey:<50}{endstyle}"
        line += " {left_count:>8} {right_count:>8} {delta_absolute:>8}"
        line += " {left_percentage:>7} {right_percentage:>7}  {delta_percentage:>7}"

        return line

    @property
    def format_string(self) -> str:
        """Formatting string for each printed line."""
        line = "  {style}{subkey:<50}{endstyle}"
        line += " {left_count:>8} {right_count:>8} {delta_absolute:>8}"
        line += " {left_percentage:>7.2f} {right_percentage:>7.2f}  {delta_percentage:>7.2f}"

        return line

    def filter_check(self, output_options: dict) -> bool:
        """Return true if we should include it."""
        delta: float = self.delta_percentage
        total: int = self.total

        if output_options["only_positive"] and delta <= 0:
            return False

        if output_options["only_negative"] and delta >= 0:
            return False

        if (
            not output_options["print_threshold"]
            and not output_options["minimum_count"]
        ):
            # always print
            return True

        if output_options["print_threshold"] and not output_options["minimum_count"]:
            # check output_options["print_threshold"] as a fraction
            if abs(delta) > output_options["print_threshold"]:
                return True
        elif not output_options["print_threshold"] and output_options["minimum_count"]:
            # just check output_options["minimum_count"]
            if total > output_options["minimum_count"]:
                return True
        elif (
            total > output_options["minimum_count"]
            and abs(delta) > output_options["print_threshold"]
        ):
            # require both
            return True

        return False
