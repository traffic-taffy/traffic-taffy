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
    def format_string(self) -> str:
        """Formatting string for each printed line."""
        line = "  {style}{subkey:<50}{endstyle}"
        line += " {left_count:>8} {right_count:>8} {delta_absolute:>8}"
        line += " {left_percentage:>7.2f} {right_percentage:>7.2f}  {delta_percentage:>7.2f}"

        return line
