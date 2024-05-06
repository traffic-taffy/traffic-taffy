"""Report for storing correlations between signals."""

from __future__ import annotations
from typing import Dict
from dataclasses import dataclass
from traffic_taffy.reports import Report


@dataclass
class CorrelationReport(Report):
    """Report for storing correlations between signals."""

    column_left: str
    column_right: str
    correlation: float

    @property
    def formatting(self) -> Dict[str, str]:
        """Formatting field recommendations."""
        return {
            "column_left": "<30",
            "column_right": "<30",
            "correlation": ">7.2f",
        }

    @property
    def format_string(self) -> str:
        """Formatting string for each printed line."""
        line = "  {style}{subkey:<50}{endstyle}"
        line += " {column_left:<30} {column_right:<30} {correlation:>7.2f}"

        return line
