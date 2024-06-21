"""Report for storing correlations between signals."""

from __future__ import annotations
from typing import Dict
from dataclasses import dataclass
from traffic_taffy.reports import Report


@dataclass
class CorrelationChangeReport(Report):
    """Report for storing correlations between signals."""

    left_correlation: float
    right_correlation: float
    delta_correlation: float
    timestamp: int

    @property
    def formatting(self) -> Dict[str, str]:
        """Formatting field recommendations."""
        return {
            "timestamp": ">7",
            "left_correlation": ">7.2f",
            "right_correlation": ">7.2f",
            "delta_correlation": ">7.2f",
        }

    @property
    def header_string(self) -> str:
        """Formatting string for each printed line."""
        line = "  {style}{subkey:<50}{endstyle}"
        line += " {timestamp:>10}"
        line += " {left_correlation:>17}"
        line += " {right_correlation:>17}"
        line += " {delta_correlation:>17}"

        return line

    @property
    def format_string(self) -> str:
        """Formatting string for each printed line."""
        line = "  {style}{subkey:<50}{endstyle}"
        line += " {timestamp:>10}"
        line += " {left_correlation:>17.2f}"
        line += " {right_correlation:>17.2f}"
        line += " {delta_correlation:>17.2f}"

        return line

    def filter_check(self, output_options: dict) -> bool:
        """Return true if we should include it

        (which is always as we pre-filter for correlations)."""
        return True
