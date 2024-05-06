"""Report for storing correlations between signals."""

from __future__ import annotations
from typing import Dict
from dataclasses import dataclass
from traffic_taffy.reports import Report


@dataclass
class CorrelationReport(Report):
    """Report for storing correlations between signals."""

    correlation: float

    @property
    def formatting(self) -> Dict[str, str]:
        """Formatting field recommendations."""
        return {
            "correlation": ">7.2f",
        }

    @property
    def header_string(self) -> str:
        """Formatting string for each printed line."""
        line = "  {style}{subkey:<50}{endstyle}"
        line += " {correlation:>11}"

        return line

    @property
    def format_string(self) -> str:
        """Formatting string for each printed line."""
        line = "  {style}{subkey:<50}{endstyle}"
        line += " {correlation:>11.2f}"

        return line

    def filter_check(self, output_options: dict) -> bool:
        """Return true if we should include it

        (which is always as we pre-filter for correlations)."""
        return True
