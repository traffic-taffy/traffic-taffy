"""Report for storing a comparison between two different dissections."""

from dataclasses import dataclass


@dataclass
class CompareSeriesReport:
    """Report for storing a comparison between two different dissections."""

    delta_percentage: float
    delta_absolute: int
    total: int
    left_count: int
    right_count: int
    left_percentage: float
    right_percentage: float
