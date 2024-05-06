"""traffic-taffy algorithm produce comparisons between different datasets."""

from __future__ import annotations
from typing import List, TYPE_CHECKING
from logging import error

if TYPE_CHECKING:
    from traffic_taffy.dissection import Dissection
    from traffic_taffy.reports import Report


class ComparisonAlgorithm:
    """A base class for all comparison algorithms."""

    def __init__(self):
        """Construct a ComparisonAlgorithm."""

    def compare_dissections(self, _dissections: List[Dissection]) -> List[Report]:
        """Compare dissections base function just to warn things are not implemented."""
        error("code failure: base class compare_two_dissections should never be called")
        raise ValueError
