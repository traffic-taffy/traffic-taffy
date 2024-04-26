"""traffic-taffy algorithm produce comparisons between different datasets."""

from logging import error


class ComparisonAlgorithm:
    """A base class for all comparison algorithms."""

    def __init__(self):
        """Construct a ComparisonAlgorithm."""

    def compare_dissections(self, _left_side: dict, _right_side: dict) -> dict:
        """Compare dissections base function just to warn things are not implemented."""
        error("code failure: base class compare_two_dissections should never be called")
        raise ValueError
