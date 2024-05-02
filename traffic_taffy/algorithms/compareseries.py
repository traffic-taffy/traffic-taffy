"""Compares datasets in time-slices rather than by series."""

from __future__ import annotations
from typing import List, TYPE_CHECKING
from traffic_taffy.algorithms import ComparisonAlgorithm
from traffic_taffy.graphdata import PcapGraphData

from logging import error

if TYPE_CHECKING:
    from traffic_taffy.dissection import Dissection
    from traffic_taffy.report import Report


class ComparisonSeriesAlgorithm(ComparisonAlgorithm):
    """A base class for algorithms that compare left/right slices."""

    def __init__(self):
        """Create a ComparisonAlgorithm."""

    def compare_two_series(
        self,
        _column_left: str,
        _series_left: list,
        _column_right: str,
        _series_right: list,
    ) -> dict:
        """Error catching base class function for comparing two columnar series."""
        error("code failure: base class compare_two_series should never be called")
        raise ValueError

    def compare_dissections(self, dissections: List[Dissection]) -> List[Report]:
        """Compare all the column series."""
        reports = []
        # hack to figure out if there is at least two instances of a generator
        # without actually extracting them all
        # (since it could be memory expensive)

        # merge all dissections together into one
        # TODO(hardaker): ideally this should be a parameter
        #                 forced upward into dissectmany
        dissection = next(dissections)
        for to_be_merged in dissections:
            dissection.merge(to_be_merged)

        # TODO(hardaker): Do time binning filling with zeros
        data = PcapGraphData()
        data.dissections = [dissection]
        # data.normalize_bins() ?
        df = data.get_dataframe()

        indexes = df["index"].unique()
        for column_left in indexes:
            series_left = df[df["index"] == column_left]
            series_left = series_left.set_index("time")
            series_left = series_left["count"]
            series_left.name = "left"

            for column_right in indexes:  # TODO(hardaker): n^2 is bad
                if column_left == column_right:
                    continue

                series_right = df[df["index"] == column_right]
                series_right = series_right.set_index("time")
                series_right = series_right["count"]
                series_right.name = "right"

                self.compare_two_series(
                    column_left, series_left, column_right, series_right
                )
        return reports
