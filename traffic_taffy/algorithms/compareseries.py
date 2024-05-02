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
        _column_one: str,
        _column_one_series: list,
        _column_two: str,
        _column_two_series: list,
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
        for column1 in indexes:
            series1 = df[df["index"] == column1]
            for column2 in indexes:  # TODO(hardaker): n^2 is bad
                if column1 == column2:
                    continue

                series2 = df[df["index"] == column2]
                self.compare_two_series(column1, series1, column2, series2)
        return reports
