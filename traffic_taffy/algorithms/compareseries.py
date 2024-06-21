"""Compares datasets in time-series rather than by series."""

from __future__ import annotations
from typing import List, TYPE_CHECKING
from traffic_taffy.algorithms import ComparisonAlgorithm
from traffic_taffy.graphdata import PcapGraphData
from traffic_taffy.comparison import Comparison, OrganizedReports

from logging import error

if TYPE_CHECKING:
    from traffic_taffy.dissection import Dissection
    from pandas import DataFrame
    from numpy import ndarray


class ComparisonSeriesAlgorithm(ComparisonAlgorithm):
    """A base class for algorithms that compare left/right series."""

    def __init__(
        self,
        timestamps: List[int] | None = None,
        match_string: str | None = None,
        match_value: str | None = None,
        minimum_count: int | None = None,
        make_printable: bool = False,
        match_expression: str | None = None,
    ):
        """Create a ComparisonAlgorithm."""
        self.timestamps = timestamps
        self.match_string = match_string
        self.match_value = match_value
        self.minimum_count = minimum_count
        self.make_printable = make_printable
        self.match_expression = (match_expression,)
        self.sort_by = "correlation"

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

    def compare_dissections(self, dissections: List[Dissection]) -> List[Comparison]:
        """Compare all the column series."""
        # hack to figure out if there is at least two instances of a generator
        # without actually extracting them all
        # (since it could be memory expensive)

        # merge all dissections together into one
        # TODO(hardaker): ideally this should be a parameter
        #                 forced upward into dissectmany
        dissection = next(dissections)
        for to_be_merged in dissections:
            dissection.merge(to_be_merged)

        # filter downward
        dissection = dissection.filter(
            self.timestamps,
            self.match_string,
            self.match_value,
            self.minimum_count,
            self.make_printable,
            self.match_expression,
        )

        data = PcapGraphData()
        data.dissections = [dissection]
        # data.normalize_bins() ?
        df = data.get_dataframe()

        return self.compare_series(df)

    def compare_series(
        self, df: DataFrame, indexes: ndarray | None = None
    ) -> List[Comparison]:
        """Compares the series found in a dataframe, two at a time."""

        reports: OrganizedReports = {}

        if indexes is None:
            indexes = df["index"].unique()

        for num, column_left in enumerate(indexes):
            series_left = df[df["index"] == column_left]
            series_left = series_left.set_index("time")
            series_left = series_left["count"]
            series_left.name = "left"

            # TODO(hardaker): n^2 is bad
            for column_right in indexes[num + 1 :]:
                if column_left == column_right:
                    continue

                series_right = df[df["index"] == column_right]
                series_right = series_right.set_index("time")
                series_right = series_right["count"]
                series_right.name = "right"

                report = self.compare_two_series(
                    column_left, series_left, column_right, series_right
                )
                if column_left not in reports:
                    reports[column_left] = {}

                if isinstance(report, list):
                    # TODO(hardaker): we don't actually handle arrays yet
                    reports[column_left][column_right].extend(report)
                elif report:
                    reports[column_left][column_right] = report

        return [Comparison(reports, "Correlation Report", self.sort_by)]
