"""Compares datasets using DataFrame's correlation."""

from __future__ import annotations
from typing import List, TYPE_CHECKING
import pandas as pd
import numpy as np

from logging import debug, warning, info

from traffic_taffy.algorithms.compareseries import ComparisonSeriesAlgorithm
from traffic_taffy.reports.correlationchangereport import CorrelationChangeReport
from traffic_taffy.comparison import Comparison, OrganizedReports
from traffic_taffy.taffy_config import TaffyConfig, taffy_default

if TYPE_CHECKING:
    from pandas import DataFrame
    from numpy import ndarray

taffy_default("algorithms.correlationchanges.minimum_change", 0.5)
taffy_default("algorithms.correlationchanges.correlation_method", "spearman")
taffy_default("algorithms.correlationchanges.comparison_width", 15)
taffy_default("algorithms.correlationchanges.slide_length", None)


class CompareCorrelationChanges(ComparisonSeriesAlgorithm):
    """Compare series using the pandas correlation."""

    MAX_PIVOT = 1000

    def __init__(
        self,
        timestamps: List[int] | None = None,
        match_string: str | None = None,
        match_value: str | None = None,
        minimum_count: int | None = None,
        make_printable: bool = False,
        match_expression: str | None = None,
    ):
        """Create a CompareCorrelationChanges instance.

        Valid methods: kendall, pearson, spearman, corrcoef

        speed-wise; pearson < spearman < corrcoef < kendall

        accuracy-wise:
            corrcoef: not great (uses np.corrcoef)
            pearson: better but, not good
            spearman: best
            kendall: best
        """
        super().__init__(
            timestamps,
            match_string,
            match_value,
            minimum_count,
            make_printable,
            match_expression,
        )
        self.method = None

    def compare_series(
        self, df: DataFrame, indexes: ndarray | None = None
    ) -> List[CorrelationChangeReport]:
        """Compare a bunch of series looking for changes in correlation.

        This tries to do a comparison in a faster path if the number
        of keys are reasonable (for if not a pivot will consume all
        available memory)
        """

        self.sort_by = "delta_correlation"

        config = TaffyConfig()
        minimum_change = float(
            config.get_dotnest("algorithms.correlationchanges.minimum_change", 0.3)
        )
        self.minimum_change = minimum_change

        method = config.get_dotnest("algorithms.correlationchanges.correlation_method")
        self.method = method

        comparison_width = config.get_dotnest(
            "algorithms.correlationchanges.comparison_width"
        )
        self.comparison_width = comparison_width

        slide_length = config.get_dotnest("algorithms.correlationchanges.slide_length")
        if not slide_length:
            slide_length = comparison_width
        self.slide_length = slide_length

        indexes = df["index"].unique()
        num_indexes = len(indexes)
        info(
            f"starting correlation changes comparison: num_indexes={num_indexes}, min_change={self.minimum_change}"
        )

        # TODO(hardaker): use a full sweeping comparison for faster correlations
        # now we just revert to the slower non-pivot method for proof of concept
        return super().compare_series(df, indexes)

        if num_indexes > self.MAX_PIVOT:
            # we assume this is arbitrarily too large
            # use the slower parent version instead
            warning(
                f"too many indexes ({num_indexes} > {self.MAX_PIVOT}) == using slower routine to conserve memory"
            )
            return super().compare_series(df, indexes)

        for key in ["subkey", "index", "filename"]:
            del df[key]
        df = df.pivot_table(
            columns=["key"], index=["time"], values="count", fill_value=0
        )

        # indexes have changed
        indexes = df.columns.to_list()

        # use pandas internal kendall
        # TODO(hardaker): np.corrcoef is multi-core but is pearsons
        # TODO(hardaker): scipy.stat.kendalltau is kendall,
        #                 but can only do one at a time

        # TODO(hardaker): df.corr() returns different numbers here
        # than inside compare_two_series!!

        reports: OrganizedReports = {}

        if method == "corrcoef":
            np_array = df.to_numpy()
            results = np.corrcoef(np_array)
            for numx, column_left in enumerate(indexes):
                for numy, column_right in enumerate(indexes[numx + 1 :]):
                    value = results[numx][numy]
                    # if value > minimum_value:
                    #     print(
                    #         f"{column_left:<30} similar to {column_right:<30}: {value}"
                    #     )
            return reports

        # default to using the datafram corr method instead
        results = df.corr(method=method)

        # TODO(hardaker): this doesn't actually do anything
        # need to break correlation into pieces and run multiple passes

        for num, column_left in enumerate(indexes):
            for column_right in indexes[num + 1 :]:
                value = results[column_left][column_right]
                if value > self.minimum_change:
                    # print(f"{column_left:<30} similar to {column_right:<30}: {value}")
                    if column_left not in reports:
                        reports[column_left] = {}
                    reports[column_left][column_right] = CorrelationChangeReport(
                        value,
                    )

        return [Comparison(reports, "Correlation Report", "delta_correlation")]

    def compare_two_series(
        self,
        column_left: str,
        series_left: list,
        column_right: str,
        series_right: list,
    ) -> CorrelationChangeReport | None:
        """Compare two series using the dataframe correlation algorithms."""
        debug(f"correlation comparing {column_left} and {column_right}")
        both = pd.concat([series_left, series_right], axis=1)
        both.fillna(0, inplace=True)

        # Note actually faster -- about the same as df.corr
        # import scipy
        # results = scipy.stats.kendalltau(both['left'], both['right'])
        # value = results.statistic

        start_index: int = 0
        middle_index: int = self.comparison_width
        end_index: int = 2 * self.comparison_width

        data_length = len(both)

        while end_index < data_length:
            left_correlation = both[start_index:middle_index].corr(self.method)["left"][
                "right"
            ]
            right_correlation = both[middle_index:end_index].corr(self.method)["left"][
                "right"
            ]
            delta_correlation = right_correlation - left_correlation

            # well this is ugly:
            timestamp = (
                both[middle_index : middle_index + 1]
                .index.to_pydatetime()[0]
                .timestamp()
            )

            debug(f"  {right_correlation} - {left_correlation} = {delta_correlation}")
            if abs(delta_correlation) >= self.minimum_change:
                return CorrelationChangeReport(
                    left_correlation, right_correlation, delta_correlation, timestamp
                )

            start_index += self.slide_length
            middle_index += self.slide_length
            end_index += self.slide_length

        # if we get here there are no change points found
        return
