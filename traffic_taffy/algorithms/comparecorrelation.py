"""Compares datasets using DataFrame's correlation."""

from __future__ import annotations
from typing import List, TYPE_CHECKING
import pandas as pd
import numpy as np

from logging import debug, warning, info

from traffic_taffy.algorithms.compareseries import ComparisonSeriesAlgorithm
from traffic_taffy.reports.correlationreport import CorrelationReport
from traffic_taffy.comparison import Comparison, OrganizedReports
from traffic_taffy.taffy_config import TaffyConfig, taffy_default

if TYPE_CHECKING:
    from pandas import DataFrame
    from numpy import ndarray

taffy_default("algorithms.correlation.minimum_correlation", 0.8)
taffy_default("algorithms.correlation.correlation_method", "spearman")
taffy_default("algorithms.correlation.max_pivot", 1000)


class CompareCorrelation(ComparisonSeriesAlgorithm):
    """Compare series using the pandas correlation."""

    def __init__(
        self,
        timestamps: List[int] | None = None,
        match_string: str | None = None,
        match_value: str | None = None,
        minimum_count: int | None = None,
        make_printable: bool = False,
        match_expression: str | None = None,
    ):
        """Create a CompareCorrelation instance.

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
    ) -> List[CorrelationReport]:
        """Compare a bunch of series using correlation.

        This tries to do a comparison in a faster path if the number
        of keys are reasonable (for if not a pivot will consume all
        available memory)
        """

        config = TaffyConfig()
        minimum_correlation = float(
            config.get_dotnest("algorithms.correlation.minimum_correlation")
        )
        self.minimum_correlation = minimum_correlation

        max_pivot = int(config.get_dotnest("algorithms.correlation.max_pivot"))
        method = config.get_dotnest("algorithms.correlation.correlation_method")
        self.method = method

        indexes = df["index"].unique()
        num_indexes = len(indexes)
        if num_indexes > max_pivot:
            # we assume this is arbitrarily too large
            # use the slower parent version instead
            warning(
                f"too many indexes ({num_indexes} > {max_pivot}) == using slower routine to conserve memory"
            )
            return super().compare_series(df, indexes)

        info(f"Studying correlation of {num_indexes} indexes")

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
                    # if value > minimum_correlation:
                    #     print(
                    #         f"{column_left:<30} similar to {column_right:<30}: {value}"
                    #     )
            return reports

        # default to using the datafram corr method instead
        df.fillna(0, inplace=True)
        results = df.corr(method=method)

        for num, column_left in enumerate(indexes):
            for column_right in indexes[num + 1 :]:
                value = results[column_left][column_right]
                if value > minimum_correlation:
                    # print(f"{column_left:<30} similar to {column_right:<30}: {value}")
                    if column_left not in reports:
                        reports[column_left] = {}
                    reports[column_left][column_right] = CorrelationReport(
                        value,
                    )
        return [Comparison(reports, "Correlation Report", "correlation")]

    def compare_two_series(
        self,
        column_left: str,
        series_left: list,
        column_right: str,
        series_right: list,
        reports: OrganizedReports = None,
    ) -> dict:
        """Compare two series using the dataframe correlation algorithms."""
        debug(f"correlation comparing {column_left} and {column_right}")
        both = pd.concat([series_left, series_right], axis=1)
        both.fillna(0, inplace=True)

        # Note actually faster -- about the same as df.corr
        # import scipy
        # results = scipy.stats.kendalltau(both['left'], both['right'])
        # value = results.statistic

        results = both.corr(method=self.method)
        value = results["left"][1]
        debug(f"{column_left:<30} similar to {column_right:<30}: {value}")

        if value > self.minimum_correlation:
            # print(f"{column_left:<30} similar to {column_right:<30}: {value}")

            return CorrelationReport(value)

        return
