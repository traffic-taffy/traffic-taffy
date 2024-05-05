"""Compares datasets using DataFrame's correlation."""

from __future__ import annotations
from typing import List, TYPE_CHECKING
import pandas as pd
import numpy

from traffic_taffy.algorithms.compareseries import ComparisonSeriesAlgorithm
from logging import debug, warning, info
from rich import print

if TYPE_CHECKING:
    from traffic_taffy.report import Report
    from pandas import DataFrame
    from numpy import ndarray


class CompareCorrelation(ComparisonSeriesAlgorithm):
    """Compare series using the pandas correlation."""

    MAX_PIVOT = 1000

    def __init__(
        self,
        timestamps: List[int] | None = None,
        match_string: str | None = None,
        match_value: str | None = None,
        minimum_count: int | None = None,
        make_printable: bool = False,
        method: str = "spearman",
    ):
        """Create a CompareCorrelation instance.

        Valid methods: kendall, pearson, spearman, corrcoef

        speed-wise; pearson < spearman < corrcoef < kendall

        accuracy-wise:
            corrcoef: not great (uses numpy.corrcoef)
            pearson: better but, not good
            spearman: best
            kendall: best
        """
        super().__init__(
            timestamps, match_string, match_value, minimum_count, make_printable
        )
        self.method = method

    def compare_series(
        self, df: DataFrame, indexes: ndarray | None = None
    ) -> List[Report]:
        """Compare a bunch of series using correlation.

        This tries to do a comparison in a faster path if the number
        of keys are reasonable (for if not a pivot will consume all
        available memory)
        """

        indexes = df["index"].unique()
        num_indexes = len(indexes)
        if num_indexes > self.MAX_PIVOT:
            # we assume this is arbitrarily too large
            # use the slower parent version instead
            warning(
                f"too many indexes ({num_indexes} > {self.MAX_PIVOT}) == using slower routine to conserve memory"
            )
            return super().compare_series(df, indexes)

        info(f"Studying correlation of {num_indexes} indexes")

        df = df.set_index("time")
        for key in ["subkey", "index", "filename"]:
            del df[key]
        df = df.pivot(columns=["key"], values="count")
        df.fillna(0, inplace=True)

        # indexes have changed
        indexes = df.columns.to_list()

        # use pandas internal kendall
        # TODO(hardaker): numpy.corrcoef is multi-core but is pearsons
        # TODO(hardaker): scipy.stat.kendalltau is kendall,
        #                 but can only do one at a time

        # TODO(hardaker): df.corr() returns different numbers here
        # than inside compare_two_series!!

        if self.method == "corrcoef":
            np_array = df.to_numpy()
            results = numpy.corrcoef(np_array)
            for numx, column_left in enumerate(indexes):
                for numy, column_right in enumerate(indexes[numx + 1 :]):
                    value = results[numx][numy]
                    if value > 0.8:
                        print(
                            f"{column_left:<30} similar to {column_right:<30}: {value}"
                        )
            return []

        # default to using the datafram corr method instead
        results = df.corr(method=self.method)

        for num, column_left in enumerate(indexes):
            for column_right in indexes[num + 1 :]:
                if results[column_left][column_right] > 0.8:
                    print(
                        f"{column_left:<30} similar to {column_right:<30}: {results[column_left][column_right]}"
                    )
        return []

    def compare_two_series(
        self,
        column_left: str,
        series_left: list,
        column_right: str,
        series_right: list,
    ) -> dict:
        """Compare two series using the dataframe correlation algorithm."""
        debug(f"correlation comparing {column_left} and {column_right}")
        both = pd.concat([series_left, series_right], axis=1)
        both.fillna(0, inplace=True)

        # Note actually faster -- about the same as df.corr
        # import scipy
        # results = scipy.stats.kendalltau(both['left'], both['right'])
        # value = results.statistic

        results = both.corr(method=self.method)
        value = results["left"][1]
        if value > 0.8:
            # if results['left'][1] == 1.0:
            #     import pdb ; pdb.set_trace()
            print(f"{column_left:<30} similar to {column_right:<30}: {value}")
        else:
            debug(
                f"{column_left} not similar to {column_right} with correlation {value}"
            )
