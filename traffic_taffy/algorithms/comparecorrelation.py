"""Compares datasets using DataFrame's correlation."""

from __future__ import annotations
from typing import List
import pandas as pd

from traffic_taffy.algorithms.compareseries import ComparisonSeriesAlgorithm
from logging import debug
from rich import print


class CompareCorrelation(ComparisonSeriesAlgorithm):
    """Compare series using the pandas correlation."""

    def __init__(
        self,
        timestamps: List[int] | None = None,
        match_string: str | None = None,
        match_value: str | None = None,
        minimum_count: int | None = None,
        make_printable: bool = False,
    ):
        """Create a CompareCorrelation instance."""
        super().__init__(
            timestamps, match_string, match_value, minimum_count, make_printable
        )

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
        results = both.corr(method="kendall")
        if results["left"][1] > 0.8:
            # if results['left'][1] == 1.0:
            #     import pdb ; pdb.set_trace()
            print(
                f"{column_left:<30} similar to {column_right:<30}: {results['left'][1]}"
            )
            print(both)
        else:
            debug(
                f"{column_left} not similar to {column_right} with correlation {results['left'][1]}"
            )
