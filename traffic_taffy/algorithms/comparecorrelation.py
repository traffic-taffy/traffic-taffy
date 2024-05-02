"""Compares datasets using DataFrame's correlation."""

from __future__ import annotations
import pandas as pd

from traffic_taffy.algorithms.compareseries import ComparisonSeriesAlgorithm
from logging import debug
from rich import print


class CompareCorrelation(ComparisonSeriesAlgorithm):
    """Compare series using the pandas correlation."""

    def __init__(self):
        super().__init__()

    def compare_two_series(
        self,
        column_left: str,
        series_left: list,
        column_right: str,
        series_right: list,
    ) -> dict:
        debug(f"correlation comparing {column_left} and {column_right}")
        both = pd.concat([series_left, series_right], axis=1)
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
