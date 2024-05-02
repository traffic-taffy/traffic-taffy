"""Compares datasets using DataFrame's correlation."""

from __future__ import annotations
import pandas as pd

from traffic_taffy.algorithms.compareseries import ComparisonSeriesAlgorithm
from logging import debug


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
        print(results)
