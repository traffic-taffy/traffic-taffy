"""Compares datasets in time-slices rather than by series."""

from __future__ import annotations
from typing import List, TYPE_CHECKING
from traffic_taffy.algorithms import ComparisonAlgorithm
import itertools
import datetime
import datetime as dt

from logging import debug, error, exception

if TYPE_CHECKING:
    from traffic_taffy.dissection import Dissection
    from traffic_taffy.report import Report


class ComparisonSlicesAlgorithm(ComparisonAlgorithm):
    """A base class for algorithms that compare left/right slices."""

    def __init__(self):
        """Create a ComparisonAlgorithm."""

    def compare_two_dissections(
        self, _left_side: Dissection, _right_side: Dissection
    ) -> dict:
        """Error catching base class function for comparing two alogirthms."""
        error("code failure: base class compare_two_dissections should never be called")
        raise ValueError

    def compare_dissections(self, dissections: List[Dissection]) -> List[Report]:
        """Compare all the dissections in slices."""
        reports = []
        # hack to figure out if there is at least two instances of a generator
        # without actually extracting them all
        # (since it could be memory expensive)

        reference = next(dissections)
        other = None
        multiple = True
        try:
            other = next(dissections)
            dissections = itertools.chain([other], dissections)
        except Exception:
            exception("failed to create a chain of dissections")
            multiple = False

        if multiple:
            # multiple file comparison
            for other in dissections:
                # compare the two global summaries

                report = self.compare_two_dissections(reference.data[0], other.data[0])
                report.title = f"{reference.pcap_file} vs {other.pcap_file}"

                reports.append(report)
        else:
            # deal with timestamps within a single file
            reference = reference.data
            timestamps = list(reference.keys())
            if len(timestamps) == 1:  # just 0-summary plus a single stamp
                error(
                    "the requested pcap data was not long enough to compare against itself"
                )
                errorstr: str = "not large enough pcap file"
                raise ValueError(errorstr)
            debug(
                f"found {len(timestamps)} timestamps from {timestamps[2]} to {timestamps[-1]}"
            )

            for timestamp in range(
                2, len(timestamps)
            ):  # second real non-zero timestamp to last
                time_left = timestamps[timestamp - 1]
                time_right = timestamps[timestamp]

                # see if we were asked to only use particular time ranges
                if self.between_times and (
                    time_left < self.between_times[0]
                    or time_right > self.between_times[1]
                ):
                    continue

                debug(f"comparing timestamps {time_left} and {time_right}")

                report = self.compare_two_dissections(
                    reference[time_left],
                    reference[time_right],
                )

                title_left = datetime.fromtimestamp(time_left, dt.UTC).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                title_right = datetime.fromtimestamp(time_right, dt.UTC).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                report.title = f"time {title_left} vs time {title_right}"
                reports.append(report)

                continue

                # takes way too much memory to do it "right"
                # reports.append(

        return reports
