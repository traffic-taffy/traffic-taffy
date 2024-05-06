"""A simple data storage module to hold comparison data."""

from __future__ import annotations
from typing import Dict, Any

from traffic_taffy.reports import Report

# Organized reports are dicts containing a primary key that is being
# compared to (left hand side), and a secondary key that is the right
# hand thing being compared.  Each key/subkey combination should point
# to a Report containing the results of that comparison.
OrganizedReports = Dict[str, Dict[Any, Report]]


class Comparison:
    """A simple data storage class to hold comparison data."""

    def __init__(
        self,
        contents: OrganizedReports,
        title: str = "",
        sort_by: str = "delta_percentage",
    ):
        """Create a Comparison class from contents."""
        self.contents: OrganizedReports = contents
        self.title: str = title
        self.printing_arguments: Dict[str, Any] = {}
        self.sort_by = sort_by

    # title
    @property
    def title(self) -> str:
        """The title of this comparison."""
        return self._title

    @title.setter
    def title(self, new_title: str) -> None:
        self._title = new_title

    # report contents -- actual data
    @property
    def contents(self) -> OrganizedReports:
        """The contents of this comparison."""
        return self._contents

    @contents.setter
    def contents(self, new_contents: OrganizedReports) -> None:
        self._contents = new_contents
