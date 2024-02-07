"""A simple data storage module to hold comparison data."""

from __future__ import annotations
from typing import Dict, Any


class Comparison:
    """A simple data storage class to hold comparison data."""

    def __init__(self, contents: list, title: str = ""):
        """Create a Comparison class from contents."""
        self.contents = contents
        self.title: str = title
        self.printing_arguments: Dict[str, Any] = {}

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
    def contents(self) -> None:
        """The contents of this comparison."""
        return self._contents

    @contents.setter
    def contents(self, new_contents: str) -> None:
        self._contents = new_contents
