from typing import Dict


class Comparison:
    def __init__(self, contents: list, title: str = ""):
        self.contents = contents
        self.title: str = title
        self.printing_arguments: Dict[str] = {}

    # title
    @property
    def title(self) -> str:
        return self._title

    @title.setter
    def title(self, new_title):
        self._title = new_title

    # report contents -- actual data
    @property
    def contents(self):
        return self._contents

    @contents.setter
    def contents(self, new_contents):
        self._contents = new_contents
