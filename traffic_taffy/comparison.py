class Comparison:
    def __init__(self, contents: list, title: str = ""):
        self.contents = contents
        self.title = title
        self.console = None
        self.printing_arguments = {}

    # title
    @property
    def title(self):
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
