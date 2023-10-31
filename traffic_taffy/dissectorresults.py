from collections import defaultdict, Counter


class DefaultCounter(Counter):
    def __init__(self, *args, default_key: str = "total", **kargs):
        super().__init__(*args, **kargs)
        self.default_key = default_key

    def __iadd__(self, value):
        self[self.default_key] += value
        return self

    def __eq__(self, value):
        return self[self.default_key] == value


class DissectorResults(defaultdict):
    def __init__(self, has_delta: bool = False, default_key: str = "total"):
        super().__init__(lambda: defaultdict(DefaultCounter))
        self.has_delta = has_delta
        self.default_key = default_key
