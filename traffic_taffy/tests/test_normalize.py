from traffic_taffy.graph import PcapGraphData
from collections import Counter, defaultdict


class ParentFaker(PcapGraphData):
    def __init__(self):
        self.match_key = None
        self.match_value = None
        self.minimum_count = 0
        self.bin_size = 1

        super().__init__()


def test_pcap_normalize():
    pg = ParentFaker()
    data = {}

    # build a dictionary with [n][a][b] = 1 for every 2 spots
    # eg (n=0,2,4...)
    for i in range(0, 10, 2):
        data[i] = defaultdict(Counter)
        data[i]["a"]["b"] += 1

    # add entries for [n][c][d] = 1 for every 3 spots
    # eg (n=0,3,6,...)
    for i in range(0, 10, 3):
        if i not in data:
            data[i] = defaultdict(Counter)
        data[i]["c"]["d"] += 2

    results = pg.normalize_bins(data)

    # note: we only normalize non 0 indexes (ie, "real" timestamps)

    # note: the results aren't sorted by time; we sort to make
    # comparisons easier

    ret_index = ["a=b", "a=b", "a=b", "c=d", "a=b", "c=d", "c=d"]
    assert results == {
        "time": [2, 4, 6, 6, 8, 3, 9],
        "index": ret_index,
        "key": ret_index,
        "count": [1, 1, 1, 2, 1, 2, 2],
    }


def test_pcap_normalize_with_gaps():
    pg = ParentFaker()
    data = defaultdict(Counter)
    for i in range(14, 100, 7):
        data[i] = defaultdict(Counter)
        if i % 14 == 0:
            data[i]["a"]["b"] += 1
    for i in range(14, 100, 7):
        if i % 21 == 0:
            if i not in data:
                data[i] = defaultdict(Counter)
            data[i]["c"]["d"] += 1

    results = pg.normalize_bins(data)
    # TODO: sort these and ensure they're right (again)
    assert results == {
        "time": [14, 21, 28, 42, 42, 56, 63, 70, 84, 84, 98],
        "count": [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        "index": [
            "a=b",
            "c=d",
            "a=b",
            "a=b",
            "c=d",
            "a=b",
            "c=d",
            "a=b",
            "a=b",
            "c=d",
            "a=b",
        ],
        "key": [
            "a=b",
            "c=d",
            "a=b",
            "a=b",
            "c=d",
            "a=b",
            "c=d",
            "a=b",
            "a=b",
            "c=d",
            "a=b",
        ],
    }


def main():
    test_pcap_normalize()
    test_pcap_normalize_with_gaps()


if __name__ == "__main__":
    main()
