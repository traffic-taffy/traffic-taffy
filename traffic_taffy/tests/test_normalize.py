from unittest.mock import Mock
from traffic_taffy.graph import PcapGraph
from collections import Counter, defaultdict


def test_pcap_normalize():
    pg = PcapGraph(Mock(), Mock(), bin_size=1)
    data = {}
    for i in range(0, 10, 2):
        data[i] = defaultdict(Counter)
        data[i]["a"]["b"] += 1
    for i in range(0, 10, 3):
        if i not in data:
            data[i] = defaultdict(Counter)
        data[i]["c"]["d"] += 1

    results = pg.normalize_bins(data)
    assert results == {
        "time": list(range(2, 10)),
        "index": ["a=b"] * 8,
        "count": [1, 0] * 4,
    }


def test_pcap_normalize_with_gaps():
    pg = PcapGraph(Mock(), Mock(), bin_size=7)
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
    assert results == {
        "time": list(range(14, 100, 7)),
        "count": [1, 0] * 6 + [1],
        "index": ["a=b"] * 13,
    }
