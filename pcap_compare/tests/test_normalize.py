from unittest.mock import Mock
from pcap_compare.pcap_graph import PcapGraph
from collections import Counter, defaultdict


def test_pcap_normalize():
    pg = PcapGraph(Mock(), Mock(), bin_size=1)
    data = defaultdict(Counter)
    for i in range(0, 10, 2):
        data["a"][i] += 1
    for i in range(0, 10, 3):
        data["b"][i] += 1

    results = pg.normalize_bins(data)
    assert results == {
        "time": list(range(0, 9)),
        "a": [1, 0] * 4 + [1],
        "b": [1, 0, 0] * 3,
    }


def test_pcap_normalize_with_gaps():
    pg = PcapGraph(Mock(), Mock(), bin_size=7)
    data = defaultdict(Counter)
    for i in range(0, 100, 7):
        if i % 14 == 0:
            data["a"][i] += 1
    for i in range(0, 100, 7):
        if i % 21 == 0:
            data["b"][i] += 1

    results = pg.normalize_bins(data)
    assert results == {
        "time": list(range(0, 100, 7)),
        "a": [1, 0] * 7 + [1],
        "b": [1, 0, 0] * 5,
    }
