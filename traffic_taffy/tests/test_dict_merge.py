from traffic_taffy.dissector import pcap_data_merge
from collections import defaultdict, Counter


def test_pcap_data_merge():
    d1 = defaultdict(Counter)
    d1["bogus"]["a"] = 3
    d1["bogus"]["b"] += 2

    d2 = defaultdict(Counter)
    d2["bogus"]["b"] = 5
    d2["bogus"]["c"] += 10

    d3 = pcap_data_merge(d1, d2)

    assert d3 == {
        "bogus": {
            "a": 3,
            "b": 7,
            "c": 10,
        }
    }
