from traffic_taffy.dissector import pcap_data_merge
from collections import defaultdict, Counter
from traffic_taffy.dissection import Dissection


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


def dissection_merge():
    d1 = Dissection("bogus")
    d2 = Dissection("bogus")

    data1 = {
        0: {
            "a": {1: 2, 3: 4},
            "b": {1: 4, 5: 6},
        },
        1: {
            "a": {1: 2, 3: 4},
        },
        2: {
            "a": {1: 2, 3: 4},
        },
    }
    data2 = {
        0: {
            "a": {1: 3, 3: 8},
            "b": {1: 4, 6: 7},
        },
        1: {
            "b": {1: 2, 3: 4},
        },
        3: {
            "a": {1: 2, 3: 4},
        },
    }
    expected = {
        0: {
            "a": {1: 5, 3: 12},
            "b": {1: 8, 5: 6, 6: 7},
        },
        1: {
            "a": {1: 2, 3: 4},
            "b": {1: 2, 3: 4},
        },
        2: {
            "a": {1: 2, 3: 4},
        },
        3: {
            "a": {1: 2, 3: 4},
        },
    }

    d1.data = data1
    d2.data = data2

    d1.merge(d2)

    result = d1.data
    assert result == expected
