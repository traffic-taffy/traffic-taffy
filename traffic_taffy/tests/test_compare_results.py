from collections import Counter
from traffic_taffy.compare import PcapCompare


def test_compare_results():
    test_data1 = {0: {"src": Counter({"a": 5, "b": 10})}}  # total = 15
    test_data2 = {0: {"src": Counter({"a": 15, "c": 15})}}  # total = 30

    # this should be positive when test_data2 is larger
    expected = {
        "src": {
            "a": {
                "delta": 15.0 / 30.0 - 5.0 / 15.0,
                "total": 20,
                "left_count": 5,
                "right_count": 15,
            },
            "b": {
                "delta": -1.0,
                "total": 10,  # only in 1
                "left_count": 10,
                "right_count": 0,
            },
            "c": {
                "delta": 1.0,
                "total": 15,  # only in 2
                "left_count": 0,
                "right_count": 15,
            },
        }
    }

    pc = PcapCompare([1, 2])  # bogus files
    report = pc.compare_dissections(test_data1[0], test_data2[0])

    assert report == expected
