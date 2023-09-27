from collections import Counter
from pcap_compare import PcapCompare


def test_compare_results():
    test_data1 = {"src": Counter({"a": 5, "b": 10})}  # total = 15
    test_data2 = {"src": Counter({"a": 15, "c": 15})}  # total = 30

    expected = {
        "src": {
            "a": 5.0 / 15.0 - 15.0 / 30.0,
            "b": 10.0 / 15.0 - 0.0,
            "c": 0.0 - 15.0 / 30.0,
        }
    }

    pc = PcapCompare([1, 2])  # bogus files
    report = pc.compare_results(test_data1, test_data2)

    assert report == expected
