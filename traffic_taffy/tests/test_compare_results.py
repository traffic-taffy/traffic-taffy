from collections import Counter
from traffic_taffy.report import Report
from traffic_taffy.algorithms.statistical import ComparisonStatistical


def test_compare_statistical_algorithm():
    left_data = {0: {"src": Counter({"a": 5, "b": 10})}}  # total = 15
    right_data = {0: {"src": Counter({"a": 15, "c": 15})}}  # total = 30

    # this should be positive when right_data is larger
    expected = {
        "src": {
            "a": Report(
                total=20,
                left_count=5,
                right_count=15,
                delta_absolute=15 - 5,
                left_percentage=5.0 / 15.0,
                right_percentage=15.0 / 30.0,
                delta_percentage=15.0 / 30.0 - 5.0 / 15.0,
            ),
            "b": Report(
                total=-10,  # only in 1
                left_count=10,
                right_count=0,
                delta_absolute=0 - 10,
                left_percentage=10.0 / 15.0,
                right_percentage=0.0,
                delta_percentage=-1.0,
            ),
            "c": Report(
                total=15,  # only in 2
                left_count=0,
                right_count=15,
                delta_absolute=15 - 0,
                left_percentage=0.0,
                right_percentage=15.0 / 30.0,
                delta_percentage=1.0,
            ),
            "__NEW_VALUES__": Report(
                total=2,  # 1 on each side
                left_count=1,  # b
                right_count=1,  # c
                delta_absolute=1 - 1,
                left_percentage=1.0 / 15.0,  # TODO: nuke this
                right_percentage=1.0 / 30.0,  # TODO: nuke this
                delta_percentage=1.0 / 30.0 - 1.0 / 15.0,
            ),
        }
    }

    algorithm = ComparisonStatistical()  # bogus file names
    report = algorithm.compare_dissections(left_data[0], right_data[0])

    assert report.contents == expected
