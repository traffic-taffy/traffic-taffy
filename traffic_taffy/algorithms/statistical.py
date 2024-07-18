from traffic_taffy.algorithms.compareslices import ComparisonSlicesAlgorithm
from traffic_taffy.comparison import Comparison
from traffic_taffy.dissection import Dissection
from traffic_taffy.reports.compareslicesreport import CompareSlicesReport


class ComparisonStatistical(ComparisonSlicesAlgorithm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def compare_two_dissections(self, left_side: dict, right_side: dict) -> Comparison:
        """Compare two dissections."""
        report = {}

        keys = set(left_side.keys())
        keys = keys.union(right_side.keys())
        for key in keys:
            report[key] = {}

            if key not in left_side:
                left_side[key] = {}
            left_side_total = sum(left_side[key].values())

            if key not in right_side:
                right_side[key] = {}
            right_side_total = sum(right_side[key].values())

            new_left_count = 0
            for subkey in left_side[key]:
                delta_percentage = 0.0
                total = 0
                if subkey in right_side[key]:
                    left_percentage = left_side[key][subkey] / left_side_total
                    right_percentage = right_side[key][subkey] / right_side_total
                    delta_percentage = right_percentage - left_percentage
                    total = right_side[key][subkey] + left_side[key][subkey]
                    left_count = left_side[key][subkey]
                    right_count = right_side[key][subkey]
                else:
                    delta_percentage = -1.0
                    left_percentage = left_side[key][subkey] / left_side_total
                    right_percentage = 0.0
                    total = -left_side[key][subkey]
                    left_count = left_side[key][subkey]
                    right_count = 0
                    new_left_count += 1

                delta_absolute = right_count - left_count
                report[key][subkey] = CompareSlicesReport(
                    delta_percentage=delta_percentage,
                    delta_absolute=delta_absolute,
                    total=total,
                    left_count=left_count,
                    right_count=right_count,
                    left_percentage=left_percentage,
                    right_percentage=right_percentage,
                )

            new_right_count = 0
            for subkey in right_side[key]:
                if subkey not in report[key]:
                    delta_percentage = 1.0
                    total = right_side[key][subkey]
                    left_count = 0
                    right_count = right_side[key][subkey]
                    left_percentage = 0.0
                    if right_side_total == 0:
                        right_percentage = 1.0
                    else:
                        right_percentage = right_side[key][subkey] / right_side_total
                    new_right_count += 1  # this value wasn't in the left

                    report[key][subkey] = CompareSlicesReport(
                        delta_percentage=delta_percentage,
                        delta_absolute=right_count,
                        total=total,
                        left_count=left_count,
                        right_count=right_count,
                        left_percentage=left_percentage,
                        right_percentage=right_percentage,
                    )

            if right_side_total == 0:
                right_percent = 1.0
            else:
                right_percent = new_right_count / right_side_total

            if left_side_total == 0:
                left_percent = 1.0
            else:
                left_percent = new_left_count / left_side_total

            report[key][Dissection.NEW_RIGHT_SUBKEY] = CompareSlicesReport(
                delta_absolute=new_right_count - new_left_count,
                total=new_left_count + new_right_count,
                left_count=new_left_count,
                right_count=new_right_count,
                left_percentage=left_percent,
                right_percentage=right_percent,
                delta_percentage=right_percent - left_percent,
            )

        return Comparison(report)
