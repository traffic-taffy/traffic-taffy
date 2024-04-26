from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


class ComparisonAlgorithm:
    def __init__(self):
        pass

    def compare_two_dissections(left_side: dict, right_side: dict) -> dict:
        raise ValueError(
            "code failure: base class compare_two_dissections should never be called"
        )
