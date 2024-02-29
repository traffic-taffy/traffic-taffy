from dataclasses import dataclass


@dataclass
class Report:
    delta_percentage: float
    delta_absolute: int
    total: int
    left_count: int
    right_count: int
    left_percentage: float
    right_percentage: float
