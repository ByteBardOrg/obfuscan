"""A pure-data utility module."""
from typing import Iterable

def average(values: Iterable[float]) -> float:
    values = list(values)
    if not values:
        return 0.0
    return sum(values) / len(values)

def normalize(values: Iterable[float]) -> list[float]:
    avg = average(values)
    return [v - avg for v in values]
