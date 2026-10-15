"""Core mathematical slider helpers for normalizing metrics to [0.0, 1.0] suspicion levels."""

from typing import Union

Number = Union[int, float]


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamps a numeric value between lo and hi."""
    return max(lo, min(float(x), hi))


def scale_up(value: Number, low: Number, high: Number) -> float:
    """0.0 at `low`, 1.0 at `high`, linear between, clamped. Higher value = more suspicious."""
    if low == high:
        raise ValueError(f"Invalid slider bounds: low ({low}) cannot equal high ({high})")
    return clamp((float(value) - float(low)) / (float(high) - float(low)))


def scale_down(value: Number, cutoff: Number, best: Number) -> float:
    """0.0 at `cutoff`, 1.0 at `best` (best < cutoff), linear between, clamped. Lower value = more suspicious."""
    if cutoff == best:
        raise ValueError(f"Invalid slider bounds: cutoff ({cutoff}) cannot equal best ({best})")
    return clamp((float(cutoff) - float(value)) / (float(cutoff) - float(best)))
