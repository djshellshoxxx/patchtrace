"""Shipped calibration runtime (calibration-corpus-and-model.md §7.2). Pure: no Qt, network, numpy or pickle.

No model artifact ships yet, so every display level is 'ordinal' (L0). Nothing here is a vulnerability
probability; the only target is A = "both endpoints are the same source-level function".
"""
from .policy import display_level

__all__ = ['display_level']
