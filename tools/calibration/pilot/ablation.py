"""Arm catalogue and leave-one-channel-out (LOCO) helpers."""
from __future__ import annotations

from collections.abc import Sequence

from patchtrace.pilot.contracts import CHANNELS

from .contracts import BASELINE_ARMS


def arm_names() -> tuple[str, ...]:
    return (*BASELINE_ARMS, 'P-adv', 'P-code', 'P-full', *(f'loco-{channel}' for channel in CHANNELS))


def drop_channel(channels: Sequence[str], channel: str) -> tuple[str, ...]:
    if channel not in channels:
        raise ValueError(f'unknown channel {channel!r}')
    return tuple(c for c in channels if c != channel)
