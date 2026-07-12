from __future__ import annotations
import asyncio
from dataclasses import dataclass, field
from typing import Any


@dataclass
class APKState:
    path: str
    package: str
    apk: Any
    analysis: Any
    dex_count: int
    class_count: int
    native_libs: list[str]
    dynamic_load: list[str]
    _xref_built: bool = False
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


CURRENT: APKState | None = None


def set_current(state: APKState) -> None:
    global CURRENT
    CURRENT = state
