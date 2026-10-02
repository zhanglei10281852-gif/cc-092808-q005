from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol


def utc_now() -> datetime:
    return datetime.now(UTC)


def to_storage(value: datetime, *, timespec: str = "seconds") -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat(timespec=timespec)


def to_microseconds(value: datetime) -> str:
    """容器摆放时间：同一秒内可能连续移库/移交，需要微秒精度保证 (容器,时间) 唯一。"""
    return to_storage(value, timespec="microseconds")


def from_storage(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


class Clock(Protocol):
    def now(self) -> datetime: ...


@dataclass(slots=True)
class SystemClock:
    def now(self) -> datetime:
        return utc_now()


@dataclass(slots=True)
class FrozenClock:
    current: datetime

    def now(self) -> datetime:
        return self.current

    def advance(self, **values: int) -> datetime:
        self.current += timedelta(**values)
        return self.current
