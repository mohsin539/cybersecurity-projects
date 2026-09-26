"""Result[T, E] pattern: explicit error handling, domain never raises to the UI.

architecture.md section 5: "Result-style returns keep error handling explicit —
the UI never gets thrown exceptions from the domain."
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Generic, TypeVar

T = TypeVar("T")
E = TypeVar("E")
U = TypeVar("U")


@dataclass(frozen=True)
class Ok(Generic[T, E]):
    """Success case carrying a value."""

    value: T

    def is_ok(self) -> bool:
        return True

    def is_err(self) -> bool:
        return False

    def map(self, fn: Callable[[T], U]) -> "Result[U, E]":
        return Ok(fn(self.value))

    def unwrap(self) -> T:
        return self.value

    def unwrap_err(self) -> E:
        raise ValueError(f"unwrap_err() called on Ok({self.value!r})")


@dataclass(frozen=True)
class Err(Generic[T, E]):
    """Failure case carrying a human-readable error."""

    error: E

    def is_ok(self) -> bool:
        return False

    def is_err(self) -> bool:
        return True

    def map(self, fn: Callable[[T], U]) -> "Result[U, E]":
        return self  # type: ignore[return-value]

    def unwrap(self) -> T:
        raise ValueError(f"unwrap() called on Err({self.error!r})")

    def unwrap_err(self) -> E:
        return self.error


Result = Ok[T, E] | Err[T, E]


def ok(value: T) -> Ok[T, E]:  # type: ignore[valid-type]
    return Ok(value)


def err(error: E) -> Err[T, E]:  # type: ignore[valid-type]
    return Err(error)
