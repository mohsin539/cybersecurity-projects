"""In-memory test collectors (deterministic test doubles)."""

from __future__ import annotations


class FakeRegistry:
    def __init__(self, values: dict[tuple[str, str, str], object]) -> None:
        self._values = values

    def read_value(self, hive: str, path: str, value: str):
        return self._values.get((hive, path, value))


class FakeServices:
    def __init__(self, states: dict[str, str]) -> None:
        self._states = states

    def query(self, name: str) -> str:
        return self._states.get(name, "NotFound")


class FakeCommands:
    def __init__(self, outputs: dict[tuple[str, ...], str]) -> None:
        self._outputs = outputs

    def run(self, argv: list[str]) -> str:
        return self._outputs.get(tuple(argv), "")


class FakeAuditpol:
    def __init__(self, state: dict[str, dict[str, bool]]) -> None:
        self._state = state

    def subcategory(self, name: str) -> dict[str, bool]:
        return self._state.get(name, {"Success": False, "Failure": False})


class FakeDefender:
    def __init__(self, prefs: dict[str, str]) -> None:
        self._prefs = prefs

    def preference(self, name: str) -> str:
        return self._prefs.get(name, "")


class FakeSystem:
    def __init__(self, hostname: str = "TEST-HOST", os_caption: str = "Microsoft Windows 11 Enterprise (test)") -> None:
        self._host, self._os = hostname, os_caption

    def hostname(self) -> str:
        return self._host

    def os_caption(self) -> str:
        return self._os
