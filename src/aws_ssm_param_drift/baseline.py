"""Parse and validate the YAML baseline."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .model import PARAMETER_TYPES, TIERS


class BaselineError(ValueError):
    """The baseline file is unusable. Raised with a message meant for the terminal."""


@dataclass
class BaselineEntry:
    name: str
    type: str | None = None
    tier: str | None = None
    key_id: str | None = None
    value: str | None = None
    pattern: str | None = None
    rotating: bool = False
    max_age_days: float | None = None

    _compiled: re.Pattern | None = field(default=None, repr=False, compare=False)

    def matches_pattern(self, value: str) -> bool:
        if self._compiled is None:
            raise BaselineError(f"{self.name}: pattern checked but never compiled")
        return self._compiled.search(value) is not None


@dataclass
class Baseline:
    path: str | None = None
    entries: list[BaselineEntry] = field(default_factory=list)
    ignore_paths: list[str] = field(default_factory=list)

    def by_name(self) -> dict[str, BaselineEntry]:
        return {e.name: e for e in self.entries}


def _as_bool(raw, where: str) -> bool:
    if isinstance(raw, bool):
        return raw
    raise BaselineError(f"{where}: expected true/false, got {raw!r}")


def _parse_entry(raw, index: int) -> BaselineEntry:
    if not isinstance(raw, dict):
        raise BaselineError(f"parameters[{index}]: expected a mapping, got {type(raw).__name__}")
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise BaselineError(f"parameters[{index}]: 'name' is required and must be a non-empty string")
    name = name.strip()

    ptype = raw.get("type")
    if ptype is not None:
        if ptype not in PARAMETER_TYPES:
            raise BaselineError(f"{name}: type {ptype!r} is not one of {', '.join(PARAMETER_TYPES)}")

    tier = raw.get("tier")
    if tier is not None and tier not in TIERS:
        raise BaselineError(f"{name}: tier {tier!r} is not one of {', '.join(TIERS)}")

    value = raw.get("value")
    if value is not None and not isinstance(value, str):
        # YAML happily turns 30 into an int; parameters are always strings in SSM.
        value = str(value)

    pattern = raw.get("pattern")
    compiled = None
    if pattern is not None:
        if not isinstance(pattern, str):
            raise BaselineError(f"{name}: pattern must be a string")
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise BaselineError(f"{name}: pattern is not a valid regex ({exc})") from exc

    max_age = raw.get("max_age_days")
    if max_age is not None:
        try:
            max_age = float(max_age)
        except (TypeError, ValueError) as exc:
            raise BaselineError(f"{name}: max_age_days must be a number") from exc

    unknown = set(raw) - {
        "name",
        "type",
        "tier",
        "key_id",
        "value",
        "pattern",
        "rotating",
        "max_age_days",
    }
    if unknown:
        raise BaselineError(f"{name}: unknown key(s) {', '.join(sorted(unknown))}")

    return BaselineEntry(
        name=name,
        type=ptype,
        tier=tier,
        key_id=raw.get("key_id"),
        value=value,
        pattern=pattern,
        rotating=_as_bool(raw.get("rotating", False), f"{name}.rotating"),
        max_age_days=max_age,
        _compiled=compiled,
    )


def parse_baseline(text: str) -> Baseline:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise BaselineError(f"baseline is not valid YAML: {exc}") from exc

    if doc is None:
        raise BaselineError("baseline is empty")
    if not isinstance(doc, dict):
        raise BaselineError(f"baseline must be a mapping at the top level, got {type(doc).__name__}")

    raw_entries = doc.get("parameters")
    if raw_entries is None:
        raise BaselineError("baseline has no 'parameters' list")
    if not isinstance(raw_entries, list):
        raise BaselineError("'parameters' must be a list")

    entries = [_parse_entry(raw, i) for i, raw in enumerate(raw_entries)]

    seen: set[str] = set()
    for entry in entries:
        if entry.name in seen:
            raise BaselineError(f"{entry.name}: declared twice in the baseline")
        seen.add(entry.name)

    ignore_paths = doc.get("ignore_paths") or []
    if not isinstance(ignore_paths, list) or any(not isinstance(p, str) for p in ignore_paths):
        raise BaselineError("'ignore_paths' must be a list of strings")

    path = doc.get("path")
    if path is not None and not isinstance(path, str):
        raise BaselineError("'path' must be a string")

    return Baseline(path=path, entries=entries, ignore_paths=list(ignore_paths))


def load_baseline(path: str | Path) -> Baseline:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {p}: {exc}") from exc
    return parse_baseline(text)
