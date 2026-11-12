"""Write a starter baseline from the live parameters, or extend an existing one.

The generated entries describe the account as it is: ``name``, ``type``, ``tier``, and
for SecureStrings ``key_id`` plus ``rotating: true``. They never carry a ``value``. A
baseline is committed to a repository, and a starter file full of live secrets would be
the leak this tool exists to prevent.

``--merge`` goes through ruamel.yaml's round-trip mode so the comments, key order and
quoting a person put into the file survive. Only entries for undeclared parameters are
appended; existing entries are not touched, even when they disagree with the account,
because that disagreement is exactly what the audit run is supposed to report.
"""

from __future__ import annotations

import io
import re
from dataclasses import dataclass

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.error import YAMLError

from .baseline import BaselineError, parse_baseline
from .model import LiveParameter

HEADER = (
    "Starter baseline written by aws-ssm-param-drift init.\n"
    "Review it before committing: tighten type and key_id where the account is wrong,\n"
    "add pattern or value where they matter, and drop rotating where nothing rotates."
)


@dataclass
class InitResult:
    text: str
    added: list[str]
    kept: int


def _yaml() -> YAML:
    y = YAML(typ="rt")
    y.indent(mapping=2, sequence=4, offset=2)
    y.width = 4096  # long ARNs in key_id stay on one line
    y.preserve_quotes = True
    return y


#: A blank line between two ``- name:`` items, which is how the examples space entries out.
_SPACED_ENTRIES = re.compile(r"\n[ \t]*\n[ \t]*- name:")


def _append(params: CommentedSeq, entry: CommentedMap, *, spaced: bool) -> None:
    params.append(entry)
    if spaced and len(params) > 1:
        params.yaml_set_comment_before_after_key(len(params) - 1, before="\n")


def _under_any(name: str, prefixes: list[str]) -> bool:
    return any(name == p or name.startswith(p) for p in prefixes)


def entry_for(live: LiveParameter) -> CommentedMap:
    """One baseline entry describing ``live``. Never includes the value."""
    entry = CommentedMap()
    entry["name"] = live.name
    entry["type"] = live.type
    if live.tier:
        entry["tier"] = live.tier
    if live.type == "SecureString":
        if live.key_id:
            entry["key_id"] = live.key_id
        entry["rotating"] = True
    return entry


def select(
    live_params: list[LiveParameter],
    *,
    path: str | None,
    ignore_paths: list[str],
    declared: set[str],
) -> list[LiveParameter]:
    """Live parameters under ``path`` that no baseline entry claims, sorted by name."""
    out = []
    for p in live_params:
        if p.name in declared:
            continue
        if path and not p.name.startswith(path):
            continue
        if _under_any(p.name, ignore_paths):
            continue
        out.append(p)
    return sorted(out, key=lambda p: p.name)


def _dump(y: YAML, doc) -> str:
    buf = io.StringIO()
    y.dump(doc, buf)
    return buf.getvalue()


def generate(
    live_params: list[LiveParameter], *, path: str | None, ignore_paths: list[str] | None = None
) -> InitResult:
    """A fresh baseline with one entry per live parameter under ``path``."""
    ignore = list(ignore_paths or [])
    chosen = select(live_params, path=path, ignore_paths=ignore, declared=set())

    doc = CommentedMap()
    if path:
        doc["path"] = path
    if ignore:
        doc["ignore_paths"] = CommentedSeq(ignore)
    params = CommentedSeq()
    for p in chosen:
        _append(params, entry_for(p), spaced=True)
    doc["parameters"] = params
    if not chosen:
        params.fa.set_flow_style()
    doc.yaml_set_start_comment(HEADER)

    text = _dump(_yaml(), doc)
    parse_baseline(text)  # the output must load as a baseline; fail here, not in the next run
    return InitResult(text=text, added=[p.name for p in chosen], kept=0)


def merge(
    existing_text: str,
    live_params: list[LiveParameter],
    *,
    path: str | None = None,
    ignore_paths: list[str] | None = None,
) -> InitResult:
    """``existing_text`` with entries appended for every undeclared live parameter.

    ``path`` defaults to the baseline's own ``path``; its ``ignore_paths`` apply on top of
    ``ignore_paths``, the same way they do during an audit.
    """
    baseline = parse_baseline(existing_text)
    audit_path = path or baseline.path
    ignore = list(baseline.ignore_paths) + list(ignore_paths or [])
    chosen = select(
        live_params,
        path=audit_path,
        ignore_paths=ignore,
        declared={e.name for e in baseline.entries},
    )

    if not chosen:
        return InitResult(text=existing_text, added=[], kept=len(baseline.entries))

    y = _yaml()
    try:
        doc = y.load(existing_text)
    except YAMLError as exc:  # pragma: no cover - parse_baseline above already rejected it
        raise BaselineError(f"baseline is not valid YAML: {exc}") from exc

    params = doc["parameters"]
    if params.fa.flow_style():
        # `parameters: []` in flow style would grow into one long line.
        params.fa.set_block_style()
    spaced = _SPACED_ENTRIES.search(existing_text) is not None
    for p in chosen:
        _append(params, entry_for(p), spaced=spaced)

    text = _dump(y, doc)
    parse_baseline(text)
    return InitResult(text=text, added=[p.name for p in chosen], kept=len(baseline.entries))
