"""Render findings as a text table or as JSON."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import UTC, datetime

from .model import Finding, LiveParameter

SEVERITY_LABEL = {"high": "HIGH ", "medium": "MED  ", "low": "LOW  "}


def summarize(findings: list[Finding], live_params: list[LiveParameter], declared: int) -> dict:
    return {
        "findings": len(findings),
        "parameters_live": len(live_params),
        "parameters_declared": declared,
        "by_rule": dict(sorted(Counter(f.rule for f in findings).items())),
        "by_severity": dict(sorted(Counter(f.severity for f in findings).items())),
    }


def render_json(
    findings: list[Finding],
    live_params: list[LiveParameter],
    declared: int,
    *,
    audit_path: str | None,
    baseline_path: str | None,
) -> str:
    doc = {
        "generated_at": datetime.now(UTC).isoformat(),
        "path": audit_path,
        "baseline": baseline_path,
        "summary": summarize(findings, live_params, declared),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(doc, indent=2, sort_keys=False)


def render_text(
    findings: list[Finding],
    live_params: list[LiveParameter],
    declared: int,
    *,
    audit_path: str | None,
    baseline_path: str | None,
) -> str:
    lines: list[str] = []
    header = f"aws-ssm-param-drift  path={audit_path or '(all)'}"
    if baseline_path:
        header += f"  baseline={baseline_path}"
    lines.append(header)
    lines.append(f"{len(live_params)} live parameter(s), {declared} declared")
    lines.append("")

    if not findings:
        lines.append("No drift. The account matches the baseline.")
        return "\n".join(lines) + "\n"

    grouped: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        grouped[f.parameter].append(f)

    rule_width = max(len(f.rule) for f in findings)
    for name in sorted(grouped):
        lines.append(name)
        for f in grouped[name]:
            label = SEVERITY_LABEL.get(f.severity, f.severity.upper())
            lines.append(f"  {label} {f.rule.ljust(rule_width)}  {f.message}")
            if f.expected is not None and f.actual is not None:
                pad = " " * (len(label) + rule_width + 1)
                lines.append(f"  {pad}  expected {f.expected} != actual {f.actual}")
        lines.append("")

    counts = summarize(findings, live_params, declared)
    by_sev = counts["by_severity"]
    tail = ", ".join(f"{by_sev[s]} {s}" for s in ("high", "medium", "low") if s in by_sev)
    lines.append(f"{len(findings)} finding(s): {tail}")
    return "\n".join(lines) + "\n"
