"""The rule engine: baseline + live parameters in, findings out.

Pure functions over plain data. No AWS, no filesystem, no clock unless one is passed in.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .baseline import Baseline, BaselineEntry
from .model import Finding, LiveParameter, digest, is_aws_managed_key, severity_rank

RULES: dict[str, str] = {
    "missing": "high",
    "undeclared": "medium",
    "type-mismatch": "high",
    "value-drift": "medium",
    "value-unverifiable": "low",
    "pattern-mismatch": "medium",
    "tier-mismatch": "low",
    "default-kms-key": "high",
    "stale": "low",
}

ALL_RULES = tuple(RULES)


class RuleError(ValueError):
    """An unknown rule name was passed on the command line."""


def validate_rule_names(names: list[str]) -> list[str]:
    unknown = [n for n in names if n not in RULES]
    if unknown:
        raise RuleError(
            f"unknown rule(s): {', '.join(unknown)}. Known rules: {', '.join(ALL_RULES)}"
        )
    return names


def _under_any(name: str, prefixes: list[str]) -> bool:
    return any(name == p or name.startswith(p) for p in prefixes)


def _rendered(value: str, show_values: bool) -> str:
    return value if show_values else digest(value)


def _check_type(entry: BaselineEntry, live: LiveParameter) -> Finding | None:
    if entry.type is None or entry.type == live.type:
        return None
    message = f"declared {entry.type}, live {live.type}"
    if entry.type == "SecureString" and live.type == "String":
        message += " — the value is stored in plaintext and readable by anything with ssm:GetParameter"
    return Finding(
        parameter=live.name,
        rule="type-mismatch",
        severity=RULES["type-mismatch"],
        message=message,
        expected=entry.type,
        actual=live.type,
    )


def _check_value(entry: BaselineEntry, live: LiveParameter, show_values: bool) -> Finding | None:
    if entry.value is None:
        return None
    if not live.value_known:
        # SecureString without --decrypt: we genuinely cannot tell. Saying "clean" here
        # would be a lie, so the run reports it as its own finding instead.
        hint = f"version {live.version}" if live.version is not None else "version unknown"
        if live.last_modified is not None:
            hint += f", last modified {live.last_modified.date().isoformat()}"
        return Finding(
            parameter=live.name,
            rule="value-unverifiable",
            severity=RULES["value-unverifiable"],
            message=(
                f"baseline pins a value but {live.type} was not decrypted "
                f"({hint}); re-run with --decrypt"
            ),
            expected=_rendered(entry.value, show_values),
            actual=None,
            extra={"status": "unverifiable", "version": live.version},
        )
    if live.value == entry.value:
        return None
    return Finding(
        parameter=live.name,
        rule="value-drift",
        severity=RULES["value-drift"],
        message="live value differs from the baseline",
        expected=_rendered(entry.value, show_values),
        actual=_rendered(live.value, show_values),
        extra={"status": "drift"},
    )


def _check_pattern(entry: BaselineEntry, live: LiveParameter, show_values: bool) -> Finding | None:
    if entry.pattern is None or not live.value_known:
        return None
    if entry.matches_pattern(live.value or ""):
        return None
    return Finding(
        parameter=live.name,
        rule="pattern-mismatch",
        severity=RULES["pattern-mismatch"],
        message=f"live value does not match /{entry.pattern}/",
        expected=f"/{entry.pattern}/",
        actual=_rendered(live.value or "", show_values),
    )


def _check_tier(entry: BaselineEntry, live: LiveParameter) -> Finding | None:
    if entry.tier is None or live.tier is None or entry.tier == live.tier:
        return None
    note = ""
    if live.tier == "Advanced" and entry.tier != "Advanced":
        note = " — Advanced parameters are billed per parameter per month"
    return Finding(
        parameter=live.name,
        rule="tier-mismatch",
        severity=RULES["tier-mismatch"],
        message=f"declared tier {entry.tier}, live {live.tier}{note}",
        expected=entry.tier,
        actual=live.tier,
    )


def _check_kms(entry: BaselineEntry, live: LiveParameter) -> Finding | None:
    if live.type != "SecureString":
        return None
    if not entry.key_id or is_aws_managed_key(entry.key_id):
        return None
    if not is_aws_managed_key(live.key_id):
        return None
    return Finding(
        parameter=live.name,
        rule="default-kms-key",
        severity=RULES["default-kms-key"],
        message="encrypted with the AWS-managed alias/aws/ssm key, baseline asked for a customer-managed key",
        expected=entry.key_id,
        actual=live.key_id,
    )


def _check_stale(
    entry: BaselineEntry, live: LiveParameter, default_max_age: float | None, now: datetime
) -> Finding | None:
    if not entry.rotating:
        return None
    limit = entry.max_age_days if entry.max_age_days is not None else default_max_age
    if limit is None:
        return None
    age = live.age_days(now)
    if age is None or age <= limit:
        return None
    return Finding(
        parameter=live.name,
        rule="stale",
        severity=RULES["stale"],
        message=f"marked rotating but last modified {age:.0f} days ago (limit {limit:.0f})",
        expected=f"<= {limit:.0f}d",
        actual=f"{age:.0f}d",
    )


def evaluate(
    baseline: Baseline,
    live_params: list[LiveParameter],
    *,
    audit_path: str | None = None,
    ignore_paths: list[str] | None = None,
    ignore_rules: list[str] | None = None,
    max_age_days: float | None = None,
    show_values: bool = False,
    min_severity: str = "low",
    now: datetime | None = None,
) -> list[Finding]:
    now = now or datetime.now(UTC)
    ignored_paths = list(baseline.ignore_paths) + list(ignore_paths or [])
    ignored_rules = set(ignore_rules or [])

    live_by_name = {p.name: p for p in live_params}
    declared = baseline.by_name()
    findings: list[Finding] = []

    for name, entry in declared.items():
        if _under_any(name, ignored_paths):
            continue
        live = live_by_name.get(name)
        if live is None:
            findings.append(
                Finding(
                    parameter=name,
                    rule="missing",
                    severity=RULES["missing"],
                    message="declared in the baseline but absent from the account",
                    expected=entry.type or "present",
                    actual="absent",
                )
            )
            continue
        for candidate in (
            _check_type(entry, live),
            _check_value(entry, live, show_values),
            _check_pattern(entry, live, show_values),
            _check_tier(entry, live),
            _check_kms(entry, live),
            _check_stale(entry, live, max_age_days, now),
        ):
            if candidate is not None:
                findings.append(candidate)

    for live in live_params:
        if live.name in declared:
            continue
        if _under_any(live.name, ignored_paths):
            continue
        if audit_path and not live.name.startswith(audit_path):
            continue
        findings.append(
            Finding(
                parameter=live.name,
                rule="undeclared",
                severity=RULES["undeclared"],
                message=f"exists in the account ({live.type}) but no baseline entry claims it",
                expected="declared",
                actual="undeclared",
            )
        )

    floor = severity_rank(min_severity)
    findings = [
        f for f in findings if f.rule not in ignored_rules and severity_rank(f.severity) >= floor
    ]
    findings.sort(key=lambda f: (f.parameter, -severity_rank(f.severity), f.rule))
    return findings
