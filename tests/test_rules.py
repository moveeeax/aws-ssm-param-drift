from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aws_ssm_param_drift.baseline import parse_baseline
from aws_ssm_param_drift.model import LiveParameter, digest
from aws_ssm_param_drift.rules import RuleError, evaluate, validate_rule_names


def rules_for(findings, name):
    return sorted(f.rule for f in findings if f.parameter == name)


def by_rule(findings, rule):
    return [f for f in findings if f.rule == rule]


def test_full_fixture_produces_the_expected_finding_set(baseline, live, now):
    findings = evaluate(baseline, live, audit_path="/prod", now=now)
    got = sorted((f.parameter, f.rule) for f in findings)
    assert got == sorted(
        [
            ("/prod/api/db-password", "type-mismatch"),
            ("/prod/api/db-password", "stale"),
            ("/prod/api/endpoint", "pattern-mismatch"),
            ("/prod/api/feature-flags", "tier-mismatch"),
            ("/prod/api/signing-key", "default-kms-key"),
            ("/prod/api/signing-key", "value-unverifiable"),
            ("/prod/api/timeout", "value-drift"),
            ("/prod/legacy/reporting-dsn", "undeclared"),
            ("/prod/worker/concurrency", "missing"),
        ]
    )


def test_clean_parameter_produces_nothing(baseline, live, now):
    findings = evaluate(baseline, live, audit_path="/prod", now=now)
    assert rules_for(findings, "/prod/worker/queue-url") == []


def test_missing_and_undeclared_are_symmetric(baseline, live, now):
    findings = evaluate(baseline, live, audit_path="/prod", now=now)
    assert by_rule(findings, "missing")[0].parameter == "/prod/worker/concurrency"
    assert by_rule(findings, "undeclared")[0].parameter == "/prod/legacy/reporting-dsn"


def test_ignore_path_suppresses_both_sides(baseline, live, now):
    findings = evaluate(
        baseline, live, audit_path="/prod", ignore_paths=["/prod/legacy/"], now=now
    )
    assert by_rule(findings, "undeclared") == []


def test_tmp_path_from_the_baseline_is_already_ignored(baseline, live, now):
    findings = evaluate(baseline, live, audit_path="/prod", now=now)
    assert all("/prod/tmp/" not in f.parameter for f in findings)


def test_securestring_declared_but_live_string_is_high_and_leaks_nothing(baseline, live, now):
    findings = evaluate(baseline, live, audit_path="/prod", now=now)
    f = [x for x in by_rule(findings, "type-mismatch") if x.parameter == "/prod/api/db-password"][0]
    assert f.severity == "high"
    assert "plaintext" in f.message
    blob = " ".join(filter(None, [f.message, f.expected, f.actual]))
    assert "hunter2-but-in-production" not in blob


def test_undecryptable_securestring_is_unverifiable_not_clean(baseline, live, now):
    findings = evaluate(baseline, live, audit_path="/prod", now=now)
    f = by_rule(findings, "value-unverifiable")[0]
    assert f.parameter == "/prod/api/signing-key"
    assert f.extra["status"] == "unverifiable"
    assert f.extra["version"] == 7
    assert by_rule(findings, "value-drift") == [] or all(
        x.parameter != "/prod/api/signing-key" for x in by_rule(findings, "value-drift")
    )


def test_decrypted_securestring_is_compared_normally():
    b = parse_baseline("parameters:\n  - name: /a/k\n    type: SecureString\n    value: expected\n")
    live = [LiveParameter(name="/a/k", type="SecureString", value="actual", decrypted=True)]
    findings = evaluate(b, live, audit_path="/a")
    assert [f.rule for f in findings] == ["value-drift"]
    assert findings[0].extra["status"] == "drift"


def test_value_drift_reports_hashes_by_default(baseline, live, now):
    findings = evaluate(baseline, live, audit_path="/prod", now=now)
    f = by_rule(findings, "value-drift")[0]
    assert f.expected == digest("30")
    assert f.actual == digest("45")
    assert f.expected.startswith("sha256:")


def test_show_values_opts_into_plaintext(baseline, live, now):
    findings = evaluate(baseline, live, audit_path="/prod", show_values=True, now=now)
    f = by_rule(findings, "value-drift")[0]
    assert (f.expected, f.actual) == ("30", "45")


def test_default_kms_key_only_fires_when_a_cmk_was_asked_for():
    yaml_cmk = "parameters:\n  - name: /a/k\n    type: SecureString\n    key_id: alias/mine\n"
    yaml_nokey = "parameters:\n  - name: /a/k\n    type: SecureString\n"
    live = [LiveParameter(name="/a/k", type="SecureString", key_id="alias/aws/ssm", decrypted=False)]
    assert [f.rule for f in evaluate(parse_baseline(yaml_cmk), live, audit_path="/a")] == ["default-kms-key"]
    assert evaluate(parse_baseline(yaml_nokey), live, audit_path="/a") == []


def test_default_kms_key_ignores_non_securestrings():
    b = parse_baseline("parameters:\n  - name: /a/k\n    key_id: alias/mine\n")
    live = [LiveParameter(name="/a/k", type="String", key_id="alias/aws/ssm")]
    assert evaluate(b, live, audit_path="/a") == []


def test_tier_mismatch_flags_the_expensive_direction(baseline, live, now):
    findings = evaluate(baseline, live, audit_path="/prod", now=now)
    f = by_rule(findings, "tier-mismatch")[0]
    assert (f.expected, f.actual) == ("Standard", "Advanced")
    assert "billed" in f.message


def test_pattern_mismatch_needs_a_readable_value():
    b = parse_baseline("parameters:\n  - name: /a/k\n    type: SecureString\n    pattern: '^https://'\n")
    hidden = [LiveParameter(name="/a/k", type="SecureString", value=None, decrypted=False)]
    assert evaluate(b, hidden, audit_path="/a") == []


@pytest.mark.parametrize(
    "modified,limit,expected",
    [
        (datetime(2026, 1, 1, tzinfo=UTC), 90, ["stale"]),
        (datetime(2026, 10, 1, tzinfo=UTC), 90, []),
        (None, 90, []),
    ],
)
def test_stale_respects_the_age_limit(modified, limit, expected, now):
    b = parse_baseline(f"parameters:\n  - name: /a/k\n    rotating: true\n    max_age_days: {limit}\n")
    live = [LiveParameter(name="/a/k", type="String", last_modified=modified)]
    assert [f.rule for f in evaluate(b, live, audit_path="/a", now=now)] == expected


def test_stale_never_fires_without_rotating(now):
    b = parse_baseline("parameters:\n  - name: /a/k\n")
    old = datetime(2020, 1, 1, tzinfo=UTC)
    live = [LiveParameter(name="/a/k", type="String", last_modified=old)]
    assert evaluate(b, live, audit_path="/a", max_age_days=1, now=now) == []


def test_cli_max_age_is_the_fallback_limit(now):
    b = parse_baseline("parameters:\n  - name: /a/k\n    rotating: true\n")
    recent = datetime(2026, 9, 1, tzinfo=UTC)
    live = [LiveParameter(name="/a/k", type="String", last_modified=recent)]
    assert evaluate(b, live, audit_path="/a", now=now) == []
    assert [f.rule for f in evaluate(b, live, audit_path="/a", max_age_days=10, now=now)] == ["stale"]


def test_ignore_rule_drops_a_rule_everywhere(baseline, live, now):
    findings = evaluate(baseline, live, audit_path="/prod", ignore_rules=["undeclared", "stale"], now=now)
    assert {f.rule for f in findings}.isdisjoint({"undeclared", "stale"})


def test_severity_floor_filters(baseline, live, now):
    high = evaluate(baseline, live, audit_path="/prod", min_severity="high", now=now)
    assert {f.severity for f in high} == {"high"}
    assert {f.rule for f in high} == {"type-mismatch", "default-kms-key", "missing"}


def test_audit_path_scopes_undeclared_parameters(baseline, live, now):
    findings = evaluate(baseline, live, audit_path="/prod/api", now=now)
    assert by_rule(findings, "undeclared") == []


def test_findings_are_sorted_by_parameter_then_severity(baseline, live, now):
    findings = evaluate(baseline, live, audit_path="/prod", now=now)
    names = [f.parameter for f in findings]
    assert names == sorted(names)
    pw = [f.severity for f in findings if f.parameter == "/prod/api/db-password"]
    assert pw == ["high", "low"]


def test_validate_rule_names_rejects_typos():
    assert validate_rule_names(["missing", "stale"]) == ["missing", "stale"]
    with pytest.raises(RuleError) as err:
        validate_rule_names(["missing", "mising"])
    assert "mising" in str(err.value)
