from __future__ import annotations

import pytest

from aws_ssm_param_drift.baseline import BaselineError, parse_baseline


def test_parses_the_shipped_fixture(baseline):
    assert baseline.path == "/prod"
    assert baseline.ignore_paths == ["/prod/tmp/"]
    assert len(baseline.entries) == 7

    entry = baseline.by_name()["/prod/api/db-password"]
    assert entry.type == "SecureString"
    assert entry.key_id == "alias/prod-app"
    assert entry.rotating is True
    assert entry.max_age_days == 90


def test_yaml_ints_become_strings():
    b = parse_baseline("parameters:\n  - name: /a/b\n    value: 30\n")
    assert b.by_name()["/a/b"].value == "30"


def test_pattern_is_compiled_once_and_usable():
    b = parse_baseline("parameters:\n  - name: /a/b\n    pattern: '^https://'\n")
    entry = b.by_name()["/a/b"]
    assert entry.matches_pattern("https://x") is True
    assert entry.matches_pattern("http://x") is False


@pytest.mark.parametrize(
    "text,fragment",
    [
        ("", "empty"),
        ("- a\n- b\n", "mapping at the top level"),
        ("path: /prod\n", "no 'parameters' list"),
        ("parameters: {}\n", "must be a list"),
        ("parameters:\n  - {}\n", "'name' is required"),
        ("parameters:\n  - name: /a\n    type: Secret\n", "not one of"),
        ("parameters:\n  - name: /a\n    tier: Gold\n", "not one of"),
        ("parameters:\n  - name: /a\n    pattern: '['\n", "not a valid regex"),
        ("parameters:\n  - name: /a\n    nope: 1\n", "unknown key"),
        ("parameters:\n  - name: /a\n  - name: /a\n", "declared twice"),
        ("parameters:\n  - name: /a\n    rotating: sometimes\n", "expected true/false"),
        ("parameters: [{name: /a, max_age_days: soon}]\n", "must be a number"),
        ("parameters: []\nignore_paths: 7\n", "list of strings"),
        ("parameters: []\npath: 7\n", "'path' must be a string"),
        ("parameters: [\n", "not valid YAML"),
    ],
)
def test_rejects_bad_baselines(text, fragment):
    with pytest.raises(BaselineError) as err:
        parse_baseline(text)
    assert fragment in str(err.value)
