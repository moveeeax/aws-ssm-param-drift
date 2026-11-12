from __future__ import annotations

import json
import sys

import pytest

from aws_ssm_param_drift.baseline import BaselineError, parse_baseline
from aws_ssm_param_drift.cli import main
from aws_ssm_param_drift.collect import parameter_from_dict
from aws_ssm_param_drift.init import generate, merge
from aws_ssm_param_drift.rules import evaluate


def _names(text: str) -> list[str]:
    return [e.name for e in parse_baseline(text).entries]


def test_generate_writes_one_entry_per_live_parameter(live):
    result = generate(live, path="/prod")
    b = parse_baseline(result.text)
    assert b.path == "/prod"
    assert len(b.entries) == 8
    assert result.added == sorted(p.name for p in live)


def test_generate_never_writes_values(live):
    text = generate(live, path="/prod").text
    assert "value:" not in text
    for p in live:
        if p.value:
            assert p.value not in text


def test_decrypted_securestring_value_stays_out():
    secret = parameter_from_dict(
        {
            "Name": "/x/db-password",
            "Type": "SecureString",
            "KeyId": "alias/x-app",
            "Value": "hunter2",
            "Decrypted": True,
        }
    )
    text = generate([secret], path="/x").text
    assert "hunter2" not in text


def test_securestrings_get_key_id_and_rotating(live):
    entries = parse_baseline(generate(live, path="/prod").text).by_name()
    signing = entries["/prod/api/signing-key"]
    assert signing.type == "SecureString"
    assert signing.key_id == "alias/aws/ssm"
    assert signing.rotating is True

    plain = entries["/prod/api/timeout"]
    assert plain.type == "String"
    assert plain.tier == "Standard"
    assert plain.key_id is None
    assert plain.rotating is False


def test_missing_tier_is_omitted_rather_than_guessed():
    p = parameter_from_dict({"Name": "/x/a", "Type": "String", "Value": "1"})
    assert parse_baseline(generate([p], path="/x").text).entries[0].tier is None


def test_generate_respects_path_and_ignore_paths(live):
    result = generate(live, path="/prod/api", ignore_paths=["/prod/api/feature-flags"])
    assert _names(result.text) == [
        "/prod/api/db-password",
        "/prod/api/endpoint",
        "/prod/api/signing-key",
        "/prod/api/timeout",
    ]
    assert parse_baseline(result.text).ignore_paths == ["/prod/api/feature-flags"]


def test_generated_baseline_has_no_undeclared_or_missing(live, now):
    baseline = parse_baseline(generate(live, path="/prod").text)
    findings = evaluate(baseline, live, audit_path="/prod", now=now)
    assert [f for f in findings if f.rule in ("undeclared", "missing")] == []


def test_generate_with_nothing_live_is_still_a_valid_baseline():
    b = parse_baseline(generate([], path="/empty").text)
    assert b.entries == []


def test_merge_adds_only_undeclared_and_keeps_comments(baseline_path, live):
    original = baseline_path.read_text()
    result = merge(original, live)

    # /prod/tmp/ is in the baseline's ignore_paths, so only the legacy DSN is new.
    assert result.added == ["/prod/legacy/reporting-dsn"]
    assert result.kept == 7
    assert result.text.startswith(original.rstrip("\n"))
    assert "# Baseline for the prod API service." in result.text
    assert 'value: "30"' in result.text  # quoting style preserved

    entries = parse_baseline(result.text).by_name()
    assert entries["/prod/legacy/reporting-dsn"].type == "String"
    # Existing entries are not rewritten to match the account.
    assert entries["/prod/api/db-password"].type == "SecureString"
    assert entries["/prod/api/feature-flags"].tier == "Standard"


def test_merge_keeps_blank_lines_between_entries(baseline_path, live):
    text = merge(baseline_path.read_text(), live).text
    assert '    value: "8"\n\n  - name: /prod/legacy/reporting-dsn\n' in text


def test_merge_with_nothing_new_returns_the_file_unchanged(baseline_path, live):
    once = merge(baseline_path.read_text(), live).text
    twice = merge(once, live)
    assert twice.added == []
    assert twice.text == once


def test_merge_into_an_empty_flow_list():
    p = parameter_from_dict({"Name": "/x/a", "Type": "String", "Value": "1"})
    text = merge("path: /x\nparameters: []\n", [p]).text
    assert "parameters:\n  - name: /x/a\n" in text
    assert _names(text) == ["/x/a"]


def test_merge_rejects_an_invalid_baseline(live):
    with pytest.raises(BaselineError):
        merge("parameters:\n  - name: /a\n    type: Nope\n", live)


@pytest.fixture
def run_init(dump_path, capsys):
    def _run(*extra):
        code = main(["init", "--from-json", str(dump_path), *extra])
        out = capsys.readouterr()
        return code, out.out, out.err

    return _run


def test_cli_init_prints_a_baseline(run_init):
    code, out, err = run_init("--path", "/prod")
    assert code == 0
    assert len(parse_baseline(out).entries) == 8
    assert "wrote 8 entr(ies) for /prod" in err


def test_cli_init_merge_takes_path_from_the_baseline(run_init, baseline_path):
    code, out, err = run_init("--merge", str(baseline_path))
    assert code == 0
    assert _names(out)[-1] == "/prod/legacy/reporting-dsn"
    assert "added 1 undeclared parameter(s) to 7 existing entr(ies)" in err


def test_cli_init_merge_output_can_be_the_same_file(run_init, baseline_path, tmp_path):
    target = tmp_path / "params.prod.yml"
    target.write_text(baseline_path.read_text())
    code, out, _ = run_init("--merge", str(target), "--output", str(target))
    assert code == 0
    assert out == ""
    assert "/prod/legacy/reporting-dsn" in target.read_text()
    assert list(tmp_path.iterdir()) == [target]


def test_cli_init_refuses_stdout_redirected_onto_the_merge_file(dump_path, tmp_path, monkeypatch, capsys):
    # `init --merge b.yml >> b.yml` would append a second copy of the file to itself.
    target = tmp_path / "params.prod.yml"
    target.write_text("path: /prod\nparameters: []\n")
    with open(target, "a") as fh:
        monkeypatch.setattr(sys, "stdout", fh)
        code = main(["init", "--from-json", str(dump_path), "--merge", str(target)])
    assert code == 2
    assert "use --output" in capsys.readouterr().err
    assert target.read_text() == "path: /prod\nparameters: []\n"


def test_cli_init_without_path_or_dump_exits_2(capsys):
    assert main(["init"]) == 2
    assert "--path is required" in capsys.readouterr().err


def test_cli_init_with_an_unreadable_merge_file_exits_2(run_init, tmp_path):
    code, _, err = run_init("--merge", str(tmp_path / "nope.yml"))
    assert code == 2
    assert "cannot read baseline" in err


def test_cli_init_output_feeds_an_audit(run_init, tmp_path, dump_path, capsys):
    target = tmp_path / "b.yml"
    assert run_init("--path", "/prod", "-o", str(target))[0] == 0
    code = main(
        [
            "--baseline",
            str(target),
            "--from-json",
            str(dump_path),
            "--format",
            "json",
            "--fail-on",
            "undeclared,missing",
        ]
    )
    assert code == 0
    assert json.loads(capsys.readouterr().out)["summary"]["parameters_declared"] == 8
