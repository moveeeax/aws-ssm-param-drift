from __future__ import annotations

import json

import pytest

from aws_ssm_param_drift.cli import main


@pytest.fixture
def run(baseline_path, dump_path, capsys):
    def _run(*extra, baseline=True):
        argv = ["--from-json", str(dump_path)]
        if baseline:
            argv = ["--baseline", str(baseline_path)] + argv
        code = main(argv + list(extra))
        out = capsys.readouterr()
        return code, out.out, out.err

    return _run


def test_offline_run_needs_no_network_and_reports(run):
    code, out, _ = run()
    assert code == 0
    assert "aws-ssm-param-drift" in out
    assert "/prod/worker/concurrency" in out
    assert "missing" in out


def test_json_output_is_parsable_and_summarized(run):
    code, out, _ = run("--format", "json")
    assert code == 0
    doc = json.loads(out)
    assert doc["path"] == "/prod"
    assert doc["summary"]["findings"] == len(doc["findings"])
    assert doc["summary"]["parameters_live"] == 8
    assert doc["summary"]["parameters_declared"] == 7
    assert doc["summary"]["by_rule"]["undeclared"] == 1
    assert doc["summary"]["by_severity"]["high"] == 3


def test_undeclared_is_queryable_from_json(run):
    _, out, _ = run("--format", "json")
    undeclared = [f for f in json.loads(out)["findings"] if f["rule"] == "undeclared"]
    assert [f["parameter"] for f in undeclared] == ["/prod/legacy/reporting-dsn"]


def test_fail_on_a_firing_rule_exits_1(run):
    code, _, _ = run("--fail-on", "missing,type-mismatch,default-kms-key")
    assert code == 1


def test_fail_on_a_quiet_rule_exits_0(run):
    code, _, _ = run("--fail-on", "stale", "--ignore-rule", "stale")
    assert code == 0


def test_fail_on_an_unknown_rule_exits_2(run):
    code, _, err = run("--fail-on", "missing,not-a-rule")
    assert code == 2
    assert "unknown rule" in err


def test_ignore_rule_with_a_typo_exits_2(run):
    code, _, err = run("--ignore-rule", "mising")
    assert code == 2
    assert "Known rules" in err


def test_unreadable_baseline_exits_2(dump_path, tmp_path, capsys):
    bad = tmp_path / "bad.yml"
    bad.write_text("parameters:\n  - name: /a\n    type: Nope\n")
    code = main(["--baseline", str(bad), "--from-json", str(dump_path)])
    assert code == 2
    assert "not one of" in capsys.readouterr().err


def test_missing_baseline_argument_exits_2(capsys):
    assert main(["--path", "/prod"]) == 2
    assert "--baseline is required" in capsys.readouterr().err


def test_values_are_hashed_unless_asked_for(run):
    _, out, _ = run()
    assert "hunter2-but-in-production" not in out
    assert "sha256:" in out

    _, shown, _ = run("--show-values")
    assert "expected 30 != actual 45" in shown


def test_severity_filter_narrows_the_report(run):
    _, out, _ = run("--format", "json", "--severity", "high")
    doc = json.loads(out)
    assert {f["severity"] for f in doc["findings"]} == {"high"}


def test_ignore_path_removes_a_whole_subtree(run):
    _, out, _ = run("--format", "json", "--ignore-path", "/prod/legacy/")
    assert all(f["rule"] != "undeclared" for f in json.loads(out)["findings"])


def test_path_override_scopes_the_audit(run):
    _, out, _ = run("--format", "json", "--path", "/prod/api")
    doc = json.loads(out)
    assert doc["path"] == "/prod/api"
    assert all(f["rule"] != "undeclared" for f in doc["findings"])


def test_clean_run_says_so(tmp_path, capsys):
    baseline = tmp_path / "b.yml"
    baseline.write_text("path: /x\nparameters:\n  - name: /x/a\n    type: String\n    value: '1'\n")
    dump = tmp_path / "d.json"
    dump.write_text(json.dumps([{"Name": "/x/a", "Type": "String", "Value": "1"}]))
    code = main(["--baseline", str(baseline), "--from-json", str(dump)])
    assert code == 0
    assert "No drift" in capsys.readouterr().out


def test_dump_json_only_mode_writes_a_replayable_file(tmp_path, dump_path, capsys):
    out = tmp_path / "copy.json"
    code = main(["--from-json", str(dump_path), "--dump-json", str(out)])
    assert code == 0
    assert "wrote 8 parameter(s)" in capsys.readouterr().err
    assert len(json.loads(out.read_text())["parameters"]) == 8


def test_from_json_is_byte_for_byte_reproducible(run):
    first = run("--format", "json")[1]
    second = run("--format", "json")[1]
    drop = lambda s: "\n".join(ln for ln in s.splitlines() if "generated_at" not in ln)  # noqa: E731
    assert drop(first) == drop(second)
