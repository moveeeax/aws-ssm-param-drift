"""Command line entry point."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .baseline import Baseline, BaselineError, load_baseline
from .collect import CollectError, collect_live, dump_to_file, load_dump
from .model import SEVERITIES
from .report import render_json, render_text
from .rules import ALL_RULES, RuleError, evaluate, validate_rule_names

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-ssm-param-drift",
        description="Diff a YAML baseline of SSM parameters against the live account.",
        epilog="Rules: " + ", ".join(ALL_RULES),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--baseline", help="YAML baseline describing the parameters a service expects")
    p.add_argument("--path", help="SSM path prefix to audit (defaults to the baseline's 'path')")
    p.add_argument("--region", help="AWS region for live collection")
    p.add_argument("--from-json", dest="from_json", help="replay a cached dump instead of calling AWS")
    p.add_argument("--dump-json", dest="dump_json", help="write the collected parameters to this file")
    p.add_argument(
        "--decrypt", action="store_true", help="call SSM with WithDecryption so values can be compared"
    )
    p.add_argument(
        "--show-values", action="store_true", help="print real values instead of hashes (off by default)"
    )
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument(
        "--fail-on", dest="fail_on", default="", help="comma-separated rules that make the run exit 1"
    )
    p.add_argument(
        "--ignore-rule", dest="ignore_rule", action="append", default=[], help="suppress a rule entirely"
    )
    p.add_argument(
        "--ignore-path", dest="ignore_path", action="append", default=[], help="suppress a path prefix"
    )
    p.add_argument("--severity", choices=SEVERITIES, default="low", help="minimum severity to report")
    p.add_argument(
        "--max-age-days", dest="max_age_days", type=float, help="age limit for rotating parameters"
    )
    return p


def _split_rules(raw: str) -> list[str]:
    return [r.strip() for r in raw.split(",") if r.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        fail_on = validate_rule_names(_split_rules(args.fail_on))
        ignore_rules = validate_rule_names(list(args.ignore_rule))
    except RuleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if not args.baseline and not args.dump_json:
        print("error: --baseline is required unless you are only running --dump-json", file=sys.stderr)
        return EXIT_USAGE

    baseline = Baseline()
    if args.baseline:
        try:
            baseline = load_baseline(args.baseline)
        except BaselineError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE

    audit_path = args.path or baseline.path
    if not audit_path and not args.from_json:
        print("error: --path is required when the baseline does not declare one", file=sys.stderr)
        return EXIT_USAGE

    try:
        if args.from_json:
            live = load_dump(args.from_json)
        else:
            live = collect_live(audit_path, region=args.region, decrypt=args.decrypt)
        if args.dump_json:
            dump_to_file(live, args.dump_json, source_path=audit_path or "", region=args.region)
    except CollectError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if not args.baseline:
        print(f"wrote {len(live)} parameter(s) to {args.dump_json}", file=sys.stderr)
        return EXIT_CLEAN

    findings = evaluate(
        baseline,
        live,
        audit_path=audit_path,
        ignore_paths=args.ignore_path,
        ignore_rules=ignore_rules,
        max_age_days=args.max_age_days,
        show_values=args.show_values,
        min_severity=args.severity,
    )

    render = render_json if args.format == "json" else render_text
    sys.stdout.write(
        render(findings, live, len(baseline.entries), audit_path=audit_path, baseline_path=args.baseline)
    )

    if fail_on and any(f.rule in fail_on for f in findings):
        return EXIT_FINDINGS
    return EXIT_CLEAN


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
