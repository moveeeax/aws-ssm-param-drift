"""Command line entry point."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .baseline import Baseline, BaselineError, load_baseline, parse_baseline
from .collect import CollectError, collect_live, dump_to_file, load_dump
from .init import generate, merge
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
        epilog="Rules: " + ", ".join(ALL_RULES) + ". "
        "Run 'aws-ssm-param-drift init --help' to write a starter baseline.",
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


def build_init_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-ssm-param-drift init",
        description="Write a starter baseline with one entry per live parameter. Values are never written.",
    )
    p.add_argument("--path", help="SSM path prefix to describe (defaults to the --merge baseline's 'path')")
    p.add_argument("--region", help="AWS region for live collection")
    p.add_argument("--from-json", dest="from_json", help="read a cached dump instead of calling AWS")
    p.add_argument(
        "--merge", metavar="FILE", help="append only the undeclared parameters to this existing baseline"
    )
    p.add_argument(
        "--output", "-o", metavar="FILE", help="write here instead of stdout; may be the --merge file"
    )
    p.add_argument(
        "--ignore-path", dest="ignore_path", action="append", default=[], help="skip a path prefix"
    )
    return p


def _same_file_as_stdout(path: str) -> bool:
    try:
        return os.path.samestat(os.fstat(sys.stdout.fileno()), os.stat(path))
    except (OSError, ValueError, AttributeError):
        # io.UnsupportedOperation (pytest's capture, a StringIO) is both an OSError and a ValueError.
        return False


def _write_atomically(path: str, text: str) -> None:
    target = Path(path)
    tmp = target.with_name(f".{target.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, target)


def init_main(argv: list[str]) -> int:
    args = build_init_parser().parse_args(argv)

    existing = None
    if args.merge:
        if not args.output and _same_file_as_stdout(args.merge):
            # `init --merge b.yml > b.yml`: the shell has already truncated the file.
            print(
                f"error: stdout is {args.merge} itself; use --output {args.merge} to update it in place",
                file=sys.stderr,
            )
            return EXIT_USAGE
        try:
            existing = Path(args.merge).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot read baseline {args.merge}: {exc}", file=sys.stderr)
            return EXIT_USAGE

    path = args.path
    if not path and existing is not None:
        try:
            path = parse_baseline(existing).path
        except BaselineError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE
    if not path and not args.from_json:
        print("error: --path is required for live collection", file=sys.stderr)
        return EXIT_USAGE

    try:
        if args.from_json:
            live = load_dump(args.from_json)
        else:
            live = collect_live(path, region=args.region, decrypt=False)
    except CollectError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        if existing is not None:
            result = merge(existing, live, path=path, ignore_paths=args.ignore_path)
        else:
            result = generate(live, path=path, ignore_paths=args.ignore_path)
    except BaselineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.output:
        _write_atomically(args.output, result.text)
    else:
        sys.stdout.write(result.text)

    where = args.output or "stdout"
    if existing is not None:
        print(
            f"added {len(result.added)} undeclared parameter(s) to {result.kept} existing entr(ies)"
            f" -> {where}",
            file=sys.stderr,
        )
    else:
        print(f"wrote {len(result.added)} entr(ies) for {path or '(all)'} -> {where}", file=sys.stderr)
    return EXIT_CLEAN


def _split_rules(raw: str) -> list[str]:
    return [r.strip() for r in raw.split(",") if r.strip()]


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] == "init":
        return init_main(argv[1:])

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
