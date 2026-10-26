# aws-ssm-param-drift

[![ci](https://github.com/moveeeax/aws-ssm-param-drift/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-ssm-param-drift/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Declare the SSM Parameter Store parameters a service expects in a YAML baseline, then diff
that baseline against the live account.

Parameter Store is the one piece of infrastructure that is *meant* to be edited by hand — that
is why the values live outside the deploy. The cost is that there is no declared truth to
compare against. `terraform plan` only sees the parameters Terraform itself created, so a
parameter added during an incident is invisible to it, and nothing at all tells you that
`/prod/api/db-password` is a plain `String` because somebody in a hurry did not pick
SecureString.

This is the missing side of that diff: a file that says what should be there, and a command
that says what actually is.

## What it checks

| Rule | Severity | Fires when |
| --- | --- | --- |
| `missing` | high | The baseline declares a parameter that does not exist in the account. |
| `undeclared` | medium | A parameter exists under the audited path and no baseline entry claims it. This is the hand-edit shape. |
| `type-mismatch` | high | Declared `SecureString`, live `String` — the secret is sitting in plaintext. |
| `default-kms-key` | high | A SecureString encrypted with `alias/aws/ssm` where the baseline asked for a customer-managed key. |
| `value-drift` | medium | The baseline pins a `value` and the live value differs. |
| `value-unverifiable` | low | The baseline pins a value on a SecureString and `--decrypt` was off, so the comparison could not be made. Not clean, not drifted. |
| `pattern-mismatch` | medium | The live value fails the baseline's `pattern` regex. |
| `tier-mismatch` | low | Declared `Standard`, live `Advanced` (the direction that costs money), or the reverse. |
| `stale` | low | A parameter marked `rotating` has not been touched inside `--max-age-days`. |

## Install

```bash
pip install git+https://github.com/moveeeax/aws-ssm-param-drift
```

Python 3.11 or newer. `boto3` is only used for live collection — `--from-json` runs without
credentials and without touching the network.

## The baseline

```yaml
path: /staging

ignore_paths:
  # Scratch space. People create things here during incidents and that is fine.
  - /staging/tmp/

parameters:
  - name: /staging/api/log-level
    type: String
    pattern: '^(debug|info|warn|error)$'

  - name: /staging/api/db-password
    type: SecureString
    key_id: alias/staging-app
    rotating: true
    max_age_days: 90

  - name: /staging/api/feature-flags
    type: StringList
    tier: Standard
```

Every key except `name` is optional, and an omitted key means "do not check this". Pin a
`value` only for parameters whose content is genuinely fixed; for the rest, a `pattern` catches
the shape without pretending to know the content.

## Usage

```bash
# Audit a live account
aws-ssm-param-drift --baseline params.prod.yml --path /prod --region eu-central-1

# Cache the account once, then iterate on the baseline offline
aws-ssm-param-drift --path /prod --dump-json /tmp/ssm.json
aws-ssm-param-drift --baseline params.prod.yml --from-json /tmp/ssm.json

# Gate CI on the rules you actually care about
aws-ssm-param-drift --baseline params.prod.yml --path /prod \
  --fail-on missing,type-mismatch,default-kms-key

# Pipe it somewhere
aws-ssm-param-drift --baseline params.prod.yml --from-json /tmp/ssm.json --format json \
  | jq '.findings[] | select(.rule=="undeclared")'
```

Running the bundled example:

```console
$ aws-ssm-param-drift --baseline examples/params.staging.yml --from-json examples/staging-dump.json
aws-ssm-param-drift  path=/staging  baseline=examples/params.staging.yml
6 live parameter(s), 4 declared

/staging/api/db-password
  HIGH  default-kms-key   encrypted with the AWS-managed alias/aws/ssm key, baseline asked for a customer-managed key
                          expected alias/staging-app != actual alias/aws/ssm
  LOW   stale             marked rotating but last modified 266 days ago (limit 90)
                          expected <= 90d != actual 266d

/staging/api/feature-flags
  LOW   tier-mismatch     declared tier Standard, live Advanced — Advanced parameters are billed per parameter per month
                          expected Standard != actual Advanced

/staging/api/log-level
  MED   pattern-mismatch  live value does not match /^(debug|info|warn|error)$/
                          expected /^(debug|info|warn|error)$/ != actual sha256:eafe895eb811

/staging/api/stripe-key
  MED   undeclared        exists in the account (String) but no baseline entry claims it
                          expected declared != actual undeclared

5 finding(s): 1 high, 2 medium, 2 low
```

### Flags

| Flag | Effect |
| --- | --- |
| `--baseline FILE` | The YAML baseline. Required unless you are only running `--dump-json`. |
| `--path PREFIX` | SSM path to audit. Defaults to the baseline's `path`. |
| `--region NAME` | AWS region for live collection. |
| `--from-json FILE` | Replay a cached dump; makes no API calls. |
| `--dump-json FILE` | Write the collected parameters so the run can be replayed. |
| `--decrypt` | Call SSM with `WithDecryption` so SecureString values can be compared. |
| `--show-values` | Print real values instead of hashes. Off by default, deliberately. |
| `--format text\|json` | Output shape. |
| `--fail-on RULES` | Comma-separated rules that make the run exit 1. |
| `--ignore-rule RULE` | Suppress a rule. Repeatable. |
| `--ignore-path PREFIX` | Suppress a path prefix on both sides of the diff. Repeatable. |
| `--severity low\|medium\|high` | Minimum severity to report. |
| `--max-age-days N` | Fallback age limit for parameters marked `rotating`. |

Exit codes: `0` clean (or nothing in `--fail-on` fired), `1` a `--fail-on` rule fired,
`2` bad usage — unreadable baseline, unparsable dump, unknown rule name.

## Values are never printed

A drift report is something you paste into a ticket, so a `value-drift` finding reports
`sha256:` fingerprints of the expected and actual values rather than the values themselves.
You still learn that the value changed and that the two sides differ; you do not learn the
secret. `--show-values` exists for when you are looking at a non-secret parameter and want the
diff spelled out.

The same principle drives `value-unverifiable`. If the baseline pins a value on a SecureString
and `--decrypt` was not passed, the honest answer is "I could not check this" — reporting it as
clean would be a lie, and reporting it as drift would be a guess. It gets its own rule, with the
live version and last-modified date so you can at least see whether anything moved.

## In CI

```yaml
- name: Check prod parameters against the baseline
  run: |
    pip install git+https://github.com/moveeeax/aws-ssm-param-drift
    aws-ssm-param-drift --baseline params.prod.yml --path /prod \
      --fail-on missing,type-mismatch,default-kms-key
```

Start with `--fail-on missing,type-mismatch,default-kms-key`. Those three are unambiguous
breakage. Add `undeclared` once the baseline has caught up with reality, otherwise the first run
fails on every parameter anybody ever created by hand, which is usually a lot of them.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
ruff check .
pytest
```

The collector returns a plain list of dataclasses and the rule engine consumes that list, so the
whole suite runs off JSON fixtures in `tests/fixtures/` with no AWS account and no mocking
library.

## License

MIT
