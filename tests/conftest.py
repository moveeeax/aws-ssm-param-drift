from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from aws_ssm_param_drift.baseline import load_baseline
from aws_ssm_param_drift.collect import load_dump

FIXTURES = Path(__file__).parent / "fixtures"

#: Every age-sensitive assertion pins the clock here so the suite does not rot.
NOW = datetime(2026, 10, 26, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def baseline_path() -> Path:
    return FIXTURES / "params.prod.yml"


@pytest.fixture
def dump_path() -> Path:
    return FIXTURES / "prod-dump.json"


@pytest.fixture
def baseline(baseline_path):
    return load_baseline(baseline_path)


@pytest.fixture
def live(dump_path):
    return load_dump(dump_path)


@pytest.fixture
def now() -> datetime:
    return NOW
