from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from aws_ssm_param_drift.collect import CollectError, dump_to_file, load_dump, parameter_from_dict


def test_loads_the_fixture_dump(live):
    assert len(live) == 8
    assert live[0].name == "/prod/api/timeout"
    assert live[0].last_modified == datetime(2026, 10, 20, 9, 14, tzinfo=UTC)


def test_accepts_a_bare_list(tmp_path):
    p = tmp_path / "d.json"
    p.write_text(json.dumps([{"Name": "/a/b", "Type": "String", "Value": "x"}]))
    assert load_dump(p)[0].name == "/a/b"


def test_securestring_without_an_explicit_flag_is_not_trusted():
    p = parameter_from_dict({"Name": "/a/b", "Type": "SecureString", "Value": "AQICAH..."})
    assert p.decrypted is False
    assert p.value_known is False


def test_plain_string_is_trusted():
    p = parameter_from_dict({"Name": "/a/b", "Type": "String", "Value": "x"})
    assert p.value_known is True


def test_z_suffixed_timestamps_parse():
    p = parameter_from_dict({"Name": "/a", "Type": "String", "LastModifiedDate": "2026-01-02T03:04:05Z"})
    assert p.last_modified == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_naive_timestamps_are_read_as_utc():
    p = parameter_from_dict({"Name": "/a", "Type": "String", "LastModifiedDate": "2026-01-02T03:04:05"})
    assert p.last_modified.tzinfo is UTC


def test_epoch_timestamps_parse():
    p = parameter_from_dict({"Name": "/a", "Type": "String", "LastModifiedDate": 1767322245})
    assert p.last_modified.year == 2026


@pytest.mark.parametrize(
    "payload,fragment",
    [
        ("{}", "no 'parameters' key"),
        ('{"parameters": 3}', "must be a list"),
        ("3", "must be an object or a list"),
        ("not json", "not valid JSON"),
        ('[{"Type": "String"}]', "has no Name"),
        ('[{"Name": "/a", "LastModifiedDate": "yesterday"}]', "unparsable timestamp"),
    ],
)
def test_rejects_bad_dumps(tmp_path, payload, fragment):
    p = tmp_path / "d.json"
    p.write_text(payload)
    with pytest.raises(CollectError) as err:
        load_dump(p)
    assert fragment in str(err.value)


def test_missing_dump_file_is_a_clear_error(tmp_path):
    with pytest.raises(CollectError) as err:
        load_dump(tmp_path / "nope.json")
    assert "cannot read dump" in str(err.value)


def test_dump_round_trips(tmp_path, live):
    out = tmp_path / "round.json"
    dump_to_file(live, out, source_path="/prod", region="eu-central-1")
    again = load_dump(out)
    assert [p.to_dict() for p in again] == [p.to_dict() for p in live]
