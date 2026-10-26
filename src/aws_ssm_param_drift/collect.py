"""Collect live parameters, either from AWS or from a cached JSON dump.

The collector's only job is to produce ``list[LiveParameter]``. Everything downstream
consumes that list, which is why the whole rule engine is testable from a JSON fixture
with no credentials anywhere near it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .model import LiveParameter


class CollectError(RuntimeError):
    pass


def _parse_ts(raw: Any) -> datetime | None:
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(raw, tz=UTC)
    if isinstance(raw, str):
        text = raw.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise CollectError(f"unparsable timestamp {raw!r}") from exc
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    raise CollectError(f"unparsable timestamp {raw!r}")


def parameter_from_dict(raw: dict) -> LiveParameter:
    name = raw.get("Name") or raw.get("name")
    if not name:
        raise CollectError(f"parameter record has no Name: {raw!r}")
    ptype = raw.get("Type") or raw.get("type") or "String"
    version = raw.get("Version", raw.get("version"))
    if version is not None:
        version = int(version)
    value = raw.get("Value", raw.get("value"))
    decrypted = raw.get("Decrypted", raw.get("decrypted"))
    if decrypted is None:
        # A SecureString we were handed a value for without an explicit flag is assumed
        # to be ciphertext; anything else is plain text by construction.
        decrypted = ptype != "SecureString"
    return LiveParameter(
        name=name,
        type=ptype,
        tier=raw.get("Tier", raw.get("tier")),
        key_id=raw.get("KeyId", raw.get("key_id")),
        version=version,
        last_modified=_parse_ts(raw.get("LastModifiedDate", raw.get("last_modified"))),
        value=value,
        decrypted=bool(decrypted),
    )


def load_dump(path: str | Path) -> list[LiveParameter]:
    p = Path(path)
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CollectError(f"cannot read dump {p}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CollectError(f"dump {p} is not valid JSON: {exc}") from exc

    if isinstance(doc, dict):
        records = doc.get("parameters")
        if records is None:
            raise CollectError(f"dump {p} has no 'parameters' key")
    elif isinstance(doc, list):
        records = doc
    else:
        raise CollectError(f"dump {p} must be an object or a list")

    if not isinstance(records, list):
        raise CollectError(f"dump {p}: 'parameters' must be a list")
    return [parameter_from_dict(r) for r in records]


def dump_to_file(
    params: list[LiveParameter], path: str | Path, *, source_path: str, region: str | None
) -> None:
    payload = {
        "path": source_path,
        "region": region,
        "collected_at": datetime.now(UTC).isoformat(),
        "parameters": [p.to_dict() for p in params],
    }
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def collect_live(path: str, *, region: str | None = None, decrypt: bool = False) -> list[LiveParameter]:
    """Read every parameter under ``path`` from the account.

    ``describe_parameters`` is the only call that returns ``Tier`` and ``KeyId``;
    ``get_parameters_by_path`` is the only one that returns ``Value``. We need both,
    so we run both and merge on name.
    """
    try:
        import boto3  # imported lazily: --from-json must work without boto3 installed
    except ImportError as exc:  # pragma: no cover - exercised only without boto3
        raise CollectError("boto3 is required for live collection; install it or use --from-json") from exc

    client = boto3.client("ssm", region_name=region)

    metadata: dict[str, dict] = {}
    describe = client.get_paginator("describe_parameters")
    filters = [{"Key": "Path", "Option": "Recursive", "Values": [path]}]
    for page in describe.paginate(ParameterFilters=filters):
        for item in page.get("Parameters", []):
            metadata[item["Name"]] = item

    values: dict[str, dict] = {}
    by_path = client.get_paginator("get_parameters_by_path")
    for page in by_path.paginate(Path=path, Recursive=True, WithDecryption=decrypt):
        for item in page.get("Parameters", []):
            values[item["Name"]] = item

    out: list[LiveParameter] = []
    for name in sorted(set(metadata) | set(values)):
        meta = metadata.get(name, {})
        val = values.get(name, {})
        ptype = meta.get("Type") or val.get("Type") or "String"
        known = ptype != "SecureString" or decrypt
        out.append(
            LiveParameter(
                name=name,
                type=ptype,
                tier=meta.get("Tier"),
                key_id=meta.get("KeyId"),
                version=meta.get("Version") or val.get("Version"),
                last_modified=_parse_ts(meta.get("LastModifiedDate") or val.get("LastModifiedDate")),
                value=val.get("Value") if known else None,
                decrypted=known,
            )
        )
    return out
