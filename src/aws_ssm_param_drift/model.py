"""Core data types shared by the collector, the rule engine and the reporters."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime

PARAMETER_TYPES = ("String", "StringList", "SecureString")
TIERS = ("Standard", "Advanced", "Intelligent-Tiering")

#: Values of ``KeyId`` that mean "the account's AWS-managed SSM key", i.e. not a CMK.
AWS_MANAGED_KEY_MARKER = "alias/aws/ssm"

SEVERITIES = ("low", "medium", "high")


def severity_rank(severity: str) -> int:
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        return 0


def digest(value: str) -> str:
    """Short, stable fingerprint of a parameter value.

    Findings print this instead of the value itself, so a drift report can be pasted
    into a ticket without leaking what the secret actually is.
    """
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def is_aws_managed_key(key_id: str | None) -> bool:
    if not key_id:
        return False
    return AWS_MANAGED_KEY_MARKER in key_id


@dataclass
class LiveParameter:
    """One parameter as it exists in the account right now."""

    name: str
    type: str
    tier: str | None = None
    key_id: str | None = None
    version: int | None = None
    last_modified: datetime | None = None
    value: str | None = None
    #: False when the value is absent or still ciphertext (SecureString without --decrypt).
    decrypted: bool = True

    @property
    def value_known(self) -> bool:
        return self.value is not None and self.decrypted

    def age_days(self, now: datetime | None = None) -> float | None:
        if self.last_modified is None:
            return None
        now = now or datetime.now(UTC)
        reference = self.last_modified
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=UTC)
        return (now - reference).total_seconds() / 86400.0

    def to_dict(self) -> dict:
        return {
            "Name": self.name,
            "Type": self.type,
            "Tier": self.tier,
            "KeyId": self.key_id,
            "Version": self.version,
            "LastModifiedDate": self.last_modified.isoformat() if self.last_modified else None,
            "Value": self.value,
            "Decrypted": self.decrypted,
        }


@dataclass
class Finding:
    parameter: str
    rule: str
    severity: str
    message: str
    expected: str | None = None
    actual: str | None = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        out = {
            "parameter": self.parameter,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
        }
        if self.expected is not None:
            out["expected"] = self.expected
        if self.actual is not None:
            out["actual"] = self.actual
        out.update(self.extra)
        return out
