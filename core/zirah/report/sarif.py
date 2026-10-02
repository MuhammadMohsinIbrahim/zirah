"""SARIF 2.1.0 report, for GitHub code scanning and other SARIF viewers.

- One ``reportingDescriptor`` per rule that fired, tagged with its module and OWASP categories
  and carrying ``security-severity`` (from ``scoring.SECURITY_SEVERITY``) and ``precision``.
- One ``result`` per finding. Its JSON Pointer is a logical location; static manifest files are
  also given as the physical artifact. The finding id is the stable fingerprint.
- The trust score and grade are run properties; failed analyzers become tool execution
  notifications and mark the invocation unsuccessful.

The output is ASCII-only JSON, so invisible characters in snippets appear as ``\\u`` escapes
in the file.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from zirah.analyzers.common import TARGET_PREFIX
from zirah.models import Finding, Severity, Target, TargetKind
from zirah.scan import Scan
from zirah.scoring import SECURITY_SEVERITY

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
TOOL_NAME = "Zirah"
INFORMATION_URI = "https://github.com/MuhammadMohsinIbrahim/zirah-mcp"
FINGERPRINT = "zirahFindingId/v1"

LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render(scan: Scan) -> str:
    return json.dumps(to_sarif(scan), indent=2, ensure_ascii=True) + "\n"


def to_sarif(scan: Scan) -> dict[str, Any]:
    result = scan.result
    rules = _rules(result.findings)
    index = {rule["id"]: i for i, rule in enumerate(rules)}
    artifact = _artifact_uri(result.target)

    invocation: dict[str, Any] = {
        "executionSuccessful": scan.complete,
        "startTimeUtc": _utc(result.started_at),
        "endTimeUtc": _utc(result.finished_at),
    }
    if scan.failures:
        invocation["toolExecutionNotifications"] = [
            {
                "level": "error",
                "message": {"text": f"Analyzer {f.analyzer} failed: {f.error}"},
                "descriptor": {"id": f.analyzer},
            }
            for f in scan.failures
        ]

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": result.zirah_version,
                "informationUri": INFORMATION_URI,
                "rules": rules,
                "properties": {"rulepackVersion": result.rulepack_version},
            }
        },
        "invocations": [invocation],
        "results": [
            _result(finding, index[finding.rule_id], artifact, scan.score.points_for(finding.id))
            for finding in result.findings
        ],
        "properties": {
            "trustScore": result.trust_score,
            "grade": result.grade.value,
            "manifestSha256": result.manifest_sha256,
            "schemaVersion": result.schema_version,
            "target": result.target.model_dump(mode="json", exclude_none=True),
        },
    }
    if artifact is not None:
        run["artifacts"] = [{"location": {"uri": artifact}}]
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def _rules(findings: tuple[Finding, ...]) -> list[dict[str, Any]]:
    first: dict[str, Finding] = {}
    for finding in findings:
        first.setdefault(finding.rule_id, finding)
    return [_rule(first[rule_id]) for rule_id in sorted(first)]


def _rule(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "shortDescription": {"text": finding.title},
        "help": {"text": finding.remediation},
        "defaultConfiguration": {"level": LEVEL[finding.severity]},
        "properties": {
            "tags": ["security", finding.module.value, *finding.owasp],
            "security-severity": SECURITY_SEVERITY[finding.severity],
            "precision": finding.confidence.value,
        },
    }


def _result(
    finding: Finding, rule_index: int, artifact: str | None, points: float
) -> dict[str, Any]:
    location: dict[str, Any] = {
        "logicalLocations": [{"fullyQualifiedName": finding.evidence.location, "kind": "member"}]
    }
    if artifact is not None and not finding.evidence.location.startswith(TARGET_PREFIX):
        location["physicalLocation"] = {"artifactLocation": {"uri": artifact, "index": 0}}
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": LEVEL[finding.severity],
        "message": {"text": f"{finding.title} (at {finding.evidence.location})"},
        "locations": [location],
        "fingerprints": {FINGERPRINT: finding.id},
        "partialFingerprints": {FINGERPRINT: finding.id},
        "properties": {
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "module": finding.module.value,
            "owasp": list(finding.owasp),
            "engine": finding.engine.value,
            "snippet": finding.evidence.snippet,
            "points": points,
        },
    }


def _artifact_uri(target: Target) -> str | None:
    """The manifest file as a SARIF URI: relative paths stay relative (with ``/``), absolute
    paths become ``file://`` URIs. Only static targets are files."""
    if target.kind is not TargetKind.STATIC:
        return None
    windows = PureWindowsPath(target.location)
    if windows.is_absolute():
        return windows.as_uri()
    posix = PurePosixPath(target.location)
    if posix.is_absolute():
        return posix.as_uri()
    return windows.as_posix()


def _utc(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")
