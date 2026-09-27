"""Core data contract for Zirah.

Every loader produces a ``Manifest``, every analyzer produces ``Finding`` objects, and a scan
ends in a ``ScanResult``. Reports, scoring, attestations and the registry all consume these
types, so change them deliberately and update the tests when you do.

All models are frozen and reject unknown fields, so a typo in a field name is an error rather
than silently dropped data.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Any, Final, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from zirah import __version__

SCHEMA_VERSION: Final = "0.1"
"""Version of the serialized finding/result schema. Bump on any breaking change."""

SNIPPET_MAX_CHARS: Final = 2000
"""Longest ``Evidence.snippet`` kept, marker included. Stops huge descriptions bloating reports."""

NonEmptyStr = Annotated[str, StringConstraints(min_length=1)]
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


def canonical_json(data: Any) -> bytes:
    """Serialize ``data`` deterministically: sorted keys, no whitespace, UTF-8.

    Used for manifest hashing and, later, attestation signing. Non-ASCII characters are kept
    as-is (not ``\\u`` escaped) so invisible Unicode in a manifest changes the hash exactly
    as it changes the bytes.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# --- Enums ---------------------------------------------------------------------------------


class Module(StrEnum):
    """Detection module identifiers (see SPEC.md §3)."""

    D1 = "D1"
    D2 = "D2"
    D3 = "D3"
    D4 = "D4"
    D5 = "D5"
    D6 = "D6"
    D7 = "D7"
    D8 = "D8"
    D9 = "D9"
    D10 = "D10"
    D11 = "D11"
    D12 = "D12"
    D13 = "D13"
    D14 = "D14"


class Owasp(StrEnum):
    """OWASP MCP Top 10 categories."""

    MCP01 = "MCP01"
    MCP02 = "MCP02"
    MCP03 = "MCP03"
    MCP04 = "MCP04"
    MCP05 = "MCP05"
    MCP06 = "MCP06"
    MCP07 = "MCP07"
    MCP08 = "MCP08"
    MCP09 = "MCP09"
    MCP10 = "MCP10"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Ordinal position, ``INFO`` = 0 .. ``CRITICAL`` = 4. For sorting, not scoring."""
        return list(Severity).index(self)


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Engine(StrEnum):
    """How a finding was produced."""

    STATIC = "static"
    LLM = "llm"
    DYNAMIC = "dynamic"


class LlmProvider(StrEnum):
    """LLM backends for the semantic judge. ``--llm none`` means no ``LlmInfo`` at all."""

    OLLAMA = "ollama"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class TargetKind(StrEnum):
    STDIO = "stdio"
    HTTP = "http"
    STATIC = "static"


class Grade(StrEnum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


# --- Target & manifest -----------------------------------------------------------------------


class Target(_Model):
    """What was scanned.

    ``location`` is the command for stdio, the URL for http, or the file path for static.
    Environment variables are deliberately not part of the target: they often hold secrets
    and must never end up in a report or attestation.
    """

    kind: TargetKind
    location: NonEmptyStr
    args: tuple[str, ...] = ()
    name: str | None = None

    @property
    def identity(self) -> tuple[TargetKind, str, tuple[str, ...]]:
        """What makes two targets the same server. ``name`` is only a label: the same server
        configured in two clients under different names is still one target."""
        return (self.kind, self.location, self.args)


class Tool(_Model):
    name: NonEmptyStr
    title: str | None = None
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None


class PromptArgument(_Model):
    name: NonEmptyStr
    description: str = ""
    required: bool = False


class Prompt(_Model):
    name: NonEmptyStr
    title: str | None = None
    description: str = ""
    arguments: tuple[PromptArgument, ...] = ()


class Resource(_Model):
    uri: NonEmptyStr
    name: NonEmptyStr
    title: str | None = None
    description: str = ""
    mime_type: str | None = None


class Manifest(_Model):
    """Everything an MCP server exposes to a client: the surface Zirah analyzes."""

    server_name: str | None = None
    server_version: str | None = None
    instructions: str | None = None
    tools: tuple[Tool, ...] = ()
    prompts: tuple[Prompt, ...] = ()
    resources: tuple[Resource, ...] = ()

    def sha256(self) -> str:
        """Hex SHA-256 of the canonical JSON form. Stable across field and key order."""
        return hashlib.sha256(canonical_json(self.model_dump(mode="json"))).hexdigest()


# --- Findings --------------------------------------------------------------------------------


class Evidence(_Model):
    """Where a finding was observed and what was seen there.

    ``location`` is a JSON Pointer into the manifest (e.g. ``/tools/0/description``) for
    manifest findings, or ``<path>:<line>`` for findings in files (configs, source).
    ``snippet`` is the offending text, verbatim: invisible characters are kept on purpose.
    Snippets longer than ``SNIPPET_MAX_CHARS`` are cut and end with a truncation marker.
    """

    location: NonEmptyStr
    snippet: str

    @field_validator("snippet")
    @classmethod
    def _cap_snippet(cls, value: str) -> str:
        if len(value) <= SNIPPET_MAX_CHARS:
            return value
        # The marker length depends on how much was cut, which depends on the marker length.
        # Size it for the worst case (the whole value) so the result never exceeds the cap.
        marker_len = len(_truncation_marker(len(value)))
        kept = SNIPPET_MAX_CHARS - marker_len
        return value[:kept] + _truncation_marker(len(value) - kept)


def _truncation_marker(dropped: int) -> str:
    return f"…[truncated {dropped} chars]"


class Finding(_Model):
    """One issue detected by one rule.

    ``id`` is derived from ``rule_id`` and the evidence when not given, so the same issue in
    the same place always gets the same id across runs. This is what lets reports dedupe
    findings and lets attestations be reproduced.
    """

    id: NonEmptyStr
    module: Module
    rule_id: NonEmptyStr
    severity: Severity
    confidence: Confidence
    owasp: Annotated[tuple[Owasp, ...], Field(min_length=1)]
    title: NonEmptyStr
    evidence: Evidence
    remediation: NonEmptyStr
    engine: Engine

    @model_validator(mode="before")
    @classmethod
    def _derive_id(cls, data: Any) -> Any:
        if isinstance(data, dict) and not data.get("id"):
            evidence = data.get("evidence")
            if isinstance(evidence, dict):
                # Validate first so the id is computed from the stored (truncated) snippet,
                # whether evidence arrived as a model or a raw dict.
                evidence = Evidence.model_validate(evidence)
            if isinstance(evidence, Evidence):
                data = {**data, "id": finding_id(data.get("rule_id"), evidence)}
        return data

    @field_validator("owasp")
    @classmethod
    def _normalize_owasp(cls, value: tuple[Owasp, ...]) -> tuple[Owasp, ...]:
        """Sorted and de-duplicated, so equal findings serialize identically."""
        return tuple(sorted(set(value)))


def finding_id(rule_id: Any, evidence: Evidence) -> str:
    """Deterministic 16-hex-char id for a finding: hash of rule, location and snippet."""
    payload = canonical_json([rule_id, evidence.location, evidence.snippet])
    return hashlib.sha256(payload).hexdigest()[:16]


# --- Scan result -----------------------------------------------------------------------------


class LlmInfo(_Model):
    """Which model judged a scan. LLM findings are only reproducible with this recorded."""

    provider: LlmProvider
    model: NonEmptyStr


class ScanResult(_Model):
    """The outcome of scanning one target.

    ``trust_score`` runs from 0 to 100, where 100 means no findings, and ``grade`` is its
    letter form (A best). Both are computed by ``zirah.scoring``, which alone defines the
    weights and grade thresholds, and every point deducted must trace back to ``findings``.
    ``engines_used`` lists every engine that ran, including ones that found nothing, and
    ``llm`` is set exactly when the LLM engine ran.
    ``signature`` stays ``None`` until attestations land (v0.3).
    """

    schema_version: Literal["0.1"] = SCHEMA_VERSION
    target: Target
    manifest_sha256: Sha256Hex
    zirah_version: NonEmptyStr = __version__
    rulepack_version: NonEmptyStr
    findings: tuple[Finding, ...] = ()
    trust_score: Annotated[int, Field(ge=0, le=100)]
    grade: Grade
    started_at: AwareDatetime
    finished_at: AwareDatetime
    engines_used: Annotated[tuple[Engine, ...], Field(min_length=1)]
    llm: LlmInfo | None = None
    signature: str | None = None

    @field_validator("engines_used")
    @classmethod
    def _normalize_engines(cls, value: tuple[Engine, ...]) -> tuple[Engine, ...]:
        order = list(Engine)
        return tuple(sorted(set(value), key=order.index))

    @model_validator(mode="after")
    def _check_consistency(self) -> ScanResult:
        if self.finished_at < self.started_at:
            raise ValueError("finished_at is before started_at")

        ids = [f.id for f in self.findings]
        if len(ids) != len(set(ids)):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            raise ValueError(f"duplicate finding ids: {', '.join(dupes)}; dedupe before building")

        unlisted = sorted({f.engine for f in self.findings} - set(self.engines_used))
        if unlisted:
            raise ValueError(f"findings from engines not in engines_used: {', '.join(unlisted)}")

        llm_ran = Engine.LLM in self.engines_used
        if llm_ran and self.llm is None:
            raise ValueError("llm must be set when the llm engine ran")
        if not llm_ran and self.llm is not None:
            raise ValueError("llm is set but the llm engine is not in engines_used")
        return self


class ScanSession(_Model):
    """All results of one multi-target run (``zirah scan --all`` or several targets).

    Cross-server analysis (the ``graph`` stage) consumes a session; single-target scans never
    see each other. Each target appears at most once: dedupe before building the session.
    """

    schema_version: Literal["0.1"] = SCHEMA_VERSION
    results: tuple[ScanResult, ...] = ()

    @model_validator(mode="after")
    def _unique_targets(self) -> ScanSession:
        seen: set[tuple[TargetKind, str, tuple[str, ...]]] = set()
        for result in self.results:
            identity = result.target.identity
            if identity in seen:
                raise ValueError(
                    f"duplicate target in session: {result.target.kind} {result.target.location}"
                )
            seen.add(identity)
        return self
