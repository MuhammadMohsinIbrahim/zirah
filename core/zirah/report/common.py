"""Helpers shared by the human-readable reports (terminal, markdown).

Snippets come from untrusted manifests: before display they are escaped so invisible
characters, control codes and line breaks show up as visible ``\\uXXXX``-style escapes instead
of acting on the terminal or the page. Secrets are already redacted by the analyzers.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass

from zirah.analyzers.common import TARGET_PREFIX
from zirah.models import Finding, Grade, Manifest, Severity
from zirah.scoring import MAX_SCORE, Score, finding_weight

BACKSLASH = chr(92)

SNIPPET_CHARS = 120
"""Longest snippet shown per finding in a report (after escaping)."""

REMEDIATION_CHARS = 160
"""Longest one-line remediation shown per finding."""

REMEDIATION_MIN_CHARS = 40
"""Sentences are added to a one-line remediation until it is at least this long, so a bare
"Remove the text." comes with its reason."""

NAME_CHARS = 60
"""Longest tool/prompt/resource name shown in a location label."""

LOCATION_SEPARATOR = " \N{SINGLE RIGHT-POINTING ANGLE QUOTATION MARK} "

SAME_TEXT = "(same text as above)"
"""Shown instead of a snippet identical to the previous finding's at the same location."""

GRADE_MEANING: dict[Grade, str] = {
    Grade.A: "No significant findings.",
    Grade.B: "Minor findings. Review them before use.",
    Grade.C: "Notable findings. Fix or accept them before use.",
    Grade.D: "Serious findings. Avoid this server until they are fixed.",
    Grade.F: "Severe findings. Do not use this server until they are fixed.",
}

_HIDDEN_CATEGORIES = {"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"}
_NAMED_ESCAPES = {"\n": "n", "\r": "r", "\t": "t"}


def _is_hidden(char: str) -> bool:
    category = unicodedata.category(char)
    if category in _HIDDEN_CATEGORIES:
        return True
    if category == "Zs":
        return char != " "
    code = ord(char)
    return 0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF  # variation selectors


def _escape_char(char: str) -> str:
    if char in _NAMED_ESCAPES:
        return BACKSLASH + _NAMED_ESCAPES[char]
    if _is_hidden(char):
        code = ord(char)
        return f"{BACKSLASH}u{code:04x}" if code <= 0xFFFF else f"{BACKSLASH}U{code:08x}"
    return char


def escape_text(text: str, limit: int | None = None) -> str:
    """``text`` with every invisible, control or unusual space character written as an
    escape (``\\n``, ``\\u200b``, ``\\U000e0041``), so what is shown is what is there.

    With ``limit``, the result is at most that long and ends in ``…`` when cut; an escape is
    never cut in half.
    """
    pieces = [_escape_char(char) for char in text]
    if limit is None or sum(map(len, pieces)) <= limit:
        return "".join(pieces)
    kept: list[str] = []
    room = limit - 1
    for piece in pieces:
        if len(piece) > room:
            break
        kept.append(piece)
        room -= len(piece)
    return "".join(kept).rstrip() + "…"


def shorten(text: str, limit: int) -> str:
    """``text`` cut to at most ``limit`` characters, ending in ``…`` when cut."""
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def display_snippet(finding: Finding, limit: int = SNIPPET_CHARS) -> str:
    """The finding's snippet, escaped and shortened for display."""
    return escape_text(finding.evidence.snippet, limit)


def one_line(text: str, limit: int = REMEDIATION_CHARS) -> str:
    """The first sentences of ``text`` on one line: at least ``REMEDIATION_MIN_CHARS`` long
    when the text allows, at most ``limit``."""
    flat = " ".join(text.split())
    end = flat.find(". ")
    while 0 <= end < REMEDIATION_MIN_CHARS:
        end = flat.find(". ", end + 1)
    return shorten(flat if end < 0 else flat[: end + 1], limit)


def _pointer_parts(pointer: str) -> list[str]:
    return [p.replace("~1", "/").replace("~0", "~") for p in pointer.split("/")[1:]]


def _name(value: str) -> str:
    return '"' + escape_text(value, NAME_CHARS) + '"'


def describe_location(location: str, manifest: Manifest) -> str:
    """A readable label for an evidence location, e.g. ``tool "add"`` then ``description``,
    joined by ``LOCATION_SEPARATOR``.

    Falls back to the raw location when it does not point into ``manifest``.
    """
    if location.startswith(TARGET_PREFIX):
        rest = location.removeprefix(TARGET_PREFIX)
        return {"/location": "target location", "/args": "target arguments"}.get(rest, location)

    parts = _pointer_parts(location)
    labels: list[str] = []
    try:
        head = parts[0] if parts else ""
        if head in ("tools", "prompts", "resources"):
            index = int(parts[1])
            items: Sequence[object] = getattr(manifest, head)
            item = items[index]
            labels.append(f"{head[:-1]} {_name(getattr(item, 'name', ''))}")
            parts = parts[2:]
            if head == "prompts" and parts[:1] == ["arguments"]:
                argument = manifest.prompts[index].arguments[int(parts[1])]
                labels.append(f"argument {_name(argument.name)}")
                parts = parts[2:]
        elif head in ("instructions", "server_name", "server_version"):
            labels.append({"instructions": "server instructions"}.get(head, head.replace("_", " ")))
            parts = parts[1:]
        else:
            return location
    except (IndexError, ValueError):
        return location

    for part in parts:
        if part == "properties":
            continue
        labels.append(part.replace("_", " ") if part.endswith("_schema") else escape_text(part))
    return LOCATION_SEPARATOR.join(labels)


@dataclass(frozen=True, slots=True)
class LocationGroup:
    """All findings at one evidence location, heaviest first."""

    location: str
    findings: tuple[Finding, ...]
    points: float

    @property
    def severity(self) -> Severity:
        return self.findings[0].severity


def group_by_location(findings: Sequence[Finding], score: Score) -> list[LocationGroup]:
    """Findings grouped by location. Groups are ordered by their worst severity, then by the
    points they cost, then by location; findings inside a group by severity, then weight."""
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.evidence.location, []).append(finding)

    groups = []
    for location, items in grouped.items():
        items.sort(key=lambda f: (-f.severity.rank, -finding_weight(f), f.rule_id, f.id))
        points = round(sum(score.points_for(f.id) for f in items), 2)
        groups.append(LocationGroup(location, tuple(items), points))
    groups.sort(key=lambda g: (-g.severity.rank, -g.points, g.location))
    return groups


def severity_counts(findings: Sequence[Finding]) -> list[tuple[Severity, int]]:
    """How many findings of each severity there are, worst first, zero counts left out."""
    counts = {severity: 0 for severity in reversed(Severity)}
    for finding in findings:
        counts[finding.severity] += 1
    return [(severity, count) for severity, count in counts.items() if count]


def cap_explanation(score: Score) -> str | None:
    """Why the score was capped, in plain words, or ``None`` when it was not."""
    if score.cap is None:
        return None
    count = len(score.cap.finding_ids)
    noun = "finding" if count == 1 else "findings"
    return (
        f"Capped at {score.cap.limit} (from {score.uncapped_score}): {count} {score.cap.severity} "
        f"{noun} with {score.cap.confidence} confidence."
    )


def score_formula(score: Score) -> str:
    """How the score follows from the deductions, e.g.
    ``100 - 87 points (deductions rounded up) = 13``, plus the floor and cap when they apply."""
    text = (
        f"{MAX_SCORE} - {score.deducted_points} points (deductions rounded up) "
        f"= {score.uncapped_score}"
    )
    if score.deducted_points > MAX_SCORE:
        text += " (a score cannot go below 0)"
    if score.cap:
        text += f", capped at {score.cap.limit}"
    return text
