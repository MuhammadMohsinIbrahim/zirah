from __future__ import annotations

import re
from pathlib import Path

from zirah.analyzers.base import ScanContext
from zirah.analyzers.common import (
    CONTEXT_CHARS,
    RuleAnalyzer,
    TextField,
    context_snippet,
    iter_text,
    json_pointer,
)
from zirah.models import (
    Finding,
    Manifest,
    Module,
    Prompt,
    PromptArgument,
    Resource,
    Target,
    TargetKind,
    Tool,
)
from zirah.rulepack import Rule, RulePack, Surface, load_rulepack

TARGET = Target(kind=TargetKind.STATIC, location="server.json")


def locations(manifest: Manifest, target: Target | None = None) -> dict[str, str]:
    return {field.location: field.text for field in iter_text(manifest, target)}


def test_json_pointer_escapes_tilde_and_slash() -> None:
    assert json_pointer("tools", 0, "a/b~c") == "/tools/0/a~1b~0c"


def test_iter_text_covers_every_part_of_the_manifest() -> None:
    manifest = Manifest(
        server_name="srv",
        server_version="1.0",
        instructions="Use carefully.",
        tools=(
            Tool(
                name="t",
                title="T",
                description="Does t.",
                input_schema={
                    "type": "object",
                    "properties": {"a/b": {"enum": ["x", 1, None, ["y"]]}},
                },
                output_schema={"description": "out"},
                annotations={"hint": "h", "readOnlyHint": True},
            ),
        ),
        prompts=(
            Prompt(
                name="p",
                title="P",
                description="Prompt.",
                arguments=(PromptArgument(name="arg", description="Arg."),),
            ),
        ),
        resources=(
            Resource(uri="file:///r", name="r", title="R", description="Res.", mime_type="text/x"),
        ),
    )
    assert locations(manifest) == {
        "/server_name": "srv",
        "/server_version": "1.0",
        "/instructions": "Use carefully.",
        "/tools/0/name": "t",
        "/tools/0/title": "T",
        "/tools/0/description": "Does t.",
        # A key and its string value share a pointer; the dict keeps the value (yielded last).
        "/tools/0/input_schema/type": "object",
        "/tools/0/input_schema/properties": "properties",
        "/tools/0/input_schema/properties/a~1b": "a/b",
        "/tools/0/input_schema/properties/a~1b/enum": "enum",
        "/tools/0/input_schema/properties/a~1b/enum/0": "x",
        "/tools/0/input_schema/properties/a~1b/enum/3/0": "y",
        "/tools/0/output_schema/description": "out",
        "/tools/0/annotations/hint": "h",
        "/tools/0/annotations/readOnlyHint": "readOnlyHint",
        "/prompts/0/name": "p",
        "/prompts/0/title": "P",
        "/prompts/0/description": "Prompt.",
        "/prompts/0/arguments/0/name": "arg",
        "/prompts/0/arguments/0/description": "Arg.",
        "/resources/0/uri": "file:///r",
        "/resources/0/name": "r",
        "/resources/0/title": "R",
        "/resources/0/description": "Res.",
        "/resources/0/mime_type": "text/x",
    }


def test_iter_text_yields_keys_before_their_values() -> None:
    manifest = Manifest(tools=(Tool(name="t", input_schema={"type": "object"}),))
    fields = [f for f in iter_text(manifest) if "input_schema" in f.location]
    # The key and its string value share the member's pointer; the key comes first.
    assert [(f.location, f.text) for f in fields] == [
        ("/tools/0/input_schema/type", "type"),
        ("/tools/0/input_schema/type", "object"),
    ]


def test_iter_text_skips_empty_strings_and_absent_fields() -> None:
    manifest = Manifest(tools=(Tool(name="t", description=""),))
    assert locations(manifest) == {"/tools/0/name": "t"}


def test_iter_text_tags_surfaces() -> None:
    manifest = Manifest(
        server_name="s",
        instructions="i",
        tools=(Tool(name="t"),),
        prompts=(Prompt(name="p"),),
        resources=(Resource(uri="u", name="r"),),
    )
    target = Target(kind=TargetKind.STDIO, location="npx", args=("-y", "pkg"))
    surfaces = {f.location: f.surface for f in iter_text(manifest, target)}
    assert surfaces == {
        "/server_name": Surface.SERVER,
        "/instructions": Surface.INSTRUCTIONS,
        "/tools/0/name": Surface.TOOLS,
        "/prompts/0/name": Surface.PROMPTS,
        "/resources/0/uri": Surface.RESOURCES,
        "/resources/0/name": Surface.RESOURCES,
        "target:/location": Surface.TARGET,
        "target:/args": Surface.TARGET,
    }


def test_iter_text_joins_target_args_into_one_command_line() -> None:
    target = Target(kind=TargetKind.STDIO, location="node", args=("server.js", "--port", "80"))
    assert locations(Manifest(), target)["target:/args"] == "server.js --port 80"


def test_iter_text_omits_args_when_there_are_none() -> None:
    assert locations(Manifest(), TARGET) == {"target:/location": "server.json"}


def test_context_snippet_keeps_short_text_whole() -> None:
    assert context_snippet("abc XYZ def", 4, 7) == "abc XYZ def"


def test_context_snippet_trims_long_text_with_ellipses() -> None:
    text = "a" * 100 + "HIT" + "b" * 100
    snippet = context_snippet(text, 100, 103)
    assert snippet == "…" + "a" * CONTEXT_CHARS + "HIT" + "b" * CONTEXT_CHARS + "…"


# --- RuleAnalyzer --------------------------------------------------------------------------


def write_pack(root: Path, body: str) -> RulePack:
    root.joinpath("pack.yaml").write_text("version: t\n", encoding="utf-8")
    root.joinpath("d1.yaml").write_text(body, encoding="utf-8")
    return load_rulepack(root)


RULES = """\
rules:
  - id: D1-WORD
    module: D1
    severity: low
    confidence: high
    owasp: [MCP03]
    title: Bad word
    remediation: Remove it.
    kind: keywords
    patterns: [bad]
  - id: D1-TOOLS-ONLY
    module: D1
    severity: high
    confidence: low
    owasp: [MCP03, MCP06]
    title: Tools only
    remediation: Remove it.
    kind: keywords
    patterns: [evil]
    surfaces: [tools]
"""


class Words(RuleAnalyzer):
    name = "test-words"
    module = Module.D1

    def analyze(self, manifest: Manifest, ctx: ScanContext) -> list[Finding]:
        return self.match_rules(manifest, ctx)


def test_rule_analyzer_builds_findings_from_rules(tmp_path: Path) -> None:
    ctx = ScanContext(target=TARGET, rules=write_pack(tmp_path, RULES))
    manifest = Manifest(tools=(Tool(name="t", description="a bad, bad and evil tool"),))
    findings = Words().run(manifest, ctx)
    # One finding per rule and location, even with repeated matches.
    assert [(f.rule_id, f.evidence.location) for f in findings] == [
        ("D1-WORD", "/tools/0/description"),
        ("D1-TOOLS-ONLY", "/tools/0/description"),
    ]
    first = findings[0]
    assert first.evidence.snippet == "a bad, bad and evil tool"
    assert (first.severity.value, first.confidence.value, first.title) == (
        "low",
        "high",
        "Bad word",
    )
    assert findings[1].owasp == ("MCP03", "MCP06")


def test_rule_analyzer_respects_surfaces(tmp_path: Path) -> None:
    ctx = ScanContext(target=TARGET, rules=write_pack(tmp_path, RULES))
    manifest = Manifest(instructions="bad and evil", tools=(Tool(name="t", title="evil"),))
    found = [(f.rule_id, f.evidence.location) for f in Words().run(manifest, ctx)]
    assert found == [("D1-WORD", "/instructions"), ("D1-TOOLS-ONLY", "/tools/0/title")]


def test_rule_analyzer_hooks_can_filter_and_reshape(tmp_path: Path) -> None:
    class Picky(Words):
        name = "test-picky"

        def accept(
            self, rule: Rule, match: re.Match[str], field: TextField, manifest: Manifest
        ) -> bool:
            return match.start() > 3

        def snippet(self, rule: Rule, match: re.Match[str]) -> str:
            return f"<{match.group(0)}>"

    ctx = ScanContext(target=TARGET, rules=write_pack(tmp_path, RULES))
    manifest = Manifest(instructions="bad, then bad again")
    findings = Picky().run(manifest, ctx)
    assert [f.evidence.snippet for f in findings] == ["<bad>"]
