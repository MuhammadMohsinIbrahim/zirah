from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from zirah.models import Module, Owasp, Severity
from zirah.rulepack import MANIFEST_SURFACES, RulePack, RulePackError, Surface, load_rulepack

RULE_FIELDS = """
    module: {module}
    severity: high
    confidence: medium
    owasp: [MCP03]
    title: Test rule
    remediation: Fix it.
"""


def rule_yaml(
    rule_id: str, kind: str, patterns: list[str], module: str = "D1", **extra: str
) -> str:
    lines = [f"  - id: {rule_id}"]
    lines += [
        "    " + line.strip() for line in RULE_FIELDS.format(module=module).strip().splitlines()
    ]
    lines.append(f"    kind: {kind}")
    lines.append("    patterns:")
    lines += [f"      - {p!r}" for p in patterns]
    lines += [f"    {key}: {value}" for key, value in extra.items()]
    return "\n".join(lines) + "\n"


def write_pack(root: Path, files: dict[str, str], version: str = '"2026.09.0"') -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "pack.yaml").write_text(f"version: {version}\n", encoding="utf-8")
    for name, body in files.items():
        (root / name).write_text(body, encoding="utf-8")
    return root


def rules_file(*rules: str) -> str:
    return "rules:\n" + "".join(rules)


# --- Bundled pack ------------------------------------------------------------------------


def test_bundled_pack_loads() -> None:
    pack = load_rulepack()
    assert pack.version == "2026.09.7"
    assert len({rule.id for rule in pack.rules}) == len(pack.rules)


# --- Loading valid packs -----------------------------------------------------------------


def test_loads_rules_from_all_files_in_sorted_order(tmp_path: Path) -> None:
    pack = load_rulepack(
        write_pack(
            tmp_path,
            {
                "d2.yaml": rules_file(rule_yaml("D2-B", "keywords", ["b"], module="D2")),
                "d1.yaml": rules_file(
                    rule_yaml("D1-A", "keywords", ["a"]), rule_yaml("D1-C", "regex", ["c+"])
                ),
                "notes.txt": "ignored: not yaml",
            },
        )
    )
    assert pack.version == "2026.09.0"
    assert [rule.id for rule in pack.rules] == ["D1-A", "D1-C", "D2-B"]
    assert [rule.id for rule in pack.for_module(Module.D2)] == ["D2-B"]
    rule = pack.rules[0]
    assert rule.severity is Severity.HIGH
    assert rule.owasp == (Owasp.MCP03,)


def test_surfaces_default_to_the_whole_manifest(tmp_path: Path) -> None:
    pack = load_rulepack(
        write_pack(tmp_path, {"d1.yaml": rules_file(rule_yaml("D1-A", "keywords", ["a"]))})
    )
    assert pack.rules[0].surfaces == MANIFEST_SURFACES
    assert Surface.TARGET not in MANIFEST_SURFACES


def test_surfaces_can_be_limited(tmp_path: Path) -> None:
    rule = rule_yaml("D1-A", "keywords", ["a"], surfaces="[tools, target]")
    pack = load_rulepack(write_pack(tmp_path, {"d1.yaml": rules_file(rule)}))
    assert pack.rules[0].surfaces == (Surface.TOOLS, Surface.TARGET)


@pytest.mark.parametrize("surfaces", ["[]", "[toolz]"])
def test_invalid_surfaces_are_rejected(tmp_path: Path, surfaces: str) -> None:
    assert_rule_error(
        tmp_path,
        rule_yaml("D1-X", "keywords", ["x"], surfaces=surfaces),
        r"rule 'D1-X': surfaces",
    )


def test_min_entropy_is_optional_and_positive(tmp_path: Path) -> None:
    plain = rule_yaml("D4-A", "regex", ["a"], module="D4")
    strict = rule_yaml("D4-B", "regex", ["b"], module="D4", min_entropy="3.5")
    pack = load_rulepack(write_pack(tmp_path, {"d4.yaml": rules_file(plain, strict)}))
    assert [rule.min_entropy for rule in pack.rules] == [None, 3.5]


@pytest.mark.parametrize("value", ["0", "-1", "high"])
def test_invalid_min_entropy_is_rejected(tmp_path: Path, value: str) -> None:
    assert_rule_error(
        tmp_path,
        rule_yaml("D4-X", "regex", ["x"], module="D4", min_entropy=value),
        r"rule 'D4-X': min_entropy",
    )


def test_version_number_in_yaml_becomes_string(tmp_path: Path) -> None:
    assert load_rulepack(write_pack(tmp_path, {}, version="3")).version == "3"


def test_empty_pack_is_valid(tmp_path: Path) -> None:
    assert load_rulepack(write_pack(tmp_path, {})).rules == ()


# --- Matching ----------------------------------------------------------------------------


def load_one(tmp_path: Path, kind: str, patterns: list[str], **extra: str) -> RulePack:
    return load_rulepack(
        write_pack(tmp_path, {"d1.yaml": rules_file(rule_yaml("D1-X", kind, patterns, **extra))})
    )


def matches(pack: RulePack, text: str) -> list[str]:
    return [m.group(0) for m in pack.rules[0].finditer(text)]


def test_regex_rule_matches_case_insensitively_by_default(tmp_path: Path) -> None:
    pack = load_one(tmp_path, "regex", [r"ignore (all )?previous"])
    assert matches(pack, "Please IGNORE previous and ignore all previous.") == [
        "IGNORE previous",
        "ignore all previous",
    ]


def test_rule_exposes_compiled_pattern(tmp_path: Path) -> None:
    pack = load_one(tmp_path, "regex", ["abc"])
    assert pack.rules[0].pattern.search("xABCx") is not None


def test_regex_rule_can_be_case_sensitive(tmp_path: Path) -> None:
    pack = load_one(tmp_path, "regex", ["SECRET"], ignore_case="false")
    assert matches(pack, "secret SECRET") == ["SECRET"]


def test_keywords_match_whole_words_only(tmp_path: Path) -> None:
    pack = load_one(tmp_path, "keywords", ["api", "do not tell the user"])
    text = "Rapid api call. Do not tell the user."
    assert matches(pack, text) == ["api", "Do not tell the user"]


def test_keywords_are_literal_not_regex(tmp_path: Path) -> None:
    pack = load_one(tmp_path, "keywords", ["<IMPORTANT>", "a.b"])
    assert matches(pack, "x<important>y a.b axb") == ["<important>", "a.b"]


def test_codepoint_rule_matches_single_and_ranges(tmp_path: Path) -> None:
    pack = load_one(tmp_path, "codepoints", ["U+200B", "U+E0000-U+E007F"])
    text = "safe​word \U000e0041\U000e0042 end"
    assert matches(pack, text) == ["​", "\U000e0041\U000e0042"]


def test_codepoint_rule_ignores_normal_non_ascii(tmp_path: Path) -> None:
    pack = load_one(tmp_path, "codepoints", ["U+200B-U+200D"])
    # Urdu, CJK and emoji are ordinary text, not hidden characters.
    assert matches(pack, "زرہ 盔甲 🛡️") == []


# --- Errors ------------------------------------------------------------------------------


def test_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(RulePackError, match="rule pack directory not found"):
        load_rulepack(tmp_path / "nope")


def test_missing_pack_file(tmp_path: Path) -> None:
    with pytest.raises(RulePackError, match=r"pack\.yaml: must contain exactly one key"):
        load_rulepack(tmp_path)


@pytest.mark.parametrize("body", ["version: '1'\nextra: 2\n", "- 1\n", "", "version: ''\n"])
def test_invalid_pack_file(tmp_path: Path, body: str) -> None:
    tmp_path.joinpath("pack.yaml").write_text(body, encoding="utf-8")
    with pytest.raises(RulePackError, match=r"pack\.yaml"):
        load_rulepack(tmp_path)


def test_invalid_yaml_names_file(tmp_path: Path) -> None:
    write_pack(tmp_path, {"d1.yaml": "rules: [unclosed\n"})
    with pytest.raises(RulePackError, match=r"d1\.yaml: invalid YAML"):
        load_rulepack(tmp_path)


@pytest.mark.parametrize("body", ["rules: {}\n", "other: []\n", "rules: []\nextra: 1\n", "[]\n"])
def test_rule_file_must_hold_a_rules_list(tmp_path: Path, body: str) -> None:
    write_pack(tmp_path, {"d1.yaml": body})
    with pytest.raises(RulePackError, match=r"d1\.yaml: must contain exactly one key, 'rules'"):
        load_rulepack(tmp_path)


def assert_rule_error(tmp_path: Path, rule: str, message: str) -> None:
    write_pack(tmp_path, {"d1.yaml": rules_file(rule)})
    with pytest.raises(RulePackError, match=message):
        load_rulepack(tmp_path)


def test_bad_regex_names_file_and_rule(tmp_path: Path) -> None:
    assert_rule_error(
        tmp_path,
        rule_yaml("D1-BROKEN", "regex", ["(unclosed"]),
        r"d1\.yaml: rule 'D1-BROKEN': invalid regex",
    )


def test_id_prefix_must_match_module(tmp_path: Path) -> None:
    assert_rule_error(
        tmp_path,
        rule_yaml("D2-WRONG", "keywords", ["x"], module="D1"),
        r"rule 'D2-WRONG': id prefix 'D2' does not match module 'D1'",
    )


@pytest.mark.parametrize("rule_id", ["d1-lower", "D1_UNDERSCORE", "X1-BAD", "D1-", "D123-X"])
def test_id_format_is_enforced(tmp_path: Path, rule_id: str) -> None:
    assert_rule_error(tmp_path, rule_yaml(rule_id, "keywords", ["x"]), r"rule '.*': id")


@pytest.mark.parametrize(
    "patterns", [["U+ZZZZ"], ["200B"], ["U+200D-U+200B"], ["U+110000"], ["U+1-U+2-U+3"]]
)
def test_invalid_codepoints(tmp_path: Path, patterns: list[str]) -> None:
    assert_rule_error(
        tmp_path, rule_yaml("D1-CP", "codepoints", patterns), r"rule 'D1-CP': .*codepoint"
    )


def test_unknown_field_is_rejected(tmp_path: Path) -> None:
    assert_rule_error(
        tmp_path, rule_yaml("D1-X", "keywords", ["x"], severty="high"), r"rule 'D1-X': severty"
    )


def test_unknown_kind_is_rejected(tmp_path: Path) -> None:
    assert_rule_error(tmp_path, rule_yaml("D1-X", "glob", ["x"]), r"rule 'D1-X': kind")


def test_rule_without_id_is_named_by_position(tmp_path: Path) -> None:
    body = textwrap.dedent(
        """\
        rules:
          - module: D1
            kind: keywords
            patterns: [x]
        """
    )
    write_pack(tmp_path, {"d1.yaml": body})
    with pytest.raises(RulePackError, match=r"rule #1: id: Field required"):
        load_rulepack(tmp_path)


def test_rule_that_is_not_a_mapping(tmp_path: Path) -> None:
    write_pack(tmp_path, {"d1.yaml": "rules:\n  - just a string\n"})
    with pytest.raises(RulePackError, match=r"rule #1"):
        load_rulepack(tmp_path)


def test_empty_patterns_are_rejected(tmp_path: Path) -> None:
    assert_rule_error(tmp_path, rule_yaml("D1-X", "keywords", []), r"rule 'D1-X': patterns")


def test_duplicate_id_across_files_names_both(tmp_path: Path) -> None:
    write_pack(
        tmp_path,
        {
            "a.yaml": rules_file(rule_yaml("D1-SAME", "keywords", ["x"])),
            "b.yaml": rules_file(rule_yaml("D1-SAME", "keywords", ["y"])),
        },
    )
    with pytest.raises(RulePackError, match=r"b\.yaml: duplicate rule id 'D1-SAME' .*a\.yaml"):
        load_rulepack(tmp_path)
