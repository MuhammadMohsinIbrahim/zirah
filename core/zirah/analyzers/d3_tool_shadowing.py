"""D3 tool shadowing, static rules for a single manifest.

The detections live in ``zirah/rules/d3_tool_shadowing.yaml``. A match that names a tool
(regex group ``tool``) only counts when that tool is not in the same manifest, so tools that
mention themselves or their siblings in plain usage stay clean.
"""

from __future__ import annotations

import re

from zirah.analyzers.base import ScanContext
from zirah.analyzers.common import RuleAnalyzer, TextField
from zirah.models import Finding, Manifest, Module
from zirah.rulepack import Rule


class ToolShadowing(RuleAnalyzer):
    name = "d3-tool-shadowing"
    module = Module.D3

    def analyze(self, manifest: Manifest, ctx: ScanContext) -> list[Finding]:
        return self.match_rules(manifest, ctx)

    def accept(
        self, rule: Rule, match: re.Match[str], field: TextField, manifest: Manifest
    ) -> bool:
        named = match.groupdict().get("tool")
        if named is None:
            return True
        return named.casefold() not in {tool.name.casefold() for tool in manifest.tools}
