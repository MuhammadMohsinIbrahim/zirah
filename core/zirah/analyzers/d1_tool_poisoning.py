"""D1 tool poisoning, static rules: hidden text and instructions in what the model reads.

The detections live in ``zirah/rules/d1_tool_poisoning.yaml``.
"""

from __future__ import annotations

from zirah.analyzers.base import ScanContext
from zirah.analyzers.common import RuleAnalyzer
from zirah.models import Finding, Manifest, Module


class ToolPoisoning(RuleAnalyzer):
    name = "d1-tool-poisoning"
    module = Module.D1

    def analyze(self, manifest: Manifest, ctx: ScanContext) -> list[Finding]:
        return self.match_rules(manifest, ctx)
