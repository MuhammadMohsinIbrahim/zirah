"""D2 prompt injection, static rules: prompts, prompt arguments, resources and instructions.

The detections live in ``zirah/rules/d2_prompt_injection.yaml``.
"""

from __future__ import annotations

from zirah.analyzers.base import ScanContext
from zirah.analyzers.common import RuleAnalyzer
from zirah.models import Finding, Manifest, Module


class PromptInjection(RuleAnalyzer):
    name = "d2-prompt-injection"
    module = Module.D2

    def analyze(self, manifest: Manifest, ctx: ScanContext) -> list[Finding]:
        return self.match_rules(manifest, ctx)
