"""D1, D2 and D3 semantic checks by the optional LLM judge (``--llm ...``).

The judge itself lives in ``zirah.judge``; these analyzers only hand each module its share of
the verdicts. They run only when an LLM is configured.
"""

from __future__ import annotations

from abc import ABC

from zirah.analyzers.base import Analyzer, ScanContext
from zirah.models import Engine, Finding, Manifest, Module


class _JudgeAnalyzer(Analyzer, ABC):
    engine = Engine.LLM

    def judged(self, manifest: Manifest, ctx: ScanContext) -> list[Finding]:
        if ctx.judge is None:
            return []
        return ctx.judge.findings_for(self.module, manifest)


class ToolPoisoningJudge(_JudgeAnalyzer):
    name = "d1-llm-judge"
    module = Module.D1

    def analyze(self, manifest: Manifest, ctx: ScanContext) -> list[Finding]:
        return self.judged(manifest, ctx)


class PromptInjectionJudge(_JudgeAnalyzer):
    name = "d2-llm-judge"
    module = Module.D2

    def analyze(self, manifest: Manifest, ctx: ScanContext) -> list[Finding]:
        return self.judged(manifest, ctx)


class ToolShadowingJudge(_JudgeAnalyzer):
    name = "d3-llm-judge"
    module = Module.D3

    def analyze(self, manifest: Manifest, ctx: ScanContext) -> list[Finding]:
        return self.judged(manifest, ctx)
