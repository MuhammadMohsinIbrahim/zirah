"""Shared test setup.

Tests marked ``repo_checkout`` read files from the repository root (``examples/``,
``LICENSE``, ``CHANGELOG.md``), which the sdist does not ship. They are skipped only when the
tests are not inside the Zirah repository; inside it they always run, and a missing file is
a failure, not a skip.

Terminal output is rendered at a pinned width (``COLUMNS``), so where lines wrap is the same
on every OS, checkout path and developer shell. Checks on rendered text use :func:`flat`
(phrases that may span a line break) and :func:`squashed` (secrets that must not appear,
even folded across lines).
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_COLUMNS = "100"
"""Console width for CLI output in tests; the same as ``terminal.REPORT_WIDTH``."""


@pytest.fixture(autouse=True)
def pinned_console_width(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rich reads ``COLUMNS`` when output is not a terminal (as under ``CliRunner``)."""
    monkeypatch.setenv("COLUMNS", TEST_COLUMNS)


def flat(text: str) -> str:
    """``text`` with every run of whitespace collapsed to one space.

    For positive checks of phrases that may wrap: ``"Trust score 100/100" in flat(out)``.
    """
    return " ".join(text.split())


def squashed(text: str) -> str:
    """``text`` with all whitespace removed.

    For negative secret checks: ``squashed(secret) not in squashed(out)`` also catches a
    secret that was folded across a line break.
    """
    return "".join(text.split())


SKIP_REASON = (
    "needs the Zirah repository checkout (examples/, LICENSE, CHANGELOG.md), which an "
    "unpacked sdist does not include"
)


def in_repo_checkout() -> bool:
    """Whether these tests sit in the Zirah repository rather than an unpacked sdist."""
    workspace = REPO_ROOT / "pyproject.toml"
    return workspace.is_file() and 'name = "zirah-workspace"' in workspace.read_text(
        encoding="utf-8"
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", f"repo_checkout: {SKIP_REASON}; skipped outside it")


def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("repo_checkout") is not None and not in_repo_checkout():
        pytest.skip(SKIP_REASON)
