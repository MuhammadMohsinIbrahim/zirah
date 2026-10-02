"""Shared test setup.

Tests marked ``repo_checkout`` read files from the repository root (``examples/``,
``LICENSE``, ``CHANGELOG.md``), which the sdist does not ship. They are skipped only when the
tests are not inside the Zirah repository; inside it they always run, and a missing file is
a failure, not a skip.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
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
