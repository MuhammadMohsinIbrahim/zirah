"""What ships to PyPI: the package's own license copy, README and version metadata."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
from conftest import REPO_ROOT, in_repo_checkout

from zirah import __version__

CORE = Path(__file__).resolve().parents[1]
ROOT = CORE.parent


@pytest.mark.repo_checkout
def test_packaged_license_is_the_repository_license() -> None:
    # Hatch only packages files under core/, so LICENSE is copied there; keep it identical.
    assert (CORE / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()


def test_version_has_one_source() -> None:
    project = tomllib.loads((CORE / "pyproject.toml").read_text(encoding="utf-8"))
    assert "version" not in project["project"]
    assert project["project"]["dynamic"] == ["version"]
    assert project["tool"]["hatch"]["version"]["path"] == "zirah/__init__.py"
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:(?:a|b|rc)\d+|\.dev\d+)?", __version__)


def test_pypi_readme_links_are_absolute() -> None:
    # PyPI renders the README without the repository, so relative links and images break.
    readme = (CORE / "README.md").read_text(encoding="utf-8")
    targets = re.findall(r"\]\(([^)\s]+)", readme)
    assert targets
    assert all(t.startswith(("https://", "#")) for t in targets), targets


@pytest.mark.repo_checkout
def test_changelog_has_a_section_for_this_version() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    heading = rf"^## \[{re.escape(__version__)}\] - \d{{4}}-\d{{2}}-\d{{2}}$"
    assert re.search(heading, changelog, re.MULTILINE)


def test_repository_checkout_is_detected() -> None:
    # Guards the repo_checkout skips: inside the repository (where examples/ exists) they
    # must never skip.
    assert in_repo_checkout() == (REPO_ROOT / "examples").is_dir()
    assert REPO_ROOT == ROOT
