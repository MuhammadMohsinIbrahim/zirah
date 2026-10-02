"""What ships to PyPI: the package's own license copy, README and version metadata."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from zirah import __version__

CORE = Path(__file__).resolve().parents[1]
ROOT = CORE.parent


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


def test_changelog_has_a_section_for_this_version() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    heading = rf"^## \[{re.escape(__version__)}\] - \d{{4}}-\d{{2}}-\d{{2}}$"
    assert re.search(heading, changelog, re.MULTILINE)
