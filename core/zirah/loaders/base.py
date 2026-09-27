"""Types shared by all loaders."""

from __future__ import annotations

from dataclasses import dataclass

from zirah.models import Manifest, Target


class LoaderError(Exception):
    """A target could not be loaded. The message is meant for the user, not a traceback."""


@dataclass(frozen=True, slots=True)
class Loaded:
    """What a loader produces: the target as it will appear in reports, and its manifest."""

    target: Target
    manifest: Manifest
