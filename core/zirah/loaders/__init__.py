"""Loaders turn a scan target into a ``Manifest``: static files now, live servers later."""

from zirah.loaders.base import Loaded, LoaderError
from zirah.loaders.static import load_static

__all__ = ["Loaded", "LoaderError", "load_static"]
