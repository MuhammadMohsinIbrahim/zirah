"""JSON report: the ``ScanResult`` exactly as the data contract defines it."""

from __future__ import annotations

from zirah.scan import Scan


def render(scan: Scan) -> str:
    return scan.result.model_dump_json(indent=2) + "\n"
