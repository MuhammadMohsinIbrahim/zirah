"""Smoke-test an installed Zirah in the release workflow. Standard library only.

    python release_smoke.py VERSION ZIRAH_COMMAND...

ZIRAH_COMMAND is how to run the installed CLI, e.g. ``zirah`` or ``.smoke/bin/python -m zirah``.
Run from the repository root: it scans the demos in ``examples/``.
"""

from __future__ import annotations

import subprocess
import sys

CHECKS = [
    # (arguments, expected exit code, text the output must contain)
    (["--version"], 0, "zirah {version}"),
    (["scan", "examples/benign/manifest.json"], 0, "Trust score 100/100"),
    (["scan", "examples/malicious/manifest.json"], 1, "Trust score 0/100"),
]


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: release_smoke.py VERSION ZIRAH_COMMAND...", file=sys.stderr)
        return 2
    version, command = sys.argv[1], sys.argv[2:]
    failed = False
    for args, code, expected in CHECKS:
        done = subprocess.run(  # noqa: S603 - the CLI under test
            [*command, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        output = " ".join((done.stdout + done.stderr).split())
        want = expected.format(version=version)
        ok = done.returncode == code and want in output
        failed |= not ok
        print(f"{'ok  ' if ok else 'FAIL'} zirah {' '.join(args)}: exit {done.returncode}")
        if not ok:
            print(f"     expected exit {code} and {want!r}; output:\n{done.stdout}{done.stderr}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
