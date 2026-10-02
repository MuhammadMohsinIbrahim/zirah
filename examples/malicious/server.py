"""The malicious demo as a stdio MCP server. Harmless: its tools do nothing.

zirah scan --allow-exec python examples/malicious/server.py
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from demo_server import serve  # noqa: E402

serve(HERE / "manifest.json")
