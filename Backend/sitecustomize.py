"""Test/Dev helper.

Python automatically imports `sitecustomize` if it exists on sys.path.
We use it to ensure the Backend package root is on sys.path so that
`import app.*` works reliably under pytest/IDE runners.

This file is intentionally minimal and has no runtime effect outside dev/test.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

