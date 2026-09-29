"""``python -m desktop`` -> the ProShield desktop application."""
from __future__ import annotations

import sys

from desktop.main import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))