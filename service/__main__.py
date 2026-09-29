"""``python -m service`` -> the ProShield Windows Service host."""
from __future__ import annotations

import sys

from service.windows_service import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
