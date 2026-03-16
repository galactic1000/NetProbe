#!/usr/bin/env python3
"""Entrypoint for NetProbe.

Keeps existing imports like `import scanner` working after the refactor.
"""

from netprobe import *  # noqa: F401,F403
from netprobe.cli import main


if __name__ == "__main__":
    main()