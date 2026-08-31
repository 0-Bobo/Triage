#!/usr/bin/env python3
"""
Triage — CTF Binary Analysis Workbench (Web Edition)
FastAPI-powered web wrapper for CTF binary triage.

Usage:
    python main.py [binary] [--host HOST] [--port PORT]
    python -m triage_web [binary] [--host HOST] [--port PORT]
"""
import sys
import os

# Ensure the package directory is importable
_pkg_dir = os.path.dirname(os.path.abspath(__file__))
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)

from triage_web.server import main

if __name__ == '__main__':
    main()
