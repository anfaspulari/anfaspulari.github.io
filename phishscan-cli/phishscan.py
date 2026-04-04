#!/usr/bin/env python3
"""
PhishScan — CLI entry point.

This file delegates to the v2 intelligence engine (main.py).
All detection logic, API calls, and reporting live in main.py.

Usage:
    python phishscan.py <email.eml>
    python phishscan.py <email.eml> --verbose
    python phishscan.py <email.eml> --json
    python phishscan.py <email.eml> --no-api
    python phishscan.py --test-apis
"""

from main import main

if __name__ == '__main__':
    main()
