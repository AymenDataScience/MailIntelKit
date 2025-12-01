#!/usr/bin/env python3
"""
email_security_check.py

This script serves as the entry point for running the email security check.
It utilizes the core logic and utilities from the email_security_check package
to extract and process SPF, DKIM, and DMARC information for a given domain.

Usage:
    python email_security_check.py example.com
"""

from email_security_check.cli import main

if __name__ == "__main__":
    main()