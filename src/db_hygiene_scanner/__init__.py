"""
db-hygiene-scanner: Automated database hygiene violation detection and remediation.

This tool scans codebases for Transaction & Query Management hygiene violations
across MSSQL, Oracle, MongoDB, and EDB/Yugabyte databases, with support for
C#/.NET, Java, and Python source code.
"""

__version__ = "0.1.0-alpha"
__author__ = "DB Hygiene Scanner Team"

from db_hygiene_scanner.models import Violation, Fix, ScanResult, Report

__all__ = ["Violation", "Fix", "ScanResult", "Report", "__version__"]
