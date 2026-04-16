"""Vercel serverless entry point for db-hygiene-scanner web UI."""

import os
import sys
from pathlib import Path

# Ensure ANTHROPIC_API_KEY is set (even if dummy) to avoid config errors
if not os.environ.get("ANTHROPIC_API_KEY"):
    os.environ["ANTHROPIC_API_KEY"] = "disabled"

# Add src to path so imports work
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from db_hygiene_scanner.web.app import app
