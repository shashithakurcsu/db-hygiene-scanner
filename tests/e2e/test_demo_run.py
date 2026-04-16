"""End-to-end tests for CLI commands."""

import json
import subprocess
from pathlib import Path

import pytest


@pytest.mark.e2e
class TestCLICommands:
    def test_version_command(self):
        """Test db-hygiene-scanner version command."""
        result = subprocess.run(
            ["python", "-m", "db_hygiene_scanner.cli", "version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "0.1.0-alpha" in result.stdout

    def test_scan_command_on_mock_repo(self):
        """Test scan command on the mock bank repo."""
        mock_repo = Path(__file__).parent.parent.parent / "demo" / "mock_bank_repo" / "src"
        if not mock_repo.exists():
            pytest.skip("Mock repo not available")

        result = subprocess.run(
            ["python", "-m", "db_hygiene_scanner.cli", "scan", str(mock_repo)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0
        assert "Detected Violations" in result.stdout or "No violations" in result.stdout

    def test_scan_with_json_output(self, tmp_path):
        """Test scan with JSON file output."""
        mock_repo = Path(__file__).parent.parent.parent / "demo" / "mock_bank_repo" / "src"
        if not mock_repo.exists():
            pytest.skip("Mock repo not available")

        output_file = tmp_path / "scan-results.json"
        result = subprocess.run(
            [
                "python", "-m", "db_hygiene_scanner.cli", "scan",
                str(mock_repo), "--output-file", str(output_file),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0
        assert output_file.exists()

        data = json.loads(output_file.read_text())
        assert "violations" in data
        assert "stats" in data

    def test_demo_command(self):
        """Test demo command runs successfully."""
        mock_repo = Path(__file__).parent.parent.parent / "demo" / "mock_bank_repo" / "src"
        if not mock_repo.exists():
            pytest.skip("Mock repo not available")

        result = subprocess.run(
            [
                "python", "-m", "db_hygiene_scanner.cli", "demo",
                "--repo-path", str(mock_repo),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0
        assert "Demo complete" in result.stdout or "demo" in result.stdout.lower()

    def test_help_command(self):
        """Test help displays all commands."""
        result = subprocess.run(
            ["python", "-m", "db_hygiene_scanner.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "scan" in result.stdout
        assert "fix" in result.stdout
        assert "report" in result.stdout
        assert "demo" in result.stdout
        assert "version" in result.stdout
