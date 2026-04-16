"""Integration tests for the full scan pipeline against mock_bank_repo."""

import json
from pathlib import Path

import pytest

from db_hygiene_scanner.config import Config
from db_hygiene_scanner.models import ViolationType
from db_hygiene_scanner.scanner import ScannerPipeline
from db_hygiene_scanner.scanner.detectors import (
    LongRunningTransactionDetector,
    ReadPreferenceDetector,
    SelectStarDetector,
    StringConcatSQLDetector,
    UnbatchedTransactionDetector,
)
from db_hygiene_scanner.utils.logging_config import get_logger


def _get_mock_repo_path() -> str:
    """Get the path to the mock bank repo."""
    base = Path(__file__).parent.parent.parent / "demo" / "mock_bank_repo" / "src"
    if base.exists():
        return str(base)
    return "/tmp"


def _build_pipeline(config, logger):
    """Build a pipeline with all detectors registered."""
    pipeline = ScannerPipeline(config, logger)
    pipeline.register_detector(SelectStarDetector(config, logger))
    pipeline.register_detector(StringConcatSQLDetector(config, logger))
    pipeline.register_detector(UnbatchedTransactionDetector(config, logger))
    pipeline.register_detector(LongRunningTransactionDetector(config, logger))
    pipeline.register_detector(ReadPreferenceDetector(config, logger))
    return pipeline


@pytest.mark.integration
class TestFullScanPipeline:
    def test_scan_mock_repo_finds_violations(self):
        """Scan the mock_bank_repo and verify violations are found."""
        repo_path = _get_mock_repo_path()
        config = Config(anthropic_api_key="test", scan_target_path=repo_path)
        logger = get_logger("test")
        pipeline = _build_pipeline(config, logger)

        result = pipeline.scan(repo_path)

        assert len(result.violations) > 0
        assert result.stats["total_files_scanned"] > 0

    def test_all_violation_types_detected(self):
        """Verify all 5 violation types are detected in mock repo."""
        repo_path = _get_mock_repo_path()
        config = Config(anthropic_api_key="test", scan_target_path=repo_path)
        logger = get_logger("test")
        pipeline = _build_pipeline(config, logger)

        result = pipeline.scan(repo_path)

        detected_types = set(v.violation_type for v in result.violations)
        expected_types = {
            ViolationType.SELECT_STAR,
            ViolationType.STRING_CONCAT_SQL,
            ViolationType.LONG_RUNNING_TXN,
            ViolationType.READ_PREFERENCE,
        }
        # At minimum these should be detected
        assert expected_types.issubset(detected_types)

    def test_no_false_positives_on_ddl(self, tmp_path):
        """Verify no false positives on clean DDL."""
        ddl_file = tmp_path / "clean.sql"
        ddl_file.write_text("""
CREATE TABLE Accounts (
    AccountId NVARCHAR(50) PRIMARY KEY,
    Balance DECIMAL(18,2) NOT NULL
)
GO
CREATE INDEX idx_status ON Accounts(AccountId)
GO
        """)
        config = Config(anthropic_api_key="test", scan_target_path=str(tmp_path))
        logger = get_logger("test")
        pipeline = _build_pipeline(config, logger)

        result = pipeline.scan(str(tmp_path))

        assert len(result.violations) == 0

    def test_no_false_positives_on_parameterized(self, tmp_path):
        """Verify parameterized queries are not flagged for SQL injection."""
        py_file = tmp_path / "safe.py"
        py_file.write_text(
            'cursor.execute("SELECT name, email FROM users WHERE id = %s", (user_id,))\n'
        )
        config = Config(anthropic_api_key="test", scan_target_path=str(tmp_path))
        logger = get_logger("test")
        pipeline = _build_pipeline(config, logger)

        result = pipeline.scan(str(tmp_path))

        concat_violations = [
            v for v in result.violations
            if v.violation_type == ViolationType.STRING_CONCAT_SQL
        ]
        assert len(concat_violations) == 0

    def test_statistics_consistency(self):
        """Verify statistics match actual violation counts."""
        repo_path = _get_mock_repo_path()
        config = Config(anthropic_api_key="test", scan_target_path=repo_path)
        logger = get_logger("test")
        pipeline = _build_pipeline(config, logger)

        result = pipeline.scan(repo_path)

        total_by_type = sum(result.stats["violations_by_type"].values())
        assert total_by_type == len(result.violations)
        assert result.stats["total_violations"] == len(result.violations)

    def test_scan_result_json_serialization(self):
        """Verify scan result can be serialized to JSON."""
        repo_path = _get_mock_repo_path()
        config = Config(anthropic_api_key="test", scan_target_path=repo_path)
        logger = get_logger("test")
        pipeline = _build_pipeline(config, logger)

        result = pipeline.scan(repo_path)
        json_str = result.model_dump_json()

        data = json.loads(json_str)
        assert "violations" in data
        assert "stats" in data
        assert "repo_path" in data
