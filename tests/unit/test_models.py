import pytest
from datetime import datetime
from db_hygiene_scanner.models import (
    Violation, Fix, ScanResult, Report,
    ViolationType, Severity, DatabasePlatform, ProgrammingLanguage,
)

class TestModels:
    def test_violation_creation(self):
        v = Violation(
            file_path="test.py", line_number=1, line_content="SELECT * FROM t",
            violation_type=ViolationType.SELECT_STAR, severity=Severity.HIGH,
            platform=DatabasePlatform.MSSQL, language=ProgrammingLanguage.PYTHON,
            description="Test violation", confidence_score=0.95,
        )
        assert v.violation_type == ViolationType.SELECT_STAR
        assert v.line_number == 1

    def test_violation_empty_path_rejected(self):
        with pytest.raises(ValueError):
            Violation(
                file_path="  ", line_number=1, line_content="content",
                violation_type=ViolationType.SELECT_STAR, severity=Severity.HIGH,
                platform=DatabasePlatform.MSSQL, language=ProgrammingLanguage.PYTHON,
                description="desc", confidence_score=0.9,
            )

    def test_scan_result_creation(self):
        sr = ScanResult(repo_path="/app/src", violations=[], stats={"total": 0})
        assert sr.repo_path == "/app/src"
        assert len(sr.violations) == 0

    def test_fix_creation(self):
        v = Violation(
            file_path="t.py", line_number=1, line_content="bad",
            violation_type=ViolationType.SELECT_STAR, severity=Severity.HIGH,
            platform=DatabasePlatform.MSSQL, language=ProgrammingLanguage.PYTHON,
            description="d", confidence_score=0.9,
        )
        f = Fix(
            violation_id="v1", violation=v, original_code="bad", fixed_code="good",
            explanation="fixed", ai_model_used="claude", confidence_score=0.9,
        )
        assert f.fixed_code == "good"

    def test_violation_type_enum(self):
        assert ViolationType.SELECT_STAR.value == "SELECT_STAR"
        assert ViolationType.STRING_CONCAT_SQL.value == "STRING_CONCAT_SQL"

    def test_json_serialization(self):
        sr = ScanResult(repo_path="/app", violations=[], stats={})
        j = sr.model_dump_json()
        assert "repo_path" in j
