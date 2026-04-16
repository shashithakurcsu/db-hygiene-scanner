import pytest
from db_hygiene_scanner.scanner.detectors.string_concat_sql import StringConcatSQLDetector
from db_hygiene_scanner.models import ViolationType, Severity

class TestStringConcatSQLDetector:
    @pytest.fixture
    def detector(self, mock_config, mock_logger):
        return StringConcatSQLDetector(mock_config, mock_logger)

    def test_python_fstring(self, detector):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        v = detector.detect("test.py", code)
        assert len(v) >= 1
        assert v[0].severity == Severity.CRITICAL

    def test_csharp_string_interpolation(self, detector):
        code = '$"SELECT * FROM users WHERE id = {userId}"'
        v = detector.detect("test.cs", code)
        assert len(v) >= 1

    def test_mybatis_unsafe(self, detector):
        code = "WHERE loan_id = ${loanId}"
        v = detector.detect("test.xml", code)
        assert len(v) >= 1

    def test_parameterized_not_flagged(self, detector):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        v = detector.detect("test.py", code)
        # Should not flag parameterized queries for concat
        # (may flag SELECT * via different detector)
        concat_violations = [x for x in v if x.violation_type == ViolationType.STRING_CONCAT_SQL]
        assert len(concat_violations) == 0

    def test_sql_exec_concat(self, detector):
        code = "EXEC('SELECT * FROM users WHERE id = ' + @id)"
        v = detector.detect("test.sql", code)
        assert len(v) >= 1
        assert v[0].severity == Severity.CRITICAL
