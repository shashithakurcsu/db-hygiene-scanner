import pytest
from db_hygiene_scanner.scanner.detectors.select_star import SelectStarDetector
from db_hygiene_scanner.models import ViolationType, Severity

class TestSelectStarDetector:
    @pytest.fixture
    def detector(self, mock_config, mock_logger):
        return SelectStarDetector(mock_config, mock_logger)

    def test_basic_select_star(self, detector):
        v = detector.detect("test.sql", "SELECT * FROM users;")
        assert len(v) == 1
        assert v[0].violation_type == ViolationType.SELECT_STAR

    def test_count_star_not_flagged(self, detector):
        v = detector.detect("test.sql", "SELECT COUNT(*) FROM users;")
        assert len(v) == 0

    def test_exists_select_star_not_flagged(self, detector):
        v = detector.detect("test.sql", "IF EXISTS(SELECT * FROM t) BEGIN END")
        assert len(v) == 0

    def test_explicit_columns_not_flagged(self, detector):
        v = detector.detect("test.sql", "SELECT id, name FROM users;")
        assert len(v) == 0

    def test_csharp_select_star(self, detector):
        code = 'var cmd = new SqlCommand("SELECT * FROM customers", conn);'
        v = detector.detect("test.cs", code)
        assert len(v) == 1
        assert v[0].language.value == "C#"

    def test_java_select_star(self, detector):
        code = 'String sql = "SELECT * FROM customers";'
        v = detector.detect("test.java", code)
        assert len(v) == 1

    def test_python_select_star(self, detector):
        code = 'cursor.execute("SELECT * FROM customers")'
        v = detector.detect("test.py", code)
        assert len(v) == 1

    def test_multiple_select_star(self, detector):
        code = '"SELECT * FROM a"\n"SELECT * FROM b"\n"SELECT * FROM c"'
        v = detector.detect("test.py", code)
        assert len(v) == 3

    def test_severity_is_high(self, detector):
        v = detector.detect("test.sql", "SELECT * FROM users;")
        assert v[0].severity == Severity.HIGH
