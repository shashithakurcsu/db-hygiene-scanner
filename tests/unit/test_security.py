import pytest
from db_hygiene_scanner.utils.security import (
    sanitize_code, validate_ai_generated_fix, compute_code_hash, mask_sensitive_fields
)
from db_hygiene_scanner.config import SecurityConfig

class TestSecurityUtilities:
    @pytest.fixture
    def security_config(self):
        return SecurityConfig()

    def test_sanitize_strips_passwords(self, security_config):
        code = 'password = "secret123"'
        sanitized, stripped = sanitize_code(code, security_config)
        assert "secret123" not in sanitized

    def test_validate_rejects_eval(self):
        is_valid, issues = validate_ai_generated_fix("original", "eval(user_input)", "python")
        assert not is_valid
        assert any("eval" in i.lower() for i in issues)

    def test_validate_rejects_exec(self):
        is_valid, issues = validate_ai_generated_fix("original", "exec(sql_string)", "python")
        assert not is_valid

    def test_validate_accepts_safe_code(self):
        is_valid, issues = validate_ai_generated_fix(
            "original", 'cursor.execute("SELECT id FROM users WHERE id = %s", (uid,))', "python"
        )
        assert is_valid
        assert len(issues) == 0

    def test_hash_consistency(self):
        code = "SELECT * FROM users"
        h1 = compute_code_hash(code)
        h2 = compute_code_hash(code)
        assert h1 == h2
        assert len(h1) == 64

    def test_mask_sensitive_fields(self):
        data = {"username": "john", "password": "secret", "api_key": "sk-123"}
        masked = mask_sensitive_fields(data)
        assert masked["password"] == "***REDACTED***"
        assert masked["api_key"] == "***REDACTED***"
        assert masked["username"] == "john"
