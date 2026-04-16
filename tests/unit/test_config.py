import pytest
from db_hygiene_scanner.config import Config

class TestConfiguration:
    def test_default_values(self):
        config = Config(anthropic_api_key="sk-test")
        assert config.log_level == "INFO"
        assert config.ai_model_scan == "claude-sonnet-4-6"
        assert config.rate_limit_rpm == 30

    def test_custom_values(self):
        config = Config(anthropic_api_key="sk-test", log_level="DEBUG", rate_limit_rpm=10)
        assert config.log_level == "DEBUG"
        assert config.rate_limit_rpm == 10

    def test_empty_api_key_rejected(self):
        with pytest.raises(ValueError):
            Config(anthropic_api_key="")

    def test_scan_target_path_default(self):
        config = Config(anthropic_api_key="sk-test")
        assert config.scan_target_path == "/app/src"
