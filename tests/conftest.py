"""Shared test fixtures for db-hygiene-scanner."""

import os

import pytest

from db_hygiene_scanner.config import Config
from db_hygiene_scanner.utils.logging_config import get_logger


@pytest.fixture
def mock_config():
    """Provide a mock configuration for testing."""
    return Config(
        anthropic_api_key="test-key",
        scan_target_path="/tmp",
        log_level="DEBUG",
        ai_model_scan="claude-sonnet-4-6",
        ai_model_fix="claude-opus-4-6",
        ai_model_review="claude-opus-4-6",
        max_file_size_kb=500,
        rate_limit_rpm=30,
    )


@pytest.fixture
def mock_logger():
    """Provide a mock logger."""
    return get_logger("test")


def pytest_collection_modifyitems(config, items):
    """Skip tests that require API key or GitHub token if not available."""
    skip_api = pytest.mark.skip(reason="requires ANTHROPIC_API_KEY")
    skip_github = pytest.mark.skip(reason="requires GITHUB_TOKEN")

    for item in items:
        if "requires_api" in item.keywords and not os.getenv("ANTHROPIC_API_KEY"):
            item.add_marker(skip_api)
        if "requires_github" in item.keywords and not os.getenv("GITHUB_TOKEN"):
            item.add_marker(skip_github)
