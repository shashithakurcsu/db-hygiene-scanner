"""
Configuration module for db-hygiene-scanner.

Uses pydantic-settings to load configuration from environment variables
with sensible defaults for banking-grade deployments.
"""

from typing import List, Literal, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class SecurityConfig(BaseSettings):
    """Security-related configuration for code sanitization."""

    strip_api_keys: bool = Field(default=True, description="Strip API keys before sending to AI")
    strip_connection_strings: bool = Field(default=True, description="Strip connection strings before sending to AI")
    strip_passwords: bool = Field(default=True, description="Strip passwords before sending to AI")
    default_patterns: List[str] = Field(
        default=[
            r"(?i)(api[_-]?key|apikey|access[_-]?key)\s*[=:]\s*['\"]?([a-zA-Z0-9\-_.]+)['\"]?",
            r"(?i)(connection[_-]?string|server|host)\s*[=:]\s*['\"]?([^'\";]+)['\"]?",
            r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([^'\";]+)['\"]?",
            r"AKIA[0-9A-Z]{16}",
            r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
        ],
        description="Regex patterns for detecting sensitive data in source code",
    )


class RateLimitConfig(BaseSettings):
    """Rate limiting configuration for AI API calls."""

    requests_per_minute: int = Field(default=30, description="Maximum API requests per minute")
    burst_size: int = Field(default=5, description="Maximum burst size for rate limiter")
    backoff_base_seconds: float = Field(default=1.0, description="Base delay for exponential backoff in seconds")


class Config(BaseSettings):
    """Main application configuration loaded from environment variables."""

    model_config = {"env_prefix": "", "case_sensitive": False}

    anthropic_api_key: str = Field(..., description="Anthropic API key for Claude AI integration")
    github_token: Optional[str] = Field(default=None, description="GitHub PAT for authenticated API calls")
    github_repo: Optional[str] = Field(default=None, description="Target repo in owner/repo format")
    github_reviewer: Optional[str] = Field(default=None, description="GitHub username for PR review assignment")
    scan_target_path: str = Field(default="/app/src", description="Local path to scan for violations")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO", description="Logging verbosity level"
    )
    ai_model_scan: str = Field(
        default="claude-sonnet-4-6", description="Claude model for scan classification"
    )
    ai_model_fix: str = Field(default="claude-opus-4-6", description="Claude model for fix generation")
    ai_model_review: str = Field(
        default="claude-opus-4-6", description="Claude model for security review"
    )
    max_file_size_kb: int = Field(default=500, gt=0, description="Maximum file size in KB to process")
    rate_limit_rpm: int = Field(default=30, gt=0, description="API rate limit: requests per minute")
    mongodb_platforms: List[str] = Field(
        default=["MONGODB", "EDB_YUGABYTE"],
        description="MongoDB variant identifiers for read preference checks",
    )
    security_strip_patterns: List[str] = Field(
        default_factory=list, description="Additional regex patterns to sanitize before AI calls"
    )

    @field_validator("anthropic_api_key")
    @classmethod
    def api_key_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("anthropic_api_key must not be empty")
        return v
