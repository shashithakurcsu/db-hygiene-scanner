"""
Security utilities for db-hygiene-scanner.

Provides code sanitization, AI-generated fix validation, hashing,
and sensitive data masking for banking-grade security.
"""

import hashlib
import re
from typing import Any

from db_hygiene_scanner.config import SecurityConfig
from db_hygiene_scanner.utils.logging_config import get_logger

logger = get_logger("security")


def sanitize_code(code: str, config: SecurityConfig) -> tuple[str, list[tuple[str, str]]]:
    """Sanitize source code by stripping sensitive data before sending to AI.

    Args:
        code: Source code string to sanitize.
        config: SecurityConfig with sanitization rules.

    Returns:
        Tuple of (sanitized_code, list of (pattern_name, stripped_value) pairs).
    """
    sanitized = code
    stripped_items: list[tuple[str, str]] = []

    for pattern_str in config.default_patterns:
        try:
            pattern = re.compile(pattern_str)
            matches = pattern.findall(sanitized)
            if matches:
                for match in matches:
                    match_str = match if isinstance(match, str) else match[-1] if match else ""
                    if match_str:
                        stripped_items.append((pattern_str[:30], match_str))
                sanitized = pattern.sub("***REDACTED***", sanitized)
        except re.error:
            logger.warning("invalid_security_pattern", pattern=pattern_str)

    if stripped_items:
        logger.info("code_sanitized", patterns_matched=len(stripped_items))

    return sanitized, stripped_items


def validate_ai_generated_fix(
    original_code: str, fixed_code: str, language: str
) -> tuple[bool, list[str]]:
    """Validate an AI-generated fix for security issues.

    Args:
        original_code: The original problematic code.
        fixed_code: The proposed fix from AI.
        language: Programming language of the code.

    Returns:
        Tuple of (is_valid, list of security issues found).
    """
    issues: list[str] = []

    # Python injection patterns
    dangerous_python = [
        (r"\beval\s*\(", "Dangerous eval() call detected - potential code injection"),
        (r"\bexec\s*\(", "Dangerous exec() call detected - potential code injection"),
        (r"\b__import__\s*\(", "Dangerous __import__() call detected"),
    ]

    # Shell injection patterns
    dangerous_shell = [
        (r"\bsystem\s*\(", "Dangerous system() call detected - potential shell injection"),
        (r"\bshell_exec\s*\(", "Dangerous shell_exec() call detected"),
        (r"subprocess\.\w+\([^)]*shell\s*=\s*True", "subprocess with shell=True detected"),
    ]

    # Credential patterns
    credential_patterns = [
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']+["\']', "Hardcoded credential detected in fix"),
        (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9]+", "Hardcoded API key detected in fix"),
    ]

    # SQL injection patterns in fix
    sql_dangerous = [
        (r"(?i)\b(EXECUTE|EXEC)\s+\(.*\+", "Suspicious EXEC with concatenation in fix"),
        (r"/\*.*\*/", "SQL block comment detected - could hide injection"),
    ]

    all_patterns = dangerous_python + dangerous_shell + credential_patterns + sql_dangerous

    for pattern_str, description in all_patterns:
        if re.search(pattern_str, fixed_code):
            issues.append(description)

    is_valid = len(issues) == 0

    if not is_valid:
        logger.warning("fix_validation_failed", issues=issues)

    return is_valid, issues


def compute_code_hash(code: str) -> str:
    """Compute SHA-256 hash of code for audit trail.

    Args:
        code: Code string to hash.

    Returns:
        Hex digest of the SHA-256 hash.
    """
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def mask_sensitive_fields(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively mask values of keys that contain sensitive identifiers.

    Args:
        data: Dictionary to mask (typically from logs or reports).

    Returns:
        New dictionary with sensitive values replaced by ***REDACTED***.
    """
    sensitive_keywords = {"password", "token", "key", "secret", "credential", "passwd", "pwd"}
    masked: dict[str, Any] = {}

    for k, v in data.items():
        key_lower = k.lower()
        if any(keyword in key_lower for keyword in sensitive_keywords):
            masked[k] = "***REDACTED***"
        elif isinstance(v, dict):
            masked[k] = mask_sensitive_fields(v)
        else:
            masked[k] = v

    return masked
