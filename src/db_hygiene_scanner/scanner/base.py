"""
Abstract base class for violation detectors.

All detectors in db-hygiene-scanner must inherit from BaseDetector
and implement the detect(), supports_language(), and supports_platform() methods.
"""

from abc import ABC, abstractmethod

import structlog

from db_hygiene_scanner.config import Config
from db_hygiene_scanner.models import DatabasePlatform, ProgrammingLanguage, Violation


class BaseDetector(ABC):
    """Abstract base class for violation detectors."""

    def __init__(self, config: Config, logger: structlog.BoundLogger) -> None:
        self.config = config
        self.logger = logger

    @abstractmethod
    def detect(self, file_path: str, content: str) -> list[Violation]:
        """Detect violations in the given file content.

        Args:
            file_path: Absolute path to the file being scanned.
            content: File contents as a string.

        Returns:
            List of Violation objects found in this file.
        """

    @abstractmethod
    def supports_language(self, language: ProgrammingLanguage) -> bool:
        """Return True if this detector can analyze this language."""

    @abstractmethod
    def supports_platform(self, platform: DatabasePlatform) -> bool:
        """Return True if this detector is relevant for this database platform."""

    def _extract_context(
        self, content: str, line_number: int, context_lines: int = 3
    ) -> tuple[list[str], list[str]]:
        """Extract context lines before and after a violation.

        Args:
            content: Full file content.
            line_number: 1-indexed line number of violation.
            context_lines: Number of lines to extract before/after.

        Returns:
            Tuple of (before_lines, after_lines).
        """
        lines = content.split("\n")
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        before = lines[start : line_number - 1]
        after = lines[line_number:end]
        return before, after
