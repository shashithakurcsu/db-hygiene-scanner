"""READ_PREFERENCE violation detector.

MongoDB-specific: detects missing or misconfigured read preference settings.
"""

import re
from datetime import datetime

import structlog

from db_hygiene_scanner.config import Config
from db_hygiene_scanner.models import (
    DatabasePlatform,
    ProgrammingLanguage,
    Severity,
    Violation,
    ViolationType,
)
from db_hygiene_scanner.scanner.base import BaseDetector


class ReadPreferenceDetector(BaseDetector):
    """Detects MongoDB read preference misconfigurations."""

    def __init__(self, config: Config, logger: structlog.BoundLogger) -> None:
        super().__init__(config, logger)
        self.violation_type = ViolationType.READ_PREFERENCE

        # Python patterns
        self.python_mongoclient = re.compile(
            r"MongoClient\s*\(", re.IGNORECASE
        )

        # Java patterns
        self.java_mongoclient = re.compile(
            r"MongoClient(?:Settings)?\.(?:create|from)\s*\(", re.IGNORECASE
        )

        # C# patterns
        self.csharp_mongoclient = re.compile(
            r"new\s+MongoClient\s*\(", re.IGNORECASE
        )

    def supports_language(self, language: ProgrammingLanguage) -> bool:
        return language in [
            ProgrammingLanguage.PYTHON,
            ProgrammingLanguage.JAVA,
            ProgrammingLanguage.CSHARP,
        ]

    def supports_platform(self, platform: DatabasePlatform) -> bool:
        return platform in [DatabasePlatform.MONGODB, DatabasePlatform.EDB_YUGABYTE]

    def detect(self, file_path: str, content: str) -> list[Violation]:
        """Detect MongoDB read preference misconfigurations."""
        violations: list[Violation] = []

        if not self._is_mongodb_file(content, file_path):
            return violations

        lines = content.split("\n")
        language = self._detect_language(file_path)

        for line_num, line in enumerate(lines, 1):
            matched = False
            issue_desc = ""

            line_lower = line.lower()

            if language == ProgrammingLanguage.PYTHON:
                if self.python_mongoclient.search(line):
                    if "read_preference" not in line_lower and "readpreference" not in line_lower:
                        matched = True
                        issue_desc = (
                            "MongoClient created without read_preference. "
                            "Specify read_preference for replicated deployments."
                        )

            elif language == ProgrammingLanguage.JAVA:
                if self.java_mongoclient.search(line):
                    if "readpreference" not in line_lower:
                        matched = True
                        issue_desc = (
                            "MongoClient without readPreference configuration. "
                            "Add ReadPreference to route reads appropriately."
                        )

            elif language == ProgrammingLanguage.CSHARP:
                if self.csharp_mongoclient.search(line):
                    if "readpreference" not in line_lower:
                        matched = True
                        issue_desc = (
                            "MongoClient without ReadPreference. "
                            "Configure ReadPreference for optimal read distribution."
                        )

            if matched:
                before, after = self._extract_context(content, line_num)

                violation = Violation(
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line.strip(),
                    violation_type=self.violation_type,
                    severity=Severity.HIGH,
                    platform=DatabasePlatform.MONGODB,
                    language=language,
                    description=issue_desc,
                    context_before=before,
                    context_after=after,
                    confidence_score=0.90,
                    created_at=datetime.utcnow(),
                )
                violations.append(violation)
                self.logger.warning("read_preference_missing", file_path=file_path, line=line_num)

        return violations

    def _is_mongodb_file(self, content: str, file_path: str) -> bool:
        """Check if this file is related to MongoDB."""
        content_lower = content.lower()
        return (
            "mongoclient" in content_lower
            or "pymongo" in content_lower
            or "mongodb" in file_path.lower()
            or "mongo" in file_path.lower()
        )

    def _detect_language(self, file_path: str) -> ProgrammingLanguage:
        if file_path.endswith(".cs"):
            return ProgrammingLanguage.CSHARP
        if file_path.endswith(".java"):
            return ProgrammingLanguage.JAVA
        if file_path.endswith(".py"):
            return ProgrammingLanguage.PYTHON
        return ProgrammingLanguage.SQL
