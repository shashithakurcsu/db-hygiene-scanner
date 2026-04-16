"""SELECT * violation detector.

Detects SELECT * queries across all languages and SQL files.
Context-aware: ignores COUNT(*), EXISTS(SELECT *), etc.
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


class SelectStarDetector(BaseDetector):
    """Detects SELECT * queries that expose unnecessary columns."""

    def __init__(self, config: Config, logger: structlog.BoundLogger) -> None:
        super().__init__(config, logger)
        self.violation_type = ViolationType.SELECT_STAR

        self.select_star_pattern = re.compile(
            r"SELECT\s+\*(?!\s*\))", re.IGNORECASE | re.MULTILINE
        )
        self.count_star_pattern = re.compile(r"COUNT\s*\(\s*\*\s*\)", re.IGNORECASE)
        self.exists_select_star = re.compile(r"EXISTS\s*\(\s*SELECT\s+\*", re.IGNORECASE)

    def supports_language(self, language: ProgrammingLanguage) -> bool:
        return True

    def supports_platform(self, platform: DatabasePlatform) -> bool:
        return True

    def detect(self, file_path: str, content: str) -> list[Violation]:
        """Detect all SELECT * queries in the file."""
        violations: list[Violation] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            if self.select_star_pattern.search(line):
                if self.count_star_pattern.search(line):
                    continue
                if self.exists_select_star.search(line):
                    continue

                before, after = self._extract_context(content, line_num)
                platform = self._detect_platform(content, file_path)
                language = self._detect_language(file_path)

                violation = Violation(
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line.strip(),
                    violation_type=self.violation_type,
                    severity=Severity.HIGH,
                    platform=platform,
                    language=language,
                    description=(
                        "SELECT * query detected. Avoid selecting all columns; "
                        "specify only required columns. This improves performance, "
                        "reduces network overhead, and limits schema exposure."
                    ),
                    context_before=before,
                    context_after=after,
                    confidence_score=0.98,
                    created_at=datetime.utcnow(),
                )
                violations.append(violation)
                self.logger.debug("select_star_detected", file_path=file_path, line=line_num)

        return violations

    def _detect_platform(self, content: str, file_path: str) -> DatabasePlatform:
        """Infer database platform from connection strings and imports."""
        content_lower = content.lower()
        if "mongoclient" in content_lower or "pymongo" in content_lower:
            return DatabasePlatform.MONGODB
        if "oracleconnection" in content_lower or "cx_oracle" in content_lower or "oracle" in file_path.lower():
            return DatabasePlatform.ORACLE
        if "yugabyte" in content_lower or "npgsql" in content_lower:
            return DatabasePlatform.EDB_YUGABYTE
        return DatabasePlatform.MSSQL

    def _detect_language(self, file_path: str) -> ProgrammingLanguage:
        """Infer language from file extension."""
        if file_path.endswith(".cs"):
            return ProgrammingLanguage.CSHARP
        if file_path.endswith(".java"):
            return ProgrammingLanguage.JAVA
        if file_path.endswith(".py"):
            return ProgrammingLanguage.PYTHON
        return ProgrammingLanguage.SQL
