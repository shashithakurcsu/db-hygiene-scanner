"""UNBATCHED_TXN violation detector.

Detects N+1 query problems: loops performing individual DB operations
without batching.
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


class UnbatchedTransactionDetector(BaseDetector):
    """Detects unbatched transaction patterns that lead to N+1 queries."""

    def __init__(self, config: Config, logger: structlog.BoundLogger) -> None:
        super().__init__(config, logger)
        self.violation_type = ViolationType.UNBATCHED_TXN

        # C# patterns
        self.csharp_savechanges_in_loop = re.compile(
            r"(?:foreach|for)\s*\([^)]*\)\s*\{[^}]*(?:SaveChanges|ExecuteNonQuery|Execute)\s*\(",
            re.DOTALL | re.IGNORECASE,
        )

        # Java patterns
        self.java_persist_in_loop = re.compile(
            r"(?:for|foreach)\s*\([^)]*\)\s*\{[^}]*(?:em\.persist|session\.save|"
            r"entityManager\.persist|\.persist)\s*\(",
            re.DOTALL | re.IGNORECASE,
        )

        # Python patterns
        self.python_insert_one_in_loop = re.compile(
            r"for\s+\w+\s+in\s+\w+.*:.*(?:insert_one|update_one|delete_one)\s*\(",
            re.DOTALL | re.IGNORECASE,
        )

    def supports_language(self, language: ProgrammingLanguage) -> bool:
        return language in [
            ProgrammingLanguage.CSHARP,
            ProgrammingLanguage.JAVA,
            ProgrammingLanguage.PYTHON,
        ]

    def supports_platform(self, platform: DatabasePlatform) -> bool:
        return True

    def detect(self, file_path: str, content: str) -> list[Violation]:
        """Detect unbatched transaction patterns."""
        violations: list[Violation] = []
        lines = content.split("\n")
        language = self._detect_language(file_path)
        platform = self._detect_platform(content, file_path)
        reported_ranges: set[int] = set()

        for line_num, line in enumerate(lines, 1):
            start = max(0, line_num - 1)
            end = min(len(lines), line_num + 15)
            context = "\n".join(lines[start:end])

            matched = False

            if language == ProgrammingLanguage.CSHARP:
                if self.csharp_savechanges_in_loop.search(context):
                    matched = True

            elif language == ProgrammingLanguage.JAVA:
                if self.java_persist_in_loop.search(context):
                    matched = True

            elif language == ProgrammingLanguage.PYTHON:
                if self.python_insert_one_in_loop.search(context):
                    matched = True

            if matched:
                # Avoid duplicate reports for same loop region
                region_key = line_num // 10
                if region_key in reported_ranges:
                    continue
                reported_ranges.add(region_key)

                before, after = self._extract_context(content, line_num)

                violation = Violation(
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line.strip(),
                    violation_type=self.violation_type,
                    severity=Severity.HIGH,
                    platform=platform,
                    language=language,
                    description=(
                        "Unbatched transaction detected: Loop with individual database operations. "
                        "This causes N+1 query problems. Use batch operations instead."
                    ),
                    context_before=before,
                    context_after=after,
                    confidence_score=0.85,
                    created_at=datetime.utcnow(),
                )
                violations.append(violation)
                self.logger.warning("unbatched_txn_detected", file_path=file_path, line=line_num)

        return violations

    def _detect_language(self, file_path: str) -> ProgrammingLanguage:
        if file_path.endswith(".cs"):
            return ProgrammingLanguage.CSHARP
        if file_path.endswith(".java"):
            return ProgrammingLanguage.JAVA
        if file_path.endswith(".py"):
            return ProgrammingLanguage.PYTHON
        return ProgrammingLanguage.SQL

    def _detect_platform(self, content: str, file_path: str) -> DatabasePlatform:
        content_lower = content.lower()
        if "mongoclient" in content_lower or "pymongo" in content_lower:
            return DatabasePlatform.MONGODB
        if "oracleconnection" in content_lower or "cx_oracle" in content_lower:
            return DatabasePlatform.ORACLE
        if "yugabyte" in content_lower or "npgsql" in content_lower:
            return DatabasePlatform.EDB_YUGABYTE
        return DatabasePlatform.MSSQL
