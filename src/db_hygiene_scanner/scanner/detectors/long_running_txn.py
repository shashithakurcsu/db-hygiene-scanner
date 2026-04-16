"""LONG_RUNNING_TXN violation detector.

Detects missing transaction timeouts and long-running transaction patterns.
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


class LongRunningTransactionDetector(BaseDetector):
    """Detects missing transaction timeout configuration."""

    def __init__(self, config: Config, logger: structlog.BoundLogger) -> None:
        super().__init__(config, logger)
        self.violation_type = ViolationType.LONG_RUNNING_TXN

        # C# patterns
        self.csharp_txn_scope_no_timeout = re.compile(
            r"new\s+TransactionScope\s*\(", re.IGNORECASE
        )
        self.csharp_sqlcommand = re.compile(
            r"new\s+SqlCommand\s*\(", re.IGNORECASE
        )

        # Java patterns
        self.java_transactional = re.compile(r"@Transactional", re.IGNORECASE)
        self.java_create_statement = re.compile(
            r"(?:connection|conn)\s*\.\s*createStatement\s*\(", re.IGNORECASE
        )

        # Python patterns
        self.python_connect = re.compile(
            r"psycopg2\.connect\s*\(", re.IGNORECASE
        )

        # SQL patterns
        self.sql_cursor_no_fast_forward = re.compile(
            r"DECLARE\s+\w+\s+CURSOR(?!.*FAST_FORWARD)", re.IGNORECASE
        )
        self.sql_begin_txn = re.compile(
            r"BEGIN\s+(?:DISTRIBUTED\s+)?TRANSACTION", re.IGNORECASE
        )

    def supports_language(self, language: ProgrammingLanguage) -> bool:
        return True

    def supports_platform(self, platform: DatabasePlatform) -> bool:
        return True

    def detect(self, file_path: str, content: str) -> list[Violation]:
        """Detect missing transaction timeout configuration."""
        violations: list[Violation] = []
        lines = content.split("\n")
        language = self._detect_language(file_path)
        platform = self._detect_platform(content, file_path)

        for line_num, line in enumerate(lines, 1):
            matched = False
            issue_desc = ""

            # Look at surrounding lines for timeout configuration
            start = max(0, line_num - 3)
            end = min(len(lines), line_num + 5)
            context = "\n".join(lines[start:end])

            if language == ProgrammingLanguage.CSHARP:
                if self.csharp_txn_scope_no_timeout.search(line):
                    if "Timeout" not in context and "TransactionOptions" not in context:
                        matched = True
                        issue_desc = (
                            "TransactionScope without timeout. Set TransactionOptions.Timeout "
                            "to prevent indefinite locks."
                        )
                elif self.csharp_sqlcommand.search(line):
                    if "CommandTimeout" not in context:
                        matched = True
                        issue_desc = (
                            "SqlCommand without CommandTimeout configured. Set CommandTimeout "
                            "to prevent long-running queries from locking resources."
                        )

            elif language == ProgrammingLanguage.JAVA:
                if self.java_transactional.search(line):
                    if "timeout" not in line.lower():
                        matched = True
                        issue_desc = (
                            "@Transactional without timeout. Add timeout parameter "
                            "to prevent indefinite transaction locks."
                        )
                elif self.java_create_statement.search(line):
                    if "setQueryTimeout" not in context:
                        matched = True
                        issue_desc = (
                            "Statement created without setQueryTimeout. "
                            "Call setQueryTimeout() to prevent long-running queries."
                        )

            elif language == ProgrammingLanguage.PYTHON:
                if self.python_connect.search(line):
                    if "connect_timeout" not in line:
                        matched = True
                        issue_desc = (
                            "Database connection without timeout. Add connect_timeout "
                            "parameter to prevent indefinite connection attempts."
                        )

            elif language == ProgrammingLanguage.SQL:
                if self.sql_cursor_no_fast_forward.search(line):
                    if "FAST_FORWARD" not in line and "READ_ONLY" not in line:
                        matched = True
                        issue_desc = (
                            "DECLARE CURSOR without FAST_FORWARD or READ_ONLY. "
                            "Add these hints to improve performance."
                        )
                elif self.sql_begin_txn.search(line):
                    if "SET TRANSACTION ISOLATION" not in context.upper():
                        matched = True
                        issue_desc = (
                            "BEGIN TRANSACTION without explicit isolation level. "
                            "Set isolation level for consistency."
                        )

            if matched:
                before, after = self._extract_context(content, line_num)

                violation = Violation(
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line.strip(),
                    violation_type=self.violation_type,
                    severity=Severity.HIGH,
                    platform=platform,
                    language=language,
                    description=issue_desc,
                    context_before=before,
                    context_after=after,
                    confidence_score=0.80,
                    created_at=datetime.utcnow(),
                )
                violations.append(violation)
                self.logger.warning("long_running_txn_detected", file_path=file_path, line=line_num)

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
        if "mongoclient" in content_lower:
            return DatabasePlatform.MONGODB
        if "oracleconnection" in content_lower or "cx_oracle" in content_lower:
            return DatabasePlatform.ORACLE
        if "yugabyte" in content_lower or "npgsql" in content_lower:
            return DatabasePlatform.EDB_YUGABYTE
        return DatabasePlatform.MSSQL
