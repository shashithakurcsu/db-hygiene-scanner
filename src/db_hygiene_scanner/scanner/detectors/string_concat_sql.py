"""STRING_CONCAT_SQL (SQL injection) violation detector.

SECURITY-CRITICAL DETECTOR: Detects SQL injection vulnerabilities
from string concatenation across all supported languages.
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


class StringConcatSQLDetector(BaseDetector):
    """Detects SQL injection vulnerabilities from string concatenation."""

    def __init__(self, config: Config, logger: structlog.BoundLogger) -> None:
        super().__init__(config, logger)
        self.violation_type = ViolationType.STRING_CONCAT_SQL

        # C# patterns
        self.csharp_concat = re.compile(
            r'(?:SqlCommand|ExecuteSql|SqlQuery)\s*\([^)]*["\'][^"\']*["\']\s*\+',
            re.IGNORECASE,
        )
        self.csharp_interpolation = re.compile(
            r'(?:SqlCommand|ExecuteSql|SqlQuery|Database\.Sql)\s*\(\s*(?:\$|f)["\']',
            re.IGNORECASE,
        )
        self.csharp_string_interpolation = re.compile(
            r'\$"[^"]*(?:SELECT|INSERT|UPDATE|DELETE)[^"]*\{',
            re.IGNORECASE,
        )
        self.csharp_string_format = re.compile(
            r'string\.Format\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE)',
            re.IGNORECASE,
        )
        self.csharp_raw_concat = re.compile(
            r'["\'](?:SELECT|INSERT|UPDATE|DELETE)\s[^"\']*["\']\s*\+',
            re.IGNORECASE,
        )

        # Java patterns
        self.java_concat = re.compile(
            r'(?:createQuery|createNativeQuery|executeQuery|prepareStatement)\s*\([^)]*["\'][^"\']*["\']\s*\+',
            re.IGNORECASE,
        )
        self.java_string_format = re.compile(
            r'String\.format\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE)[^"\']*%[sd][^"\']*["\']',
            re.IGNORECASE,
        )
        self.mybatis_unsafe = re.compile(r"\$\{[^}]+\}")

        # Python patterns
        self.python_fstring = re.compile(
            r'(?:execute|executemany|query|run)\s*\(\s*f["\'].*(?:SELECT|INSERT|UPDATE|DELETE)',
            re.IGNORECASE,
        )
        self.python_percent_format = re.compile(
            r'(?:execute|executemany|query|run)\s*\(["\'][^"\']*%[sd][^"\']*["\']\s*%',
            re.IGNORECASE,
        )
        self.python_concat = re.compile(
            r'(?:execute|executemany|query|run)\s*\(["\'][^"\']*["\']\s*\+',
            re.IGNORECASE,
        )
        self.python_fstring_sql_var = re.compile(
            r'f["\'](?:SELECT|INSERT|UPDATE|DELETE)\s[^"\']*\{',
            re.IGNORECASE,
        )

        # SQL patterns
        self.sql_dynamic_exec = re.compile(
            r"(?:EXEC|EXECUTE)\s*\(\s*['\"][^'\"]*['\"]\s*\+",
            re.IGNORECASE,
        )
        self.sql_execute_immediate_concat = re.compile(
            r"EXECUTE\s+IMMEDIATE\s+.*\|\|", re.IGNORECASE
        )

    def supports_language(self, language: ProgrammingLanguage) -> bool:
        return True

    def supports_platform(self, platform: DatabasePlatform) -> bool:
        return True

    def detect(self, file_path: str, content: str) -> list[Violation]:
        """Detect SQL injection vulnerabilities from string concatenation."""
        violations: list[Violation] = []
        lines = content.split("\n")
        language = self._detect_language(file_path)
        platform = self._detect_platform(content, file_path)

        for line_num, line in enumerate(lines, 1):
            matched = False

            if language == ProgrammingLanguage.CSHARP:
                if (
                    self.csharp_concat.search(line)
                    or self.csharp_interpolation.search(line)
                    or self.csharp_string_interpolation.search(line)
                    or self.csharp_string_format.search(line)
                    or self.csharp_raw_concat.search(line)
                ):
                    matched = True

            elif language == ProgrammingLanguage.JAVA:
                if self.java_concat.search(line) or self.java_string_format.search(line):
                    matched = True
                if self.mybatis_unsafe.search(line):
                    matched = True

            elif language == ProgrammingLanguage.PYTHON:
                if (
                    self.python_fstring.search(line)
                    or self.python_percent_format.search(line)
                    or self.python_concat.search(line)
                    or self.python_fstring_sql_var.search(line)
                ):
                    matched = True

            elif language == ProgrammingLanguage.SQL:
                if self.sql_dynamic_exec.search(line) or self.sql_execute_immediate_concat.search(line):
                    matched = True

            if matched:
                before, after = self._extract_context(content, line_num)

                violation = Violation(
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line.strip(),
                    violation_type=self.violation_type,
                    severity=Severity.CRITICAL,
                    platform=platform,
                    language=language,
                    description=(
                        "SQL Injection Risk: Query constructed via string concatenation "
                        "or interpolation. Use parameterized queries or prepared statements."
                    ),
                    context_before=before,
                    context_after=after,
                    confidence_score=0.95,
                    created_at=datetime.utcnow(),
                )
                violations.append(violation)
                self.logger.warning(
                    "sql_injection_risk_detected",
                    file_path=file_path,
                    line=line_num,
                    severity="CRITICAL",
                )

        return violations

    def _detect_language(self, file_path: str) -> ProgrammingLanguage:
        if file_path.endswith(".cs"):
            return ProgrammingLanguage.CSHARP
        if file_path.endswith(".java") or file_path.endswith(".xml"):
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
