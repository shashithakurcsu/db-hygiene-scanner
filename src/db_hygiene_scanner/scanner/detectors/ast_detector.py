"""AST-based detector that uses tree-sitter for deep code analysis.

This detector runs alongside regex-based detectors and catches patterns they miss:
- Multi-line SQL string concatenation
- Variable flow analysis (SQL assigned to var, passed to execute later)
- Scope-aware loop detection
- Context-aware (ignores comments, dead code)

Results are deduplicated with regex detectors by line number.
"""

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


VIOLATION_TYPE_MAP = {
    "SELECT_STAR": ViolationType.SELECT_STAR,
    "STRING_CONCAT_SQL": ViolationType.STRING_CONCAT_SQL,
    "UNBATCHED_TXN": ViolationType.UNBATCHED_TXN,
    "LONG_RUNNING_TXN": ViolationType.LONG_RUNNING_TXN,
    "READ_PREFERENCE": ViolationType.READ_PREFERENCE,
}

SEVERITY_MAP = {
    "SELECT_STAR": Severity.HIGH,
    "STRING_CONCAT_SQL": Severity.CRITICAL,
    "UNBATCHED_TXN": Severity.HIGH,
    "LONG_RUNNING_TXN": Severity.HIGH,
    "READ_PREFERENCE": Severity.HIGH,
}


class ASTDetector(BaseDetector):
    """Deep code analysis detector using tree-sitter AST parsing."""

    def __init__(self, config: Config, logger: structlog.BoundLogger) -> None:
        super().__init__(config, logger)
        self._parsers = {}
        self._init_parsers()

    def _init_parsers(self) -> None:
        """Initialize AST parsers for each supported language."""
        try:
            from db_hygiene_scanner.scanner.ast_parsers.java_ast import JavaASTParser
            self._parsers["java"] = JavaASTParser()
        except Exception as e:
            self.logger.debug("java_ast_parser_unavailable", error=str(e))

        try:
            from db_hygiene_scanner.scanner.ast_parsers.python_ast import PythonASTParser
            self._parsers["python"] = PythonASTParser()
        except Exception as e:
            self.logger.debug("python_ast_parser_unavailable", error=str(e))

        try:
            from db_hygiene_scanner.scanner.ast_parsers.csharp_ast import CSharpASTParser
            self._parsers["csharp"] = CSharpASTParser()
        except Exception as e:
            self.logger.debug("csharp_ast_parser_unavailable", error=str(e))

    def supports_language(self, language: ProgrammingLanguage) -> bool:
        return language in [
            ProgrammingLanguage.JAVA,
            ProgrammingLanguage.PYTHON,
            ProgrammingLanguage.CSHARP,
        ]

    def supports_platform(self, platform: DatabasePlatform) -> bool:
        return True

    def detect(self, file_path: str, content: str) -> list[Violation]:
        """Run AST-based detection on a source file."""
        parser_key = self._get_parser_key(file_path)
        if not parser_key or parser_key not in self._parsers:
            return []

        try:
            ast_parser = self._parsers[parser_key]
            ast_violations = ast_parser.parse(content)
        except Exception as e:
            self.logger.debug("ast_parse_error", file=file_path, error=str(e))
            return []

        violations: list[Violation] = []
        platform = self._detect_platform(content, file_path)
        language = self._detect_language(file_path)

        for av in ast_violations:
            vtype = VIOLATION_TYPE_MAP.get(av.type)
            severity = SEVERITY_MAP.get(av.type, Severity.HIGH)
            if not vtype:
                continue

            before, after = self._extract_context(content, av.line)

            violations.append(Violation(
                file_path=file_path,
                line_number=av.line,
                line_content=av.code[:150] if av.code else content.split("\n")[av.line - 1].strip()[:150],
                violation_type=vtype,
                severity=severity,
                platform=platform,
                language=language,
                description=f"[AST] {av.description}",
                context_before=before,
                context_after=after,
                confidence_score=av.confidence,
                created_at=datetime.utcnow(),
            ))

        if violations:
            self.logger.info(
                "ast_violations_detected",
                file=file_path,
                count=len(violations),
                parser=parser_key,
            )

        return violations

    def _get_parser_key(self, file_path: str) -> str | None:
        if file_path.endswith(".java"):
            return "java"
        if file_path.endswith(".py"):
            return "python"
        if file_path.endswith(".cs"):
            return "csharp"
        return None

    def _detect_platform(self, content: str, file_path: str) -> DatabasePlatform:
        content_lower = content.lower()
        if "mongoclient" in content_lower or "pymongo" in content_lower:
            return DatabasePlatform.MONGODB
        if "oracleconnection" in content_lower or "cx_oracle" in content_lower:
            return DatabasePlatform.ORACLE
        if "yugabyte" in content_lower or "npgsql" in content_lower:
            return DatabasePlatform.EDB_YUGABYTE
        return DatabasePlatform.MSSQL

    def _detect_language(self, file_path: str) -> ProgrammingLanguage:
        if file_path.endswith(".cs"):
            return ProgrammingLanguage.CSHARP
        if file_path.endswith(".java"):
            return ProgrammingLanguage.JAVA
        if file_path.endswith(".py"):
            return ProgrammingLanguage.PYTHON
        return ProgrammingLanguage.SQL
