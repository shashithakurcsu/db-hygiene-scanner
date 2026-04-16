"""SQL file parser for database hygiene violation detection."""

import re

from db_hygiene_scanner.models import ProgrammingLanguage


class SQLParser:
    """Parse raw .sql files for database hygiene patterns."""

    def __init__(self) -> None:
        self.language = ProgrammingLanguage.SQL

        self.select_star = re.compile(
            r"SELECT\s+\*(?!\s*\))", re.IGNORECASE | re.MULTILINE
        )
        self.count_star = re.compile(r"COUNT\s*\(\s*\*\s*\)", re.IGNORECASE)
        self.exists_select_star = re.compile(
            r"EXISTS\s*\(\s*SELECT\s+\*", re.IGNORECASE
        )
        self.exec_with_concat = re.compile(
            r"EXEC\s*\(\s*['\"].*['\"]\s*\+", re.IGNORECASE | re.MULTILINE
        )
        self.cursor_without_forward_only = re.compile(
            r"DECLARE\s+\w+\s+CURSOR(?!.*(?:FAST_FORWARD|READ_ONLY))",
            re.IGNORECASE,
        )
        self.begin_txn = re.compile(
            r"BEGIN\s+(?:DISTRIBUTED\s+)?TRANSACTION", re.IGNORECASE
        )
        self.execute_immediate_concat = re.compile(
            r"EXECUTE\s+IMMEDIATE\s+.*\|\|", re.IGNORECASE
        )

    def parse(self, content: str) -> list[tuple[str, int, str]]:
        """Parse entire SQL file and return all violations."""
        violations: list[tuple[str, int, str]] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            # Check for SELECT *
            if self.select_star.search(line):
                if not self.count_star.search(line) and not self.exists_select_star.search(line):
                    violations.append(("SELECT_STAR", line_num, line))

            # Check for EXEC with concatenation (MSSQL dynamic SQL)
            if self.exec_with_concat.search(line):
                violations.append(("STRING_CONCAT_SQL", line_num, line))

            # Check for EXECUTE IMMEDIATE with concatenation (Oracle)
            if self.execute_immediate_concat.search(line):
                violations.append(("STRING_CONCAT_SQL", line_num, line))

            # Check for DECLARE CURSOR without FAST_FORWARD
            if self.cursor_without_forward_only.search(line):
                violations.append(("LONG_RUNNING_TXN", line_num, line))

            # Check for BEGIN TRANSACTION
            if self.begin_txn.search(line):
                # Look for SET TRANSACTION ISOLATION in surrounding context
                start = max(0, line_num - 5)
                end = min(len(lines), line_num + 10)
                context = "\n".join(lines[start:end])
                if "SET TRANSACTION ISOLATION" not in context.upper():
                    violations.append(("LONG_RUNNING_TXN", line_num, line))

        return violations
