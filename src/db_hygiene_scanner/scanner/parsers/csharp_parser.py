"""C# source code parser for database hygiene violation detection."""

import re

from db_hygiene_scanner.models import ProgrammingLanguage


class CSharpParser:
    """Parse C# source files for database hygiene patterns."""

    def __init__(self) -> None:
        self.language = ProgrammingLanguage.CSHARP

        self.select_star_pattern = re.compile(
            r"SELECT\s+\*(?!\s*\))", re.IGNORECASE
        )
        self.count_star_pattern = re.compile(
            r"COUNT\s*\(\s*\*\s*\)", re.IGNORECASE
        )
        self.exists_select_star = re.compile(
            r"EXISTS\s*\(\s*SELECT\s+\*", re.IGNORECASE
        )
        self.string_concat_sql_pattern = re.compile(
            r'(?:SqlCommand|ExecuteSql|SqlQuery)\s*\([^)]*["\'][^"\']*["\']\s*\+',
            re.IGNORECASE,
        )
        self.entity_framework_interpolation = re.compile(
            r'(?:Database\.ExecuteSql|SqlQuery|RawSql)\s*\(\s*(?:\$|f)["\']',
            re.IGNORECASE,
        )
        self.string_interpolation_sql = re.compile(
            r'\$"[^"]*(?:SELECT|INSERT|UPDATE|DELETE)[^"]*\{',
            re.IGNORECASE,
        )

    def parse_line(
        self, line: str, line_number: int, content: str
    ) -> list[tuple[str, int, str]]:
        """Parse a single line for database hygiene violations.

        Returns list of (violation_type, line_number, matched_text) tuples.
        """
        violations: list[tuple[str, int, str]] = []

        # Check for SELECT *
        if self.select_star_pattern.search(line):
            if not self.count_star_pattern.search(line) and not self.exists_select_star.search(line):
                violations.append(("SELECT_STAR", line_number, line))

        # Check for string concatenation in SQL
        if self.string_concat_sql_pattern.search(line):
            violations.append(("STRING_CONCAT_SQL", line_number, line))

        if self.entity_framework_interpolation.search(line):
            violations.append(("STRING_CONCAT_SQL", line_number, line))

        if self.string_interpolation_sql.search(line):
            violations.append(("STRING_CONCAT_SQL", line_number, line))

        # Check for SqlCommand without CommandTimeout
        if re.search(r"new\s+SqlCommand", line, re.IGNORECASE):
            lines = content.split("\n")
            current_idx = line_number - 1
            found_timeout = False
            for i in range(current_idx, min(current_idx + 5, len(lines))):
                if "CommandTimeout" in lines[i]:
                    found_timeout = True
                    break
            if not found_timeout:
                violations.append(("LONG_RUNNING_TXN", line_number, line))

        return violations

    def parse(self, content: str) -> list[tuple[str, int, str]]:
        """Parse entire C# file and return all violations."""
        violations: list[tuple[str, int, str]] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            violations.extend(self.parse_line(line, line_num, content))

        return violations
