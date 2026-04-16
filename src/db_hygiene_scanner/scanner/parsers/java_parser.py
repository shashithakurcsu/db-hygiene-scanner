"""Java source code parser for database hygiene violation detection."""

import re

from db_hygiene_scanner.models import ProgrammingLanguage


class JavaParser:
    """Parse Java source files for database hygiene patterns."""

    def __init__(self) -> None:
        self.language = ProgrammingLanguage.JAVA

        self.select_star = re.compile(r'["\']SELECT\s+\*', re.IGNORECASE)
        self.count_star = re.compile(r"COUNT\s*\(\s*\*\s*\)", re.IGNORECASE)
        self.string_concat_query = re.compile(
            r'(?:createQuery|createNativeQuery|createStatement|executeQuery)\s*\([^)]*["\'][^"\']*["\']\s*\+',
            re.IGNORECASE,
        )
        self.string_format_sql = re.compile(
            r'String\.format\s*\(\s*["\'](?:SELECT|INSERT|UPDATE|DELETE)[^"\']*%[sd][^"\']*["\']',
            re.IGNORECASE,
        )
        self.mybatis_unsafe_interpolation = re.compile(r"\$\{[^}]+\}")
        self.statement_creation = re.compile(
            r"(?:Statement|Query)\s+\w+\s*=\s*(?:connection|session|em)\."
            r"create(?:Statement|Query|NativeQuery)\s*\(",
            re.IGNORECASE,
        )

    def parse(self, content: str) -> list[tuple[str, int, str]]:
        """Parse entire Java file and return all violations."""
        violations: list[tuple[str, int, str]] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            # Check for SELECT *
            if self.select_star.search(line):
                if not self.count_star.search(line):
                    violations.append(("SELECT_STAR", line_num, line))

            # Check for string concatenation in queries
            if self.string_concat_query.search(line):
                violations.append(("STRING_CONCAT_SQL", line_num, line))

            if self.string_format_sql.search(line):
                if re.search(r"String\.format.*%[sd]", line):
                    violations.append(("STRING_CONCAT_SQL", line_num, line))

            # Check for MyBatis unsafe interpolation
            if self.mybatis_unsafe_interpolation.search(line):
                violations.append(("STRING_CONCAT_SQL", line_num, line))

            # Check for Statement without timeout
            if self.statement_creation.search(line):
                if "PreparedStatement" not in line:
                    violations.append(("STRING_CONCAT_SQL", line_num, line))
                next_idx = min(line_num, len(lines) - 1)
                if "setQueryTimeout" not in lines[next_idx]:
                    violations.append(("LONG_RUNNING_TXN", line_num, line))

        return violations
