"""Python source code parser for database hygiene violation detection."""

import re

from db_hygiene_scanner.models import ProgrammingLanguage


class PythonParser:
    """Parse Python source files for database hygiene patterns."""

    def __init__(self) -> None:
        self.language = ProgrammingLanguage.PYTHON

        self.cursor_execute_fstring = re.compile(
            r'(?:cursor|conn)\s*\.\s*execute\s*\(\s*f["\']', re.IGNORECASE
        )
        self.cursor_execute_percent_format = re.compile(
            r'(?:cursor|conn)\s*\.\s*execute\s*\(["\'][^"\']*["\']\s*%',
            re.IGNORECASE,
        )
        self.sqlalchemy_text_concat = re.compile(
            r'(?:text|engine\.execute)\s*\(["\'][^"\']*["\']\s*\+',
            re.IGNORECASE,
        )
        self.mongoclient_no_read_preference = re.compile(
            r"MongoClient\s*\(\s*[^)]*\)", re.IGNORECASE
        )
        self.django_raw_formatted = re.compile(
            r'(?:\.raw|RawSQL)\s*\(\s*(?:f["\']|["\'][^"\']*["\']\s*%)',
            re.IGNORECASE,
        )
        self.select_star = re.compile(r'["\']SELECT\s+\*', re.IGNORECASE)
        self.count_star = re.compile(r"COUNT\s*\(\s*\*\s*\)", re.IGNORECASE)
        self.psycopg2_no_timeout = re.compile(
            r"psycopg2\.connect\s*\([^)]*\)", re.IGNORECASE
        )

    def parse(self, content: str) -> list[tuple[str, int, str]]:
        """Parse entire Python file and return all violations."""
        violations: list[tuple[str, int, str]] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            # Check for SELECT *
            if self.select_star.search(line):
                if not self.count_star.search(line):
                    violations.append(("SELECT_STAR", line_num, line))

            # Check for cursor.execute with f-string
            if self.cursor_execute_fstring.search(line):
                violations.append(("STRING_CONCAT_SQL", line_num, line))

            # Check for cursor.execute with % formatting
            if self.cursor_execute_percent_format.search(line):
                violations.append(("STRING_CONCAT_SQL", line_num, line))

            # Check for SQLAlchemy text() with string concatenation
            if self.sqlalchemy_text_concat.search(line):
                violations.append(("STRING_CONCAT_SQL", line_num, line))

            # Check for Django raw() with formatting
            if self.django_raw_formatted.search(line):
                violations.append(("STRING_CONCAT_SQL", line_num, line))

            # Check for MongoDB without read_preference
            if self.mongoclient_no_read_preference.search(line):
                if "read_preference" not in line.lower() and "readpreference" not in line.lower():
                    violations.append(("READ_PREFERENCE", line_num, line))

            # Check for psycopg2 without timeout
            if self.psycopg2_no_timeout.search(line):
                if "connect_timeout" not in line:
                    violations.append(("LONG_RUNNING_TXN", line_num, line))

        return violations
