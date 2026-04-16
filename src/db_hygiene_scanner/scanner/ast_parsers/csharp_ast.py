"""C# AST parser using tree-sitter for deep code analysis.

Catches patterns regex misses:
- SqlCommand with SQL built across multiple lines
- String interpolation in SQL context
- SaveChanges/ExecuteNonQuery inside foreach (scope-aware)
- TransactionScope without timeout options
- Missing CommandTimeout across separated lines
"""

import re

from tree_sitter import Language, Parser

from db_hygiene_scanner.scanner.ast_parsers.base_ast import (
    ASTViolation,
    find_ancestor,
    find_child,
    find_nodes,
    node_text,
    walk_tree,
)


class CSharpASTParser:
    """Deep C# analysis using tree-sitter AST."""

    def __init__(self):
        import tree_sitter_c_sharp
        self._lang = Language(tree_sitter_c_sharp.language())
        self._parser = Parser(self._lang)

    def parse(self, content: str) -> list[ASTViolation]:
        """Parse C# source and return violations found via AST analysis."""
        tree = self._parser.parse(content.encode("utf-8"))
        root = tree.root_node
        violations: list[ASTViolation] = []

        violations.extend(self._check_sql_variable_flow(root))
        violations.extend(self._check_interpolated_sql(root))
        violations.extend(self._check_loop_savechanges(root))
        violations.extend(self._check_transaction_scope_timeout(root))
        violations.extend(self._check_command_timeout(root))
        violations.extend(self._check_select_star(root))

        return violations

    def _check_sql_variable_flow(self, root) -> list[ASTViolation]:
        """Detect SQL concatenation assigned to variable then passed to SqlCommand."""
        violations = []
        sql_kw = re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s")

        for var_decl in find_nodes(root, "local_declaration_statement"):
            text = node_text(var_decl)
            if sql_kw.search(text) and "+" in text:
                # Extract variable name
                parts = text.split("=")[0].strip().split()
                if len(parts) >= 2:
                    var_name = parts[-1]
                else:
                    continue

                # Check if passed to SqlCommand/Execute in same scope
                block = find_ancestor(var_decl, "block")
                if block:
                    block_text = node_text(block)
                    if (f"SqlCommand({var_name}" in block_text or
                            f"ExecuteSql({var_name}" in block_text or
                            f"NpgsqlCommand({var_name}" in block_text or
                            f"OracleCommand({var_name}" in block_text):
                        violations.append(ASTViolation(
                            type="STRING_CONCAT_SQL",
                            line=var_decl.start_point[0] + 1,
                            code=text.strip()[:120],
                            description=(
                                "SQL injection: SQL built via string concatenation then passed to command constructor. "
                                "Use parameterized queries with cmd.Parameters.AddWithValue()."
                            ),
                            confidence=0.93,
                        ))

        return violations

    def _check_interpolated_sql(self, root) -> list[ASTViolation]:
        """Detect $\"...SQL...{variable}...\" interpolated strings with SQL."""
        violations = []
        sql_kw = re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s")

        for string_node in find_nodes(root, "interpolated_string_expression"):
            text = node_text(string_node)
            if sql_kw.search(text):
                violations.append(ASTViolation(
                    type="STRING_CONCAT_SQL",
                    line=string_node.start_point[0] + 1,
                    code=text.strip()[:120],
                    description=(
                        "SQL injection: String interpolation ($\"...\") used to build SQL query. "
                        "Use parameterized queries instead."
                    ),
                    confidence=0.95,
                ))

        return violations

    def _check_loop_savechanges(self, root) -> list[ASTViolation]:
        """Detect SaveChanges/ExecuteNonQuery inside foreach/for loops."""
        violations = []
        loop_types = {"for_each_statement", "for_statement", "while_statement"}
        unbatched_calls = [
            "SaveChanges(", "SaveChangesAsync(",
            "ExecuteNonQuery(", "ExecuteNonQueryAsync(",
            "Execute(", "ExecuteAsync(",
        ]

        for loop_type in loop_types:
            for loop_node in find_nodes(root, loop_type):
                loop_text = node_text(loop_node)
                for call in unbatched_calls:
                    if call in loop_text:
                        violations.append(ASTViolation(
                            type="UNBATCHED_TXN",
                            line=loop_node.start_point[0] + 1,
                            code=loop_text.strip()[:120],
                            description=(
                                f"N+1 query: {call.rstrip('(')} inside loop. "
                                "Move SaveChanges() outside the loop for batch commit."
                            ),
                            confidence=0.92,
                        ))
                        break

        return violations

    def _check_transaction_scope_timeout(self, root) -> list[ASTViolation]:
        """Detect TransactionScope without TransactionOptions.Timeout."""
        violations = []
        for obj_creation in find_nodes(root, "object_creation_expression"):
            text = node_text(obj_creation)
            if "TransactionScope" in text:
                if "Timeout" not in text and "TransactionOptions" not in text:
                    violations.append(ASTViolation(
                        type="LONG_RUNNING_TXN",
                        line=obj_creation.start_point[0] + 1,
                        code=text.strip()[:120],
                        description=(
                            "TransactionScope without timeout. Use TransactionScope with "
                            "TransactionOptions { Timeout = TimeSpan.FromSeconds(30) }."
                        ),
                        confidence=0.87,
                    ))

        return violations

    def _check_command_timeout(self, root) -> list[ASTViolation]:
        """Detect SqlCommand/NpgsqlCommand/OracleCommand without CommandTimeout set."""
        violations = []
        command_types = {"SqlCommand", "NpgsqlCommand", "OracleCommand"}

        for obj_creation in find_nodes(root, "object_creation_expression"):
            text = node_text(obj_creation)
            if not any(ct in text for ct in command_types):
                continue

            # Check if CommandTimeout is set in surrounding scope
            block = find_ancestor(obj_creation, "block")
            if block:
                block_text = node_text(block)
                if "CommandTimeout" not in block_text:
                    violations.append(ASTViolation(
                        type="LONG_RUNNING_TXN",
                        line=obj_creation.start_point[0] + 1,
                        code=text.strip()[:120],
                        description=(
                            "Database command without CommandTimeout. Set cmd.CommandTimeout = 30 "
                            "to prevent long-running queries from holding locks."
                        ),
                        confidence=0.85,
                    ))

        return violations

    def _check_select_star(self, root) -> list[ASTViolation]:
        """Detect SELECT * in string literals (ignoring comments)."""
        violations = []
        select_star = re.compile(r"SELECT\s+\*(?!\s*\))", re.I)
        count_star = re.compile(r"COUNT\s*\(\s*\*\s*\)", re.I)

        for node_type in ["string_literal", "interpolated_string_expression", "verbatim_string_literal"]:
            for string_node in find_nodes(root, node_type):
                text = node_text(string_node)
                if select_star.search(text) and not count_star.search(text):
                    violations.append(ASTViolation(
                        type="SELECT_STAR",
                        line=string_node.start_point[0] + 1,
                        code=text.strip()[:120],
                        description="SELECT * in SQL string literal. Specify explicit columns.",
                        confidence=0.97,
                    ))

        return violations
