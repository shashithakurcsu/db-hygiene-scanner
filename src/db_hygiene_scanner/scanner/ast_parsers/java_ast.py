"""Java AST parser using tree-sitter for deep code analysis.

Catches patterns that regex misses:
- SQL strings assigned to variables then passed to execute()
- Multi-line string concatenation building SQL
- Loop scope detection for unbatched operations
- Missing timeout in method-level @Transactional
- Statement vs PreparedStatement context
"""

import re
from typing import Optional

from tree_sitter import Language, Parser

from db_hygiene_scanner.scanner.ast_parsers.base_ast import (
    ASTViolation,
    find_ancestor,
    find_child,
    find_nodes,
    node_text,
    walk_tree,
)


class JavaASTParser:
    """Deep Java analysis using tree-sitter AST."""

    def __init__(self):
        import tree_sitter_java
        self._lang = Language(tree_sitter_java.language())
        self._parser = Parser(self._lang)

    def parse(self, content: str) -> list[ASTViolation]:
        """Parse Java source and return violations found via AST analysis."""
        tree = self._parser.parse(content.encode("utf-8"))
        root = tree.root_node
        violations: list[ASTViolation] = []

        violations.extend(self._check_sql_string_variables(root))
        violations.extend(self._check_concat_in_execute(root))
        violations.extend(self._check_loop_persist(root))
        violations.extend(self._check_transactional_timeout(root))
        violations.extend(self._check_statement_vs_prepared(root))
        violations.extend(self._check_select_star_strings(root))

        return violations

    def _check_sql_string_variables(self, root) -> list[ASTViolation]:
        """Detect SQL strings assigned to variables then passed to execute methods.

        Catches:
            String sql = "SELECT * FROM " + table;
            // ... 10 lines later ...
            stmt.executeQuery(sql);  // regex won't link these
        """
        violations = []
        sql_pattern = re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s", re.IGNORECASE)

        # Find all local variable declarations with string concatenation
        for var_decl in find_nodes(root, "local_variable_declaration"):
            text = node_text(var_decl)
            # Check if it assigns a SQL string with concatenation
            if sql_pattern.search(text) and "+" in text:
                # Find the variable name
                declarator = find_child(var_decl, "variable_declarator")
                if not declarator:
                    continue
                var_name_node = find_child(declarator, "identifier")
                if not var_name_node:
                    continue
                var_name = node_text(var_name_node)

                # Check if this variable is later passed to an execute method
                block = find_ancestor(var_decl, "block")
                if block:
                    block_text = node_text(block)
                    exec_patterns = [
                        f"executeQuery({var_name})",
                        f"executeUpdate({var_name})",
                        f"execute({var_name})",
                        f"createQuery({var_name})",
                        f"prepareStatement({var_name})",
                    ]
                    if any(p in block_text for p in exec_patterns):
                        violations.append(ASTViolation(
                            type="STRING_CONCAT_SQL",
                            line=var_decl.start_point[0] + 1,
                            code=text.strip()[:120],
                            description=(
                                "SQL injection: SQL string built via concatenation and passed to execute method. "
                                "The variable flow crosses multiple lines, making this harder to spot. "
                                "Use parameterized queries instead."
                            ),
                            confidence=0.92,
                        ))

        return violations

    def _check_concat_in_execute(self, root) -> list[ASTViolation]:
        """Detect string concatenation directly inside execute/query method calls."""
        violations = []
        for call in find_nodes(root, "method_invocation"):
            text = node_text(call)
            method_name = ""
            for child in call.children:
                if child.type == "identifier":
                    method_name = node_text(child)

            execute_methods = {"executeQuery", "executeUpdate", "execute",
                               "createQuery", "createNativeQuery", "prepareStatement"}
            if method_name in execute_methods:
                args = find_child(call, "argument_list")
                if args:
                    args_text = node_text(args)
                    if "+" in args_text and re.search(r'["\'].*(?:SELECT|INSERT|UPDATE|DELETE)', args_text, re.I):
                        violations.append(ASTViolation(
                            type="STRING_CONCAT_SQL",
                            line=call.start_point[0] + 1,
                            code=text.strip()[:120],
                            description="SQL injection: String concatenation inside execute/query call.",
                            confidence=0.95,
                        ))

        return violations

    def _check_loop_persist(self, root) -> list[ASTViolation]:
        """Detect persist/save/execute calls inside for/while loops."""
        violations = []
        loop_types = {"for_statement", "enhanced_for_statement", "while_statement"}

        for loop_type in loop_types:
            for loop_node in find_nodes(root, loop_type):
                loop_text = node_text(loop_node)
                unbatched_calls = [
                    "entityManager.persist", "em.persist", "session.save",
                    "session.saveOrUpdate", ".executeUpdate", ".executeNonQuery",
                    ".execute(", "em.flush()",
                ]
                for pattern in unbatched_calls:
                    if pattern in loop_text:
                        violations.append(ASTViolation(
                            type="UNBATCHED_TXN",
                            line=loop_node.start_point[0] + 1,
                            code=loop_text.strip()[:120],
                            description=(
                                f"N+1 query: {pattern} called inside a loop. "
                                "Batch operations with addBatch()/executeBatch() or "
                                "collect and flush once outside the loop."
                            ),
                            confidence=0.90,
                        ))
                        break  # one per loop

        return violations

    def _check_transactional_timeout(self, root) -> list[ASTViolation]:
        """Detect @Transactional annotations without timeout parameter."""
        violations = []
        for annotation in find_nodes(root, "marker_annotation"):
            text = node_text(annotation)
            if "@Transactional" in text:
                if "timeout" not in text.lower():
                    violations.append(ASTViolation(
                        type="LONG_RUNNING_TXN",
                        line=annotation.start_point[0] + 1,
                        code=text.strip(),
                        description=(
                            "@Transactional without timeout parameter. Add timeout "
                            "(e.g., @Transactional(timeout = 30)) to prevent indefinite locks."
                        ),
                        confidence=0.85,
                    ))

        # Also check annotation nodes (with arguments)
        for annotation in find_nodes(root, "annotation"):
            text = node_text(annotation)
            if "@Transactional" in text and "timeout" not in text.lower():
                # Avoid duplicating marker_annotation matches
                if annotation.type == "annotation" and "(" in text:
                    violations.append(ASTViolation(
                        type="LONG_RUNNING_TXN",
                        line=annotation.start_point[0] + 1,
                        code=text.strip(),
                        description="@Transactional with parameters but no timeout set.",
                        confidence=0.85,
                    ))

        return violations

    def _check_statement_vs_prepared(self, root) -> list[ASTViolation]:
        """Detect use of Statement instead of PreparedStatement for queries."""
        violations = []
        for var_decl in find_nodes(root, "local_variable_declaration"):
            text = node_text(var_decl)
            if "createStatement()" in text and "PreparedStatement" not in text:
                # Check if it's used for executing queries (not just metadata)
                block = find_ancestor(var_decl, "block")
                if block and "executeQuery" in node_text(block):
                    violations.append(ASTViolation(
                        type="STRING_CONCAT_SQL",
                        line=var_decl.start_point[0] + 1,
                        code=text.strip()[:120],
                        description=(
                            "Using Statement instead of PreparedStatement. "
                            "Statement does not support parameterized queries, "
                            "making SQL injection possible."
                        ),
                        confidence=0.88,
                    ))

        return violations

    def _check_select_star_strings(self, root) -> list[ASTViolation]:
        """Detect SELECT * in string literals (more precise than regex - ignores comments)."""
        violations = []
        select_star = re.compile(r"SELECT\s+\*(?!\s*\))", re.I)
        count_star = re.compile(r"COUNT\s*\(\s*\*\s*\)", re.I)

        for string_node in find_nodes(root, "string_literal"):
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
