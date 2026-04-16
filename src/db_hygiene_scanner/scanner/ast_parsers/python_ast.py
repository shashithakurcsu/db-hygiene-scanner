"""Python AST parser using tree-sitter for deep code analysis.

Catches patterns regex misses:
- SQL assigned to variable then passed to cursor.execute()
- Multi-line f-string SQL construction
- for-loop with individual DB operations (scope-aware)
- MongoClient without read_preference across multiple lines
- psycopg2.connect() without timeout (even with kwargs spread)
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


class PythonASTParser:
    """Deep Python analysis using tree-sitter AST."""

    def __init__(self):
        import tree_sitter_python
        self._lang = Language(tree_sitter_python.language())
        self._parser = Parser(self._lang)

    def parse(self, content: str) -> list[ASTViolation]:
        """Parse Python source and return violations found via AST analysis."""
        tree = self._parser.parse(content.encode("utf-8"))
        root = tree.root_node
        violations: list[ASTViolation] = []

        violations.extend(self._check_sql_variable_flow(root))
        violations.extend(self._check_fstring_sql(root))
        violations.extend(self._check_loop_db_ops(root))
        violations.extend(self._check_mongo_read_preference(root))
        violations.extend(self._check_connect_timeout(root))
        violations.extend(self._check_select_star(root))

        return violations

    def _check_sql_variable_flow(self, root) -> list[ASTViolation]:
        """Detect SQL built via concatenation/formatting in a variable, then passed to execute().

        Catches:
            query = "SELECT * FROM users WHERE id = " + str(uid)
            cursor.execute(query)   # regex won't connect these two lines
        """
        violations = []
        sql_keywords = re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s")

        # Find assignments with SQL-like strings involving concatenation or formatting
        for assignment in find_nodes(root, "assignment"):
            text = node_text(assignment)
            right = find_child(assignment, "binary_operator") or find_child(assignment, "concatenated_string")
            if not right:
                # Check for f-string or % format
                for child in assignment.children:
                    child_text = node_text(child)
                    if sql_keywords.search(child_text) and ("%" in child_text or child.type == "string"):
                        right = child
                        break

            if not right:
                continue

            right_text = node_text(right)
            if not sql_keywords.search(right_text):
                continue
            if "+" not in right_text and "%" not in right_text and "{" not in right_text:
                continue

            # Get variable name
            left = assignment.children[0] if assignment.children else None
            if not left:
                continue
            var_name = node_text(left)

            # Search for this variable being passed to execute/query
            scope = find_ancestor(assignment, "function_definition") or find_ancestor(assignment, "module")
            if scope:
                scope_text = node_text(scope)
                execute_patterns = [
                    f"execute({var_name})",
                    f"execute({var_name},",
                    f"executemany({var_name}",
                    f"query({var_name})",
                    f"text({var_name})",
                ]
                if any(p in scope_text for p in execute_patterns):
                    violations.append(ASTViolation(
                        type="STRING_CONCAT_SQL",
                        line=assignment.start_point[0] + 1,
                        code=text.strip()[:120],
                        description=(
                            "SQL injection: SQL string built via concatenation/formatting and passed to execute(). "
                            "Use parameterized queries: cursor.execute('SELECT ... WHERE id = %s', (uid,))"
                        ),
                        confidence=0.93,
                    ))

        return violations

    def _check_fstring_sql(self, root) -> list[ASTViolation]:
        """Detect f-strings containing SQL keywords passed to execute methods."""
        violations = []
        sql_kw = re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s")

        for call in find_nodes(root, "call"):
            text = node_text(call)
            # Check if it's a .execute() or .query() call
            func = call.children[0] if call.children else None
            if not func:
                continue
            func_text = node_text(func)
            if not any(m in func_text for m in [".execute", ".query", ".run"]):
                continue

            # Check arguments for f-strings
            args = find_child(call, "argument_list")
            if not args:
                continue
            for arg in args.children:
                arg_text = node_text(arg)
                if arg.type == "string" and arg_text.startswith("f") and sql_kw.search(arg_text):
                    violations.append(ASTViolation(
                        type="STRING_CONCAT_SQL",
                        line=call.start_point[0] + 1,
                        code=text.strip()[:120],
                        description="SQL injection: f-string with SQL keywords passed to execute().",
                        confidence=0.96,
                    ))

        return violations

    def _check_loop_db_ops(self, root) -> list[ASTViolation]:
        """Detect DB operations inside for/while loops (scope-aware)."""
        violations = []
        loop_types = {"for_statement", "while_statement"}
        db_ops = [
            "cursor.execute(", "collection.insert_one(", "collection.update_one(",
            "collection.delete_one(", "session.add(", "session.execute(",
            ".save(", ".persist(",
        ]

        for loop_type in loop_types:
            for loop_node in find_nodes(root, loop_type):
                body = find_child(loop_node, "block")
                if not body:
                    continue
                body_text = node_text(body)
                for op in db_ops:
                    if op in body_text:
                        violations.append(ASTViolation(
                            type="UNBATCHED_TXN",
                            line=loop_node.start_point[0] + 1,
                            code=node_text(loop_node).strip()[:120],
                            description=(
                                f"N+1 query: {op.rstrip('(')} called inside loop. "
                                "Use executemany(), insert_many(), or bulk_write() instead."
                            ),
                            confidence=0.88,
                        ))
                        break

        return violations

    def _check_mongo_read_preference(self, root) -> list[ASTViolation]:
        """Detect MongoClient instantiation without read_preference."""
        violations = []
        for call in find_nodes(root, "call"):
            func = call.children[0] if call.children else None
            if not func:
                continue
            func_text = node_text(func)
            if "MongoClient" not in func_text:
                continue

            args = find_child(call, "argument_list")
            args_text = node_text(args) if args else ""
            if "read_preference" not in args_text.lower() and "readpreference" not in args_text.lower():
                violations.append(ASTViolation(
                    type="READ_PREFERENCE",
                    line=call.start_point[0] + 1,
                    code=node_text(call).strip()[:120],
                    description=(
                        "MongoClient without read_preference. For replica sets, set "
                        "read_preference=ReadPreference.SECONDARY_PREFERRED to distribute reads."
                    ),
                    confidence=0.90,
                ))

        return violations

    def _check_connect_timeout(self, root) -> list[ASTViolation]:
        """Detect psycopg2.connect / MongoClient without timeout parameter."""
        violations = []
        timeout_targets = {"psycopg2.connect", "pymysql.connect", "cx_Oracle.connect"}

        for call in find_nodes(root, "call"):
            func = call.children[0] if call.children else None
            if not func:
                continue
            func_text = node_text(func)
            if not any(t in func_text for t in timeout_targets):
                continue

            args = find_child(call, "argument_list")
            args_text = node_text(args) if args else ""
            if "timeout" not in args_text.lower() and "connect_timeout" not in args_text:
                violations.append(ASTViolation(
                    type="LONG_RUNNING_TXN",
                    line=call.start_point[0] + 1,
                    code=node_text(call).strip()[:120],
                    description="Database connection without timeout. Add connect_timeout parameter.",
                    confidence=0.82,
                ))

        return violations

    def _check_select_star(self, root) -> list[ASTViolation]:
        """Detect SELECT * in string literals (ignoring comments)."""
        violations = []
        select_star = re.compile(r"SELECT\s+\*(?!\s*\))", re.I)
        count_star = re.compile(r"COUNT\s*\(\s*\*\s*\)", re.I)

        for string_node in find_nodes(root, "string"):
            text = node_text(string_node)
            if select_star.search(text) and not count_star.search(text):
                violations.append(ASTViolation(
                    type="SELECT_STAR",
                    line=string_node.start_point[0] + 1,
                    code=text.strip()[:120],
                    description="SELECT * in SQL string. Specify explicit columns.",
                    confidence=0.97,
                ))

        return violations
