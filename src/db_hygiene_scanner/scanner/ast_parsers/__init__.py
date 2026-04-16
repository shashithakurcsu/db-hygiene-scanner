"""AST-based parsers using tree-sitter for deep code analysis.

These parsers build on regex detection by understanding actual code structure:
- Multi-line string concatenation tracking
- Variable flow analysis (SQL assigned to var, then passed to execute)
- Scope-aware detection (is this inside a loop? a try/catch?)
- Context-aware (ignore comments, test assertions, string literals in non-SQL context)
"""

from db_hygiene_scanner.scanner.ast_parsers.java_ast import JavaASTParser
from db_hygiene_scanner.scanner.ast_parsers.python_ast import PythonASTParser
from db_hygiene_scanner.scanner.ast_parsers.csharp_ast import CSharpASTParser

__all__ = ["JavaASTParser", "PythonASTParser", "CSharpASTParser"]
