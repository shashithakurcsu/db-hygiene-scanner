"""Base class for AST-based parsers with common tree traversal utilities."""

from typing import Optional


class ASTViolation:
    """A violation found by AST analysis."""

    __slots__ = ("type", "line", "code", "description", "confidence")

    def __init__(self, type: str, line: int, code: str, description: str, confidence: float = 0.9):
        self.type = type
        self.line = line
        self.code = code
        self.description = description
        self.confidence = confidence


def walk_tree(node, visitor_fn, depth: int = 0, max_depth: int = 50):
    """Walk AST tree depth-first, calling visitor_fn(node, depth) on each node."""
    if depth > max_depth:
        return
    visitor_fn(node, depth)
    for child in node.children:
        walk_tree(child, visitor_fn, depth + 1, max_depth)


def find_nodes(root, node_type: str) -> list:
    """Find all nodes of a given type in the tree."""
    results = []

    def _visit(node, _depth):
        if node.type == node_type:
            results.append(node)

    walk_tree(root, _visit)
    return results


def find_ancestor(node, ancestor_type: str) -> Optional[object]:
    """Walk up the tree to find an ancestor of the given type."""
    current = node.parent
    while current:
        if current.type == ancestor_type:
            return current
        current = current.parent
    return None


def node_text(node) -> str:
    """Get the text content of a node."""
    return node.text.decode("utf-8") if node.text else ""


def has_child_type(node, child_type: str) -> bool:
    """Check if node has a direct child of the given type."""
    return any(c.type == child_type for c in node.children)


def find_child(node, child_type: str):
    """Find first direct child of given type."""
    for c in node.children:
        if c.type == child_type:
            return c
    return None
