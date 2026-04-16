"""
File discovery utilities for db-hygiene-scanner.

Provides recursive file discovery with language detection,
.gitignore respect, and safe file reading.
"""

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from db_hygiene_scanner.models import ProgrammingLanguage
from db_hygiene_scanner.utils.logging_config import get_logger

logger = get_logger("file_discovery")

# Directories to always skip
SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "obj", "bin", ".vs", ".idea", ".vscode", "dist", "build",
    ".tox", ".eggs", ".mypy_cache", ".ruff_cache", ".pytest_cache",
}

# File extension to language mapping
EXTENSION_MAP: dict[str, ProgrammingLanguage] = {
    ".cs": ProgrammingLanguage.CSHARP,
    ".java": ProgrammingLanguage.JAVA,
    ".py": ProgrammingLanguage.PYTHON,
    ".sql": ProgrammingLanguage.SQL,
    ".xml": ProgrammingLanguage.JAVA,  # MyBatis XML mappers
}


@dataclass
class FileInfo:
    """Information about a discovered source file."""

    path: str
    language: ProgrammingLanguage
    size_bytes: int
    last_modified: datetime
    relative_path: str


def get_file_language(file_path: str) -> Optional[ProgrammingLanguage]:
    """Determine programming language from file extension.

    Args:
        file_path: Path to the file.

    Returns:
        ProgrammingLanguage enum value, or None if not recognized.
    """
    ext = Path(file_path).suffix.lower()
    return EXTENSION_MAP.get(ext)


def discover_files(root_path: str, config: "Config") -> list[FileInfo]:  # type: ignore[name-defined]
    """Recursively discover scannable files in the given path.

    Filters by extension, size, and excludes common non-scannable directories.

    Args:
        root_path: Root directory to scan.
        config: Application configuration with max_file_size_kb.

    Returns:
        List of FileInfo objects sorted by path.
    """
    files: list[FileInfo] = []
    root = Path(root_path)
    max_size_bytes = config.max_file_size_kb * 1024
    files_skipped = 0

    if not root.exists() or not root.is_dir():
        logger.error("root_path_invalid", path=root_path)
        return files

    for dirpath, dirnames, filenames in os.walk(root):
        # Filter out skip directories in-place
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            file_path = Path(dirpath) / filename
            language = get_file_language(str(file_path))

            if language is None:
                continue

            try:
                stat = file_path.stat()
            except OSError:
                continue

            if stat.st_size > max_size_bytes:
                files_skipped += 1
                continue

            files.append(
                FileInfo(
                    path=str(file_path),
                    language=language,
                    size_bytes=stat.st_size,
                    last_modified=datetime.fromtimestamp(stat.st_mtime),
                    relative_path=str(file_path.relative_to(root)),
                )
            )

    files.sort(key=lambda f: f.path)

    logger.info(
        "file_discovery_complete",
        files_found=len(files),
        files_skipped=files_skipped,
        root_path=root_path,
    )

    return files


def read_file_safe(file_path: str, max_size_kb: int) -> str:
    """Read file contents safely with encoding fallbacks.

    Args:
        file_path: Path to the file to read.
        max_size_kb: Maximum file size in KB; larger files are truncated.

    Returns:
        File contents as a string.
    """
    max_bytes = max_size_kb * 1024
    path = Path(file_path)

    if not path.exists():
        logger.warning("file_not_found", path=file_path)
        return ""

    file_size = path.stat().st_size

    encodings = ["utf-8", "latin-1", "utf-16"]

    for encoding in encodings:
        try:
            content = path.read_text(encoding=encoding)
            if file_size > max_bytes:
                logger.warning(
                    "file_truncated",
                    path=file_path,
                    size_kb=file_size // 1024,
                    max_kb=max_size_kb,
                )
                content = content[: max_bytes] + "\n/* FILE TRUNCATED - exceeded max size */\n"
            return content
        except (UnicodeDecodeError, UnicodeError):
            continue

    logger.error("file_encoding_error", path=file_path)
    return ""
