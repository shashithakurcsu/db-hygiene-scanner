"""
Data models for db-hygiene-scanner.

Pydantic V2 models providing type-safe data structures for violations,
fixes, scan results, and reports.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class ViolationType(str, Enum):
    """Types of database hygiene violations detected by the scanner."""

    SELECT_STAR = "SELECT_STAR"
    UNBATCHED_TXN = "UNBATCHED_TXN"
    LONG_RUNNING_TXN = "LONG_RUNNING_TXN"
    STRING_CONCAT_SQL = "STRING_CONCAT_SQL"
    READ_PREFERENCE = "READ_PREFERENCE"


class Severity(str, Enum):
    """Severity levels for detected violations."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"


class DatabasePlatform(str, Enum):
    """Supported database platforms."""

    MSSQL = "MSSQL"
    ORACLE = "ORACLE"
    MONGODB = "MONGODB"
    EDB_YUGABYTE = "EDB_YUGABYTE"


class ProgrammingLanguage(str, Enum):
    """Supported programming languages for source code analysis."""

    CSHARP = "C#"
    JAVA = "JAVA"
    PYTHON = "PYTHON"
    SQL = "SQL"


class Violation(BaseModel):
    """A detected database hygiene violation in source code."""

    file_path: str = Field(..., description="Absolute or relative path to the file")
    line_number: int = Field(..., ge=1, description="1-indexed line number of the violation")
    line_content: str = Field(..., description="The actual line of code containing the violation")
    violation_type: ViolationType = Field(..., description="Type of hygiene violation")
    severity: Severity = Field(..., description="CRITICAL or HIGH severity")
    platform: DatabasePlatform = Field(..., description="Detected database platform")
    language: ProgrammingLanguage = Field(..., description="Source code language")
    description: str = Field(..., description="Human-readable explanation of the violation")
    context_before: List[str] = Field(default_factory=list, description="Lines before the violation")
    context_after: List[str] = Field(default_factory=list, description="Lines after the violation")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Detection confidence (0.0-1.0)")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="When violation was detected")

    @field_validator("file_path")
    @classmethod
    def file_path_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("file_path must not be empty")
        return v

    @field_validator("line_content")
    @classmethod
    def line_content_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("line_content must not be empty")
        return v

    @field_validator("description")
    @classmethod
    def description_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("description must not be empty")
        return v


class Fix(BaseModel):
    """A proposed fix for a detected violation."""

    violation_id: str = Field(..., description="UUID or hash reference to the Violation")
    violation: Violation = Field(..., description="Reference to the original violation")
    original_code: str = Field(..., description="The problematic code snippet")
    fixed_code: str = Field(..., description="The proposed fix")
    explanation: str = Field(..., description="Why this fix resolves the violation")
    ai_model_used: str = Field(..., description="Which Claude model generated this fix")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Fix quality confidence (0.0-1.0)")
    security_review_passed: bool = Field(default=False, description="Was this fix security reviewed?")
    security_review_notes: str = Field(default="", description="Details from security review")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="When fix was generated")


class ScanResult(BaseModel):
    """Result of a complete scan operation."""

    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When the scan completed")
    repo_path: str = Field(..., description="The scanned repository path")
    violations: List[Violation] = Field(default_factory=list, description="All detected violations")
    stats: Dict[str, Any] = Field(default_factory=dict, description="Scan statistics")

    @field_validator("repo_path")
    @classmethod
    def repo_path_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("repo_path must not be empty")
        return v


class Report(BaseModel):
    """A comprehensive report of scan findings and proposed fixes."""

    scan_result: ScanResult = Field(..., description="The scan results")
    fixes: List[Fix] = Field(default_factory=list, description="Proposed fixes for violations")
    summary: str = Field(default="", description="Executive summary of findings")
    generated_at: datetime = Field(default_factory=datetime.utcnow, description="When report was generated")
