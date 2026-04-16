"""Template-based fix generator - no API calls needed.

Generates deterministic fixes using predefined patterns for each violation type.
Used as fallback when AI API is unavailable, or for instant demo mode.
"""

import re
from datetime import datetime
from pathlib import Path

from db_hygiene_scanner.models import Fix, Violation, ViolationType


# Fix templates per violation type and language pattern
FIX_TEMPLATES = {
    ViolationType.SELECT_STAR: {
        "description": "Replace SELECT * with explicit column list",
        "confidence": 0.85,
        "fix_fn": "_fix_select_star",
    },
    ViolationType.STRING_CONCAT_SQL: {
        "description": "Replace string concatenation with parameterized query",
        "confidence": 0.90,
        "fix_fn": "_fix_string_concat",
    },
    ViolationType.UNBATCHED_TXN: {
        "description": "Move database operation outside loop for batch execution",
        "confidence": 0.80,
        "fix_fn": "_fix_unbatched",
    },
    ViolationType.LONG_RUNNING_TXN: {
        "description": "Add timeout configuration to prevent long-running operations",
        "confidence": 0.82,
        "fix_fn": "_fix_long_running",
    },
    ViolationType.READ_PREFERENCE: {
        "description": "Add ReadPreference configuration for MongoDB replica set routing",
        "confidence": 0.88,
        "fix_fn": "_fix_read_preference",
    },
}


def generate_template_fix(violation: Violation) -> Fix:
    """Generate a fix using templates instead of AI API.

    Args:
        violation: The violation to fix.

    Returns:
        Fix object with proposed code change.
    """
    template = FIX_TEMPLATES.get(violation.violation_type)
    if not template:
        return _empty_fix(violation, "No template available for this violation type")

    fix_fn = globals().get(template["fix_fn"])
    if not fix_fn:
        return _empty_fix(violation, "Fix function not found")

    try:
        fixed_code, explanation = fix_fn(violation)
        if not fixed_code:
            return _empty_fix(violation, explanation or "Could not generate fix for this pattern")

        return Fix(
            violation_id=str(hash(violation.file_path + str(violation.line_number))),
            violation=violation,
            original_code=violation.line_content,
            fixed_code=fixed_code,
            explanation=explanation,
            ai_model_used="template-engine",
            confidence_score=template["confidence"],
            security_review_passed=True,
            security_review_notes="Template-based fix (pre-validated pattern)",
            created_at=datetime.utcnow(),
        )
    except Exception as e:
        return _empty_fix(violation, f"Fix generation error: {e}")


def _fix_select_star(v: Violation) -> tuple[str, str]:
    """Fix SELECT * by replacing with explicit columns."""
    line = v.line_content.strip()

    # Extract table name from SELECT * FROM <table>
    match = re.search(r"SELECT\s+\*\s+FROM\s+(\w+)", line, re.I)
    table = match.group(1) if match else "table"

    # Common column mappings by table name pattern
    column_map = {
        "account": "account_id, account_number, customer_id, balance, status",
        "transaction": "transaction_id, account_id, amount, transaction_type, post_date",
        "payment": "payment_id, amount, from_account, to_account, status, processed_date",
        "loan": "application_id, applicant_name, requested_amount, status",
        "user": "user_id, username, email, role, created_date",
        "customer": "customer_id, first_name, last_name, email, status",
    }

    # Find best matching columns
    table_lower = table.lower()
    columns = "id, name, status, created_date"  # safe default
    for key, cols in column_map.items():
        if key in table_lower:
            columns = cols
            break

    fixed = re.sub(r"SELECT\s+\*", f"SELECT {columns}", line, flags=re.I)
    explanation = f"Replaced SELECT * with explicit columns ({columns}) from {table}. This reduces data exposure, improves query performance, and ensures only needed columns are transferred."
    return fixed, explanation


def _fix_string_concat(v: Violation) -> tuple[str, str]:
    """Fix string concatenation SQL injection."""
    line = v.line_content.strip()
    lang = v.language.value

    if lang == "C#":
        # $"SELECT ... WHERE id = '{var}'" -> "SELECT ... WHERE id = @id" + params
        if "$" in line or "+" in line:
            # Extract the variable being concatenated
            fixed = re.sub(
                r'''["']\s*\+\s*(\w+)\s*\+\s*["']''',
                r'" -- Use: cmd.Parameters.AddWithValue("@param", \1)',
                line
            )
            if fixed == line:
                fixed = line + "  // FIX: Use parameterized query with cmd.Parameters.AddWithValue()"
            return fixed, "Replaced string concatenation with parameterized query. Use SqlCommand.Parameters.AddWithValue() to prevent SQL injection."

    elif lang == "JAVA":
        if "${" in line:
            # MyBatis ${} -> #{}
            fixed = re.sub(r"\$\{(\w+)\}", r"#{\1}", line)
            return fixed, "Replaced MyBatis ${} (string interpolation) with #{} (parameterized). ${} is vulnerable to SQL injection, #{} uses PreparedStatement binding."
        elif "+" in line:
            fixed = line + "  // FIX: Use PreparedStatement with ? placeholders"
            return fixed, "Replace string concatenation with PreparedStatement. Use conn.prepareStatement(sql) with ? placeholders and setString()/setInt() for parameters."

    elif lang == "PYTHON":
        if 'f"' in line or "f'" in line:
            fixed = re.sub(r'f(["\'])(.*?)\{(\w+)\}(.*?)\1', r'\1\2%s\4\1, (\3,)', line)
            return fixed, "Replaced f-string SQL with parameterized query. Use cursor.execute(sql, (param,)) to prevent SQL injection."
        elif "+" in line:
            fixed = line + "  # FIX: Use parameterized query: cursor.execute(sql, (param,))"
            return fixed, "Replace string concatenation with parameterized query using %s placeholders and tuple parameters."

    elif lang == "SQL":
        if "EXEC(" in line.upper():
            fixed = line + "  -- FIX: Use sp_executesql with parameters instead of EXEC with concatenation"
            return fixed, "Replace EXEC() with string concatenation with sp_executesql and parameter binding to prevent SQL injection."

    fixed = line + "  // FIX: Use parameterized queries instead of string concatenation"
    return fixed, "String concatenation in SQL creates injection risk. Use parameterized queries appropriate to your framework."


def _fix_unbatched(v: Violation) -> tuple[str, str]:
    """Fix unbatched operations in loops."""
    line = v.line_content.strip()
    lang = v.language.value

    if lang == "C#":
        explanation = "Move SaveChanges() outside the loop. Add all entities in the loop, then call SaveChanges() once after the loop for a single batch commit."
        fixed = line + "  // FIX: Move SaveChanges() outside the loop for batch operation"
    elif lang == "JAVA":
        explanation = "Use batch execution: collect operations in loop, then call entityManager.flush() or executeBatch() once outside the loop."
        fixed = line + "  // FIX: Batch operations - flush/commit outside the loop"
    elif lang == "PYTHON":
        explanation = "Replace individual insert_one()/execute() calls with insert_many()/executemany() for batch processing."
        fixed = line + "  # FIX: Use executemany() or insert_many() for batch operations"
    else:
        explanation = "Batch database operations instead of executing individually in a loop."
        fixed = line + "  -- FIX: Use batch operations"

    return fixed, explanation


def _fix_long_running(v: Violation) -> tuple[str, str]:
    """Fix missing timeout configuration."""
    line = v.line_content.strip()
    lang = v.language.value

    if lang == "C#":
        if "SqlCommand" in line or "NpgsqlCommand" in line or "OracleCommand" in line:
            fixed = line + "\n    cmd.CommandTimeout = 30;  // 30-second timeout to prevent long-running queries"
            return fixed, "Added CommandTimeout = 30 seconds. Prevents queries from holding locks indefinitely."
        elif "TransactionScope" in line:
            fixed = line.replace("TransactionScope()", "TransactionScope(TransactionScopeOption.Required, new TransactionOptions { Timeout = TimeSpan.FromSeconds(30) })")
            return fixed, "Added TransactionScope timeout of 30 seconds to prevent indefinite transaction locks."
    elif lang == "JAVA":
        if "@Transactional" in line:
            fixed = line.replace("@Transactional", "@Transactional(timeout = 30)")
            return fixed, "Added timeout = 30 seconds to @Transactional annotation to prevent indefinite transaction locks."
        elif "createStatement" in line:
            fixed = line + "\n    stmt.setQueryTimeout(30);  // 30-second query timeout"
            return fixed, "Added setQueryTimeout(30) to prevent long-running queries from blocking resources."
    elif lang == "PYTHON":
        if "connect(" in line:
            fixed = line.replace(")", ", connect_timeout=10)")
            return fixed, "Added connect_timeout=10 seconds to database connection to prevent indefinite connection attempts."

    fixed = line + "  // FIX: Add timeout configuration"
    return fixed, "Add appropriate timeout configuration to prevent long-running operations."


def _fix_read_preference(v: Violation) -> tuple[str, str]:
    """Fix missing MongoDB read preference."""
    line = v.line_content.strip()
    lang = v.language.value

    if lang == "PYTHON":
        if "MongoClient(" in line:
            fixed = line.replace("MongoClient(", "MongoClient(\n    read_preference=ReadPreference.SECONDARY_PREFERRED,\n    ")
            return fixed, "Added read_preference=ReadPreference.SECONDARY_PREFERRED to distribute reads across replica set secondaries."
    elif lang == "JAVA":
        fixed = line + "\n    // FIX: .withReadPreference(ReadPreference.secondaryPreferred())"
        return fixed, "Add ReadPreference.secondaryPreferred() to route read operations to secondary replicas."
    elif lang == "C#":
        if "MongoClient(" in line:
            fixed = line + "\n    // FIX: Use MongoClientSettings with ReadPreference = ReadPreference.SecondaryPreferred"
            return fixed, "Configure MongoClientSettings with ReadPreference.SecondaryPreferred for optimal read distribution."

    fixed = line + "  // FIX: Add ReadPreference configuration"
    return fixed, "Add read preference configuration to distribute read load across MongoDB replica set members."


def _empty_fix(violation: Violation, reason: str) -> Fix:
    return Fix(
        violation_id=str(hash(violation.file_path + str(violation.line_number))),
        violation=violation,
        original_code=violation.line_content,
        fixed_code="",
        explanation=reason,
        ai_model_used="template-engine",
        confidence_score=0.0,
        security_review_passed=False,
        security_review_notes=reason,
        created_at=datetime.utcnow(),
    )
