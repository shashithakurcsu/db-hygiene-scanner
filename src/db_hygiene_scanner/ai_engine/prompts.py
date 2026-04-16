"""Prompt templates for AI-powered violation classification, fix generation, and review."""

SYSTEM_MESSAGE = (
    "You are a senior database security engineer at a major regulated financial institution. "
    "Your expertise spans SQL Server, Oracle, MongoDB, and PostgreSQL/EDB/Yugabyte. "
    "You produce code that would pass a strict security review in a banking environment."
)

CLASSIFICATION_PROMPT = """
Given the following code violation:

Violation Type: {violation_type}
Database Platform: {database_platform}
Language: {language}
Code Snippet:
{code_snippet}

Context: {context}

Task:
1. Confirm that this is indeed a {violation_type} violation (answer: yes/no, briefly why)
2. Assess the severity in a banking context: CRITICAL, HIGH, MEDIUM, or LOW
3. Explain the specific risk this poses to financial data integrity and security
4. For SQL violations, explain the attack vector (if any)
5. Identify any related violations that might exist in similar patterns

You MUST respond with ONLY valid JSON:
{{
  "confirmed": true,
  "severity": "CRITICAL",
  "banking_risk_explanation": "explanation",
  "attack_vector": "explanation or null",
  "remediation_priority": "immediate|high|medium|low",
  "related_patterns": [],
  "confidence_score": 0.95
}}
"""

FIX_GENERATION_PROMPT = """
CRITICAL RULES:
- Only change what is necessary to fix the violation
- Preserve all business logic and error handling
- Follow the idiomatic patterns of the language
- Do NOT introduce new libraries unless absolutely necessary
- Assume the fix will be deployed to production handling real financial transactions

Original Code:
{original_code}

Violation: {violation_type}
Database Platform: {database_platform}
Language: {language}
Surrounding Context:
{context}

Task:
1. Generate a fixed version that eliminates the {violation_type} violation
2. Ensure the fix is syntactically correct for {language}
3. Include inline comments explaining ONLY the changes made
4. Rate your confidence that this fix is correct and safe (0.0-1.0)

You MUST respond with ONLY valid JSON:
{{
  "fixed_code": "the complete corrected code block",
  "explanation": "2-3 sentences explaining what changed and why",
  "confidence_score": 0.92,
  "breaking_changes": ["none"],
  "dependencies_added": [],
  "testing_recommendations": ["test scenario 1"]
}}
"""

SECURITY_REVIEW_PROMPT = """
Original Code:
{original_code}

Proposed Fix:
{fixed_code}

Violation Type Being Fixed: {violation_type}
Language: {language}
Database Platform: {database_platform}

Review Checklist:
1. Does the fix actually solve the stated violation?
2. Are there any NEW SQL injection vectors introduced?
3. Are there any NEW credential exposure risks?
4. Does error handling remain robust?
5. Is transaction safety preserved?
6. Will this code scale?
7. Does it follow best practices?
8. Any subtle security issues (timing attacks, race conditions)?

You MUST respond with ONLY valid JSON:
{{
  "approved": true,
  "risk_level": "NONE",
  "issues": [],
  "recommendations": [],
  "review_notes": "Summary of security review findings"
}}
"""

PR_DESCRIPTION_PROMPT = """
Generate a PR description for the following fixes:

Fixes Summary:
{fixes_summary}

Total Violations Fixed: {total_count}
Categories: {categories}

Guidelines:
- Start with a concise summary (2-3 sentences)
- List each fix with violation type, file, and brief explanation
- Include testing recommendations
- Keep it under 200 words

Output plain text PR description.
"""
