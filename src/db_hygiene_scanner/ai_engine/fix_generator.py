"""AI-powered fix generator using Claude API."""

import json
from datetime import datetime
from typing import Optional

import structlog

from db_hygiene_scanner.ai_engine.client import AIClient
from db_hygiene_scanner.ai_engine.prompts import FIX_GENERATION_PROMPT
from db_hygiene_scanner.config import Config, SecurityConfig
from db_hygiene_scanner.models import Fix, Violation
from db_hygiene_scanner.utils.security import sanitize_code, validate_ai_generated_fix


class FixGenerator:
    """Generates fixes for violations using Claude API."""

    def __init__(self, config: Config, logger: structlog.BoundLogger, dry_run: bool = False) -> None:
        self.config = config
        self.logger = logger
        self.client = AIClient(config, logger)
        self.security_config = SecurityConfig()
        self.dry_run = dry_run

    def generate_fix(self, violation: Violation) -> Fix:
        """Generate a fix for a single violation.

        Args:
            violation: The violation to fix.

        Returns:
            Fix object with proposed code change.
        """
        if self.dry_run:
            return Fix(
                violation_id=str(hash(violation.file_path + str(violation.line_number))),
                violation=violation,
                original_code=violation.line_content,
                fixed_code="",
                explanation="DRY RUN - no AI call made",
                ai_model_used=self.config.ai_model_fix,
                confidence_score=0.0,
                security_review_passed=False,
                security_review_notes="",
                created_at=datetime.utcnow(),
            )

        sanitized_code, _ = sanitize_code(violation.line_content, self.security_config)
        context = "\n".join(violation.context_before + [violation.line_content] + violation.context_after)

        prompt = FIX_GENERATION_PROMPT.format(
            original_code=sanitized_code,
            violation_type=violation.violation_type.value,
            database_platform=violation.platform.value,
            language=violation.language.value,
            context=context,
        )

        response = self.client.call(prompt, model=self.config.ai_model_fix)

        if response.get("error"):
            self.logger.error("fix_generation_failed", error=response["error"])
            return self._error_fix(violation, response["error"])

        try:
            result = self.client.parse_json_response(response["content"])
            fixed_code = result.get("fixed_code", "")
            confidence = float(result.get("confidence_score", 0.0))

            # Validate the generated fix
            is_valid, issues = validate_ai_generated_fix(
                violation.line_content, fixed_code, violation.language.value
            )

            fix = Fix(
                violation_id=str(hash(violation.file_path + str(violation.line_number))),
                violation=violation,
                original_code=violation.line_content,
                fixed_code=fixed_code,
                explanation=result.get("explanation", ""),
                ai_model_used=self.config.ai_model_fix,
                confidence_score=confidence,
                security_review_passed=is_valid,
                security_review_notes="; ".join(issues) if issues else "Passed basic validation",
                created_at=datetime.utcnow(),
            )

            self.logger.info(
                "fix_generated",
                type=violation.violation_type.value,
                confidence=confidence,
                valid=is_valid,
            )

            return fix

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            self.logger.warning("fix_parse_error", error=str(e))
            return self._error_fix(violation, str(e))

    def generate_batch(self, violations: list[Violation]) -> list[Fix]:
        """Generate fixes for multiple violations.

        Args:
            violations: List of violations to fix.

        Returns:
            List of Fix objects.
        """
        fixes = []
        for violation in violations:
            try:
                fix = self.generate_fix(violation)
                fixes.append(fix)
            except Exception as e:
                self.logger.error("batch_fix_error", error=str(e))
                fixes.append(self._error_fix(violation, str(e)))
        return fixes

    def _error_fix(self, violation: Violation, error_msg: str) -> Fix:
        """Create an error Fix object when generation fails."""
        return Fix(
            violation_id=str(hash(violation.file_path + str(violation.line_number))),
            violation=violation,
            original_code=violation.line_content,
            fixed_code="",
            explanation=f"Fix generation failed: {error_msg}",
            ai_model_used=self.config.ai_model_fix,
            confidence_score=0.0,
            security_review_passed=False,
            security_review_notes=f"Error: {error_msg}",
            created_at=datetime.utcnow(),
        )
