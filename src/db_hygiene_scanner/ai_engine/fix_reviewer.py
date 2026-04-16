"""AI-powered security reviewer for proposed fixes."""

import json
from typing import Any

import structlog

from db_hygiene_scanner.ai_engine.client import AIClient
from db_hygiene_scanner.ai_engine.prompts import SECURITY_REVIEW_PROMPT
from db_hygiene_scanner.config import Config
from db_hygiene_scanner.models import Fix


class FixReviewer:
    """Independent security review of proposed fixes using Claude API."""

    def __init__(self, config: Config, logger: structlog.BoundLogger) -> None:
        self.config = config
        self.logger = logger
        self.client = AIClient(config, logger)

    def review_fix(self, fix: Fix) -> Fix:
        """Review a single fix for security issues.

        Uses an independent AI conversation (not shared with fix generation).

        Args:
            fix: The Fix to review.

        Returns:
            Updated Fix with security review results.
        """
        if not fix.fixed_code:
            fix.security_review_passed = False
            fix.security_review_notes = "No fixed code to review"
            return fix

        prompt = SECURITY_REVIEW_PROMPT.format(
            original_code=fix.original_code,
            fixed_code=fix.fixed_code,
            violation_type=fix.violation.violation_type.value,
            language=fix.violation.language.value,
            database_platform=fix.violation.platform.value,
        )

        response = self.client.call(prompt, model=self.config.ai_model_review)

        if response.get("error"):
            self.logger.warning("review_failed", error=response["error"])
            fix.security_review_passed = False
            fix.security_review_notes = f"Review failed: {response['error']}"
            return fix

        try:
            result = self.client.parse_json_response(response["content"])
            fix.security_review_passed = result.get("approved", False)
            fix.security_review_notes = result.get("review_notes", "")

            issues = result.get("issues", [])
            if issues:
                issue_texts = [
                    f"{i.get('severity', 'UNKNOWN')}: {i.get('issue', '')}" for i in issues
                ]
                fix.security_review_notes += " Issues: " + "; ".join(issue_texts)

            self.logger.info(
                "fix_reviewed",
                approved=fix.security_review_passed,
                risk_level=result.get("risk_level"),
                issues_count=len(issues),
            )

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            self.logger.warning("review_parse_error", error=str(e))
            fix.security_review_passed = False
            fix.security_review_notes = f"Review parse error: {e}"

        return fix

    def review_batch(self, fixes: list[Fix]) -> list[Fix]:
        """Review multiple fixes.

        Args:
            fixes: List of fixes to review.

        Returns:
            Updated list of fixes with review results.
        """
        reviewed = []
        for fix in fixes:
            reviewed.append(self.review_fix(fix))
        return reviewed
