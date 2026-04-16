"""AI-powered violation classifier using Claude API."""

import json
from typing import Any

import structlog

from db_hygiene_scanner.ai_engine.client import AIClient
from db_hygiene_scanner.ai_engine.prompts import CLASSIFICATION_PROMPT
from db_hygiene_scanner.config import Config
from db_hygiene_scanner.models import Violation
from db_hygiene_scanner.utils.security import sanitize_code
from db_hygiene_scanner.config import SecurityConfig


class AIViolationClassifier:
    """Classifies violations using Claude API for severity assessment."""

    def __init__(self, config: Config, logger: structlog.BoundLogger) -> None:
        self.config = config
        self.logger = logger
        self.client = AIClient(config, logger)
        self.security_config = SecurityConfig()

    def classify_violation(self, violation: Violation) -> Violation:
        """Classify a single violation using AI.

        Args:
            violation: The violation to classify.

        Returns:
            Updated Violation with AI-assessed severity and description.
        """
        sanitized_code, _ = sanitize_code(violation.line_content, self.security_config)
        context = "\n".join(violation.context_before + [violation.line_content] + violation.context_after)

        prompt = CLASSIFICATION_PROMPT.format(
            violation_type=violation.violation_type.value,
            database_platform=violation.platform.value,
            language=violation.language.value,
            code_snippet=sanitized_code,
            context=context,
        )

        response = self.client.call(prompt, model=self.config.ai_model_scan)

        if response.get("error"):
            self.logger.warning("classification_failed", error=response["error"])
            return violation

        try:
            result = self.client.parse_json_response(response["content"])
            if result.get("banking_risk_explanation"):
                violation.description = result["banking_risk_explanation"]
            if result.get("confidence_score"):
                violation.confidence_score = float(result["confidence_score"])

            self.logger.info(
                "violation_classified",
                type=violation.violation_type.value,
                ai_severity=result.get("severity"),
                confidence=result.get("confidence_score"),
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            self.logger.warning("classification_parse_error", error=str(e))

        return violation

    def classify_batch(self, violations: list[Violation]) -> list[Violation]:
        """Classify multiple violations.

        Args:
            violations: List of violations to classify.

        Returns:
            Updated list of violations with AI classifications.
        """
        classified = []
        for violation in violations:
            classified.append(self.classify_violation(violation))
        return classified
