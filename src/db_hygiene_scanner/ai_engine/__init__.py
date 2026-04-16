"""AI Engine orchestrator for db-hygiene-scanner.

Coordinates the full pipeline: classify -> generate fix -> security review.
"""

from typing import Any

import structlog

from db_hygiene_scanner.ai_engine.classifier import AIViolationClassifier
from db_hygiene_scanner.ai_engine.fix_generator import FixGenerator
from db_hygiene_scanner.ai_engine.fix_reviewer import FixReviewer
from db_hygiene_scanner.config import Config
from db_hygiene_scanner.models import Fix, Violation


class AIEngine:
    """Orchestrates the full AI pipeline: classify -> generate -> review."""

    def __init__(self, config: Config, logger: structlog.BoundLogger, dry_run: bool = False) -> None:
        self.config = config
        self.logger = logger
        self.classifier = AIViolationClassifier(config, logger)
        self.fix_generator = FixGenerator(config, logger, dry_run=dry_run)
        self.fix_reviewer = FixReviewer(config, logger)
        self.stats: dict[str, Any] = {
            "violations_classified": 0,
            "fixes_generated": 0,
            "fixes_approved": 0,
            "fixes_rejected": 0,
            "total_tokens_used": 0,
            "estimated_cost": 0.0,
        }

    def process_violations(
        self,
        violations: list[Violation],
        skip_classification: bool = False,
        skip_security_review: bool = False,
    ) -> list[Fix]:
        """Run the full AI pipeline on detected violations.

        Args:
            violations: List of detected violations.
            skip_classification: Skip AI classification (use scanner severity).
            skip_security_review: Skip security review (for dev speed).

        Returns:
            List of Fix objects ready for PR creation.
        """
        # Step 1: Classify
        if not skip_classification:
            violations = self.classifier.classify_batch(violations)
            self.stats["violations_classified"] = len(violations)

        # Step 2: Generate fixes
        fixes = self.fix_generator.generate_batch(violations)
        self.stats["fixes_generated"] = len([f for f in fixes if f.fixed_code])

        # Step 3: Security review
        if not skip_security_review:
            fixes = self.fix_reviewer.review_batch(fixes)

        # Step 4: Filter approved fixes
        approved = [f for f in fixes if f.security_review_passed or skip_security_review]
        self.stats["fixes_approved"] = len(approved)
        self.stats["fixes_rejected"] = len(fixes) - len(approved)

        self.logger.info("ai_pipeline_complete", **self.stats)
        return approved

    def get_stats(self) -> dict[str, Any]:
        """Return processing statistics."""
        return self.stats


__all__ = ["AIEngine", "AIViolationClassifier", "FixGenerator", "FixReviewer"]
