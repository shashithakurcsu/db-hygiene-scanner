"""Reviewer assignment based on file patterns and violation types."""

import fnmatch
import os
from pathlib import Path
from typing import Optional

import structlog


class ReviewerAssigner:
    """Assigns reviewers based on file patterns and violation types.

    Loads configuration from .db-hygiene.yml or GITHUB_REVIEWER env var.
    """

    def __init__(
        self,
        config_path: str = ".db-hygiene.yml",
        env_var: str = "GITHUB_REVIEWER",
    ) -> None:
        self.logger = structlog.get_logger(logger_name="reviewer_assigner")
        self.config: dict = {}
        self.default_reviewer: Optional[str] = None

        # Priority: env var > config file
        env_reviewer = os.getenv(env_var)
        if env_reviewer:
            self.default_reviewer = env_reviewer
            self.logger.debug("reviewer_from_env", reviewer=env_reviewer)

        # Load config file
        config_file = Path(config_path)
        if config_file.exists():
            try:
                import yaml
                with open(config_file) as f:
                    self.config = yaml.safe_load(f) or {}
                if not self.default_reviewer:
                    self.default_reviewer = (
                        self.config.get("reviewers", {}).get("default", "security-team")
                    )
                self.logger.debug("config_loaded", path=config_path)
            except Exception as e:
                self.logger.warning("config_load_error", error=str(e))

        if not self.default_reviewer:
            self.default_reviewer = "security-team"

    def get_reviewer_for_path(self, filepath: str) -> str:
        """Get the appropriate reviewer for a given file path.

        Args:
            filepath: Path to the file that was modified.

        Returns:
            GitHub username or team slug.
        """
        by_pattern = self.config.get("reviewers", {}).get("by_file_pattern", {})

        for pattern, reviewer in by_pattern.items():
            if fnmatch.fnmatch(filepath, pattern):
                self.logger.debug("reviewer_matched", pattern=pattern, reviewer=reviewer)
                return reviewer

        return self.default_reviewer or "security-team"

    def get_reviewers_for_violation_type(self, violation_type: str) -> list[str]:
        """Get reviewers for a specific violation type.

        Args:
            violation_type: The violation type string.

        Returns:
            List of reviewer usernames.
        """
        by_type = self.config.get("reviewers", {}).get("by_violation_type", {})
        reviewer = by_type.get(violation_type)

        if reviewer:
            return [reviewer] if isinstance(reviewer, str) else reviewer

        return [self.default_reviewer or "security-team"]
