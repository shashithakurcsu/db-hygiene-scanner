"""GitHub integration orchestrator for db-hygiene-scanner."""

import structlog

from db_hygiene_scanner.github_integration.pr_creator import PRCreator
from db_hygiene_scanner.github_integration.reviewer_assigner import ReviewerAssigner
from db_hygiene_scanner.models import Fix, ScanResult


class GitHubIntegration:
    """Orchestrator for GitHub PR workflows."""

    def __init__(
        self,
        repo_owner: str,
        repo_name: str,
        github_token: str,
        config_path: str = ".db-hygiene.yml",
        dry_run: bool = False,
    ) -> None:
        self.logger = structlog.get_logger(logger_name="github_integration")
        self.pr_creator = PRCreator(repo_owner, repo_name, github_token, dry_run=dry_run)
        self.reviewer_assigner = ReviewerAssigner(config_path=config_path)

    def create_fix_pr(self, fixes: list[Fix], scan_result: ScanResult) -> str:
        """Create a PR with proposed fixes.

        Args:
            fixes: List of Fix objects to include in the PR.
            scan_result: ScanResult for PR description context.

        Returns:
            PR URL string.
        """
        reviewers = set()
        for fix in fixes:
            reviewer = self.reviewer_assigner.get_reviewer_for_path(fix.violation.file_path)
            if reviewer:
                reviewers.add(reviewer)

        pr_url = self.pr_creator.create_fix_pr(fixes, scan_result, list(reviewers))
        self.logger.info("fix_pr_created", url=pr_url, fixes=len(fixes))
        return pr_url

    def post_scan_comment(self, pr_number: int, scan_result: ScanResult) -> str:
        """Post scan results as a comment on an existing PR.

        Args:
            pr_number: PR number to comment on.
            scan_result: ScanResult to summarize.

        Returns:
            Comment URL.
        """
        return self.pr_creator.post_scan_comment(pr_number, scan_result)

    def add_labels(self, pr_number: int, labels: list[str]) -> None:
        """Add labels to an existing PR."""
        self.pr_creator.add_labels(pr_number, labels)


__all__ = ["GitHubIntegration", "PRCreator", "ReviewerAssigner"]
