"""GitHub PR creator for automated fix deployment."""

import time
from datetime import datetime
from typing import Optional

import structlog

from db_hygiene_scanner.models import Fix, ScanResult


class PullRequestError(Exception):
    """Error during PR creation."""


class PRCreator:
    """Creates GitHub PRs with proposed fixes from the scanner."""

    def __init__(
        self,
        repo_owner: str,
        repo_name: str,
        github_token: str,
        dry_run: bool = False,
    ) -> None:
        self.repo_owner = repo_owner
        self.repo_name = repo_name
        self.github_token = github_token
        self.dry_run = dry_run
        self.logger = structlog.get_logger(logger_name="pr_creator")
        self._github: Optional[object] = None
        self._repo: Optional[object] = None

    def _get_repo(self) -> object:
        """Lazily initialize GitHub repo object."""
        if self._repo is None:
            from github import Github
            self._github = Github(self.github_token)
            self._repo = self._github.get_repo(f"{self.repo_owner}/{self.repo_name}")  # type: ignore
        return self._repo  # type: ignore

    def create_fix_pr(
        self,
        fixes: list[Fix],
        scan_result: ScanResult,
        reviewers: Optional[list[str]] = None,
    ) -> str:
        """Create a PR with proposed fixes.

        Args:
            fixes: List of Fix objects.
            scan_result: ScanResult for context.
            reviewers: GitHub usernames to assign as reviewers.

        Returns:
            PR URL string.
        """
        if not fixes:
            self.logger.info("no_fixes_to_create_pr")
            return ""

        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        branch_name = f"hygiene-fix/{timestamp}"

        # Build PR description
        violation_types = set(f.violation.violation_type.value for f in fixes)
        primary_category = ", ".join(sorted(violation_types))
        title = f"DB Hygiene: Fix {len(fixes)} violations ({primary_category})"

        body = self._build_pr_body(fixes, scan_result)

        if self.dry_run:
            self.logger.info(
                "dry_run_pr",
                branch=branch_name,
                title=title,
                fixes=len(fixes),
            )
            return f"https://github.com/{self.repo_owner}/{self.repo_name}/pull/DRY-RUN"

        try:
            repo = self._get_repo()

            # Create branch from default branch
            default_branch = repo.default_branch  # type: ignore
            source = repo.get_branch(default_branch)  # type: ignore
            repo.create_git_ref(  # type: ignore
                ref=f"refs/heads/{branch_name}",
                sha=source.commit.sha,
            )

            # Commit fixes
            for fix in fixes:
                if fix.fixed_code:
                    try:
                        contents = repo.get_contents(fix.violation.file_path, ref=branch_name)  # type: ignore
                        original = contents.decoded_content.decode("utf-8")  # type: ignore
                        updated = original.replace(fix.original_code, fix.fixed_code)
                        repo.update_file(  # type: ignore
                            fix.violation.file_path,
                            f"Fix: {fix.violation.violation_type.value} in {fix.violation.file_path}",
                            updated,
                            contents.sha,  # type: ignore
                            branch=branch_name,
                        )
                    except Exception as e:
                        self.logger.warning("commit_fix_error", file=fix.violation.file_path, error=str(e))

            # Determine if draft
            avg_confidence = sum(f.confidence_score for f in fixes) / len(fixes)
            is_draft = avg_confidence < 0.85

            # Create PR
            pr = repo.create_pull(  # type: ignore
                title=title,
                body=body,
                head=branch_name,
                base=default_branch,
                draft=is_draft,
            )

            # Add labels
            pr.add_to_labels("db-hygiene", "automated-fix")  # type: ignore

            # Assign reviewers
            if reviewers:
                try:
                    pr.create_review_request(reviewers=reviewers)  # type: ignore
                except Exception as e:
                    self.logger.warning("reviewer_assignment_error", error=str(e))

            self.logger.info("pr_created", url=pr.html_url, draft=is_draft)  # type: ignore
            return pr.html_url  # type: ignore

        except Exception as e:
            self.logger.error("pr_creation_failed", error=str(e))
            raise PullRequestError(f"Failed to create PR: {e}") from e

    def post_scan_comment(self, pr_number: int, scan_result: ScanResult) -> str:
        """Post scan summary as a PR comment.

        Args:
            pr_number: PR number.
            scan_result: ScanResult to summarize.

        Returns:
            Comment URL.
        """
        if self.dry_run:
            self.logger.info("dry_run_comment", pr=pr_number)
            return ""

        repo = self._get_repo()
        pr = repo.get_pull(pr_number)  # type: ignore

        body = "## DB Hygiene Scan Results\n\n"
        violations = scan_result.violations

        if not violations:
            body += "No violations detected.\n"
        else:
            body += f"**{len(violations)} violation(s) detected**\n\n"
            body += "| Type | Count | Severity |\n|------|-------|----------|\n"

            from collections import Counter
            type_counts = Counter(v.violation_type.value for v in violations)
            for vtype, count in type_counts.most_common():
                body += f"| {vtype} | {count} | HIGH |\n"

        body += "\n---\n*Generated by db-hygiene-scanner*"

        comment = pr.create_issue_comment(body)  # type: ignore
        return comment.html_url  # type: ignore

    def add_labels(self, pr_number: int, labels: list[str]) -> None:
        """Add labels to an existing PR."""
        if self.dry_run:
            return

        repo = self._get_repo()
        pr = repo.get_pull(pr_number)  # type: ignore
        for label in labels:
            pr.add_to_labels(label)  # type: ignore

    def _build_pr_body(self, fixes: list[Fix], scan_result: ScanResult) -> str:
        """Build the PR description body."""
        body = "## DB Hygiene Automated Fix\n\n"
        body += f"This PR addresses **{len(fixes)}** database hygiene violations "
        body += "detected by the automated scanner.\n\n"

        body += "### Fixes Applied\n\n"
        body += "| File | Violation | Confidence |\n"
        body += "|------|-----------|------------|\n"

        for fix in fixes:
            body += (
                f"| {fix.violation.file_path}:{fix.violation.line_number} "
                f"| {fix.violation.violation_type.value} "
                f"| {fix.confidence_score:.0%} |\n"
            )

        body += "\n### Testing Recommendations\n\n"
        body += "- [ ] Verify all fixes compile and pass existing tests\n"
        body += "- [ ] Review each fix for business logic preservation\n"
        body += "- [ ] Run integration tests against test database\n"

        body += "\n---\n*Generated by db-hygiene-scanner*\n"
        return body
