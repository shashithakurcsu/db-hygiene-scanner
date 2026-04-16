"""
Scanner pipeline for db-hygiene-scanner.

Orchestrates file discovery and violation detection across
multiple detectors running in parallel.
"""

import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any

import structlog

from db_hygiene_scanner.config import Config
from db_hygiene_scanner.models import ScanResult, Violation
from db_hygiene_scanner.scanner.base import BaseDetector
from db_hygiene_scanner.utils.file_discovery import FileInfo, discover_files, read_file_safe


class ScannerPipeline:
    """Main scanning pipeline that orchestrates file discovery and detector execution."""

    def __init__(self, config: Config, logger: structlog.BoundLogger) -> None:
        self.config = config
        self.logger = logger
        self.detectors: list[BaseDetector] = []

    def register_detector(self, detector: BaseDetector) -> None:
        """Register a violation detector."""
        self.detectors.append(detector)

    def scan(self, repo_path: str) -> ScanResult:
        """Execute the full scanning pipeline.

        Args:
            repo_path: Root directory to scan.

        Returns:
            ScanResult containing all violations and statistics.
        """
        start_time = time.time()
        self.logger.info("scan_started", repo_path=repo_path)

        files = discover_files(repo_path, self.config)
        self.logger.info("files_discovered", count=len(files))

        all_violations: list[Violation] = []
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for file_info in files:
                future = executor.submit(self._scan_file, file_info)
                futures.append((file_info, future))

            for file_info, future in futures:
                try:
                    violations = future.result()
                    all_violations.extend(violations)
                except Exception as e:
                    self.logger.warning(
                        "file_scan_error", file_path=file_info.path, error=str(e)
                    )

        stats = self._compute_stats(all_violations, len(files))
        duration = time.time() - start_time

        result = ScanResult(
            timestamp=datetime.utcnow(),
            repo_path=repo_path,
            violations=all_violations,
            stats={**stats, "scan_duration_seconds": duration},
        )

        self.logger.info("scan_completed", **stats)
        return result

    def _scan_file(self, file_info: FileInfo) -> list[Violation]:
        """Scan a single file with all applicable detectors, deduplicating results."""
        content = read_file_safe(file_info.path, self.config.max_file_size_kb)
        violations: list[Violation] = []
        seen: set[tuple[str, int]] = set()  # (violation_type, line_number)

        for detector in self.detectors:
            if detector.supports_language(file_info.language):
                try:
                    detected = detector.detect(file_info.path, content)
                    for v in detected:
                        key = (v.violation_type.value, v.line_number)
                        if key not in seen:
                            seen.add(key)
                            violations.append(v)
                except Exception as e:
                    self.logger.warning(
                        "detector_error",
                        detector=detector.__class__.__name__,
                        file=file_info.path,
                        error=str(e),
                    )

        return violations

    def _compute_stats(
        self, violations: list[Violation], files_scanned: int
    ) -> dict[str, Any]:
        """Compute scan statistics."""
        by_type: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        by_platform: dict[str, int] = defaultdict(int)
        by_language: dict[str, int] = defaultdict(int)

        for violation in violations:
            by_type[violation.violation_type.value] += 1
            by_severity[violation.severity.value] += 1
            by_platform[violation.platform.value] += 1
            by_language[violation.language.value] += 1

        return {
            "total_files_scanned": files_scanned,
            "total_violations": len(violations),
            "violations_by_type": dict(by_type),
            "violations_by_severity": dict(by_severity),
            "violations_by_platform": dict(by_platform),
            "violations_by_language": dict(by_language),
        }


__all__ = ["BaseDetector", "ScannerPipeline"]
