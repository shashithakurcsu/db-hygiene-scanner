"""Flask web application for db-hygiene-scanner interactive demo."""

import json
import os
import time
from datetime import datetime
from pathlib import Path
from threading import Thread

from flask import Flask, jsonify, render_template, request

app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "templates"),
    static_folder=str(Path(__file__).parent / "static"),
)

# Global state for the demo pipeline
pipeline_state = {
    "status": "idle",
    "step": 0,
    "scan_result": None,
    "classifications": [],
    "fixes": [],
    "reviews": [],
    "logs": [],
    "error": None,
}


def _get_mock_repo_path():
    base = Path(__file__).parent.parent.parent.parent / "demo" / "mock_bank_repo" / "src"
    return str(base) if base.exists() else None


def _log(msg):
    pipeline_state["logs"].append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "message": msg,
    })


def _run_scan(repo_path):
    """Run the scanning step."""
    from db_hygiene_scanner.config import Config
    from db_hygiene_scanner.scanner import ScannerPipeline
    from db_hygiene_scanner.scanner.detectors import (
        LongRunningTransactionDetector,
        ReadPreferenceDetector,
        SelectStarDetector,
        StringConcatSQLDetector,
        UnbatchedTransactionDetector,
    )
    from db_hygiene_scanner.utils.logging_config import get_logger

    logger = get_logger("web-scanner")
    api_key = os.environ.get("ANTHROPIC_API_KEY", "demo-key")
    config = Config(anthropic_api_key=api_key, scan_target_path="/tmp")

    pipeline = ScannerPipeline(config, logger)
    pipeline.register_detector(SelectStarDetector(config, logger))
    pipeline.register_detector(StringConcatSQLDetector(config, logger))
    pipeline.register_detector(UnbatchedTransactionDetector(config, logger))
    pipeline.register_detector(LongRunningTransactionDetector(config, logger))
    pipeline.register_detector(ReadPreferenceDetector(config, logger))

    result = pipeline.scan(repo_path)
    return result, config, logger


def _run_pipeline(repo_path):
    """Run the full pipeline in background."""
    try:
        pipeline_state["status"] = "scanning"
        pipeline_state["step"] = 1
        _log("Starting scan...")

        result, config, logger = _run_scan(repo_path)

        violations_data = []
        for v in result.violations:
            violations_data.append({
                "file_path": v.file_path,
                "file_name": v.file_path.split("/")[-1],
                "line_number": v.line_number,
                "line_content": v.line_content[:120],
                "violation_type": v.violation_type.value,
                "severity": v.severity.value,
                "platform": v.platform.value,
                "language": v.language.value,
                "description": v.description,
                "confidence_score": v.confidence_score,
            })

        pipeline_state["scan_result"] = {
            "total_violations": len(result.violations),
            "total_files": result.stats.get("total_files_scanned", 0),
            "duration": result.stats.get("scan_duration_seconds", 0),
            "by_type": result.stats.get("violations_by_type", {}),
            "by_platform": result.stats.get("violations_by_platform", {}),
            "by_severity": result.stats.get("violations_by_severity", {}),
            "by_language": result.stats.get("violations_by_language", {}),
            "violations": violations_data,
        }
        _log(f"Scan complete: {len(result.violations)} violations in {result.stats.get('total_files_scanned', 0)} files")

        # Pick 1 of each type for AI processing
        seen = set()
        sample = []
        for v in result.violations:
            if v.violation_type.value not in seen and len(sample) < 5:
                seen.add(v.violation_type.value)
                sample.append(v)

        # Check if API key is available for AI steps
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key or api_key == "demo-key":
            pipeline_state["status"] = "complete"
            pipeline_state["step"] = 5
            _log("No API key - skipping AI steps. Scan-only demo complete.")
            return

        # STEP 2: CLASSIFY
        pipeline_state["status"] = "classifying"
        pipeline_state["step"] = 2
        _log("Starting AI classification...")

        from db_hygiene_scanner.ai_engine.classifier import AIViolationClassifier
        config.ai_model_scan = "claude-sonnet-4-6"
        config.ai_model_fix = "claude-sonnet-4-6"
        config.ai_model_review = "claude-sonnet-4-6"
        classifier = AIViolationClassifier(config, logger)

        for i, v in enumerate(sample):
            _log(f"Classifying [{i+1}/{len(sample)}]: {v.violation_type.value}...")
            classified = classifier.classify_violation(v)
            pipeline_state["classifications"].append({
                "type": v.violation_type.value,
                "file": v.file_path.split("/")[-1],
                "line": v.line_number,
                "description": classified.description[:200],
                "confidence": classified.confidence_score,
                "severity": v.severity.value,
            })
            time.sleep(0.2)

        _log(f"Classification complete: {len(sample)} violations assessed")

        # STEP 3: FIX
        pipeline_state["status"] = "fixing"
        pipeline_state["step"] = 3
        _log("Starting AI fix generation...")

        from db_hygiene_scanner.ai_engine.fix_generator import FixGenerator
        fixer = FixGenerator(config, logger)

        fix_objects = []
        for i, v in enumerate(sample):
            _log(f"Generating fix [{i+1}/{len(sample)}]: {v.violation_type.value}...")
            fix = fixer.generate_fix(v)
            fix_objects.append(fix)
            pipeline_state["fixes"].append({
                "type": v.violation_type.value,
                "file": v.file_path.split("/")[-1],
                "line": v.line_number,
                "original": fix.original_code[:200],
                "fixed": fix.fixed_code[:500] if fix.fixed_code else "",
                "explanation": fix.explanation[:200],
                "confidence": fix.confidence_score,
                "has_fix": bool(fix.fixed_code),
            })
            time.sleep(0.2)

        generated = len([f for f in fix_objects if f.fixed_code])
        _log(f"Fix generation complete: {generated}/{len(sample)} fixes generated")

        # STEP 4: REVIEW
        pipeline_state["status"] = "reviewing"
        pipeline_state["step"] = 4
        _log("Starting security review...")

        from db_hygiene_scanner.ai_engine.fix_reviewer import FixReviewer
        reviewer = FixReviewer(config, logger)

        for i, fix in enumerate(fix_objects):
            if not fix.fixed_code:
                pipeline_state["reviews"].append({
                    "type": fix.violation.violation_type.value,
                    "approved": False,
                    "notes": "No fix to review",
                })
                continue
            _log(f"Reviewing fix [{i+1}/{len(fix_objects)}]: {fix.violation.violation_type.value}...")
            reviewed = reviewer.review_fix(fix)
            pipeline_state["reviews"].append({
                "type": fix.violation.violation_type.value,
                "file": fix.violation.file_path.split("/")[-1],
                "approved": reviewed.security_review_passed,
                "notes": reviewed.security_review_notes[:200],
            })
            time.sleep(0.2)

        approved = len([r for r in pipeline_state["reviews"] if r["approved"]])
        _log(f"Security review complete: {approved} approved, {len(pipeline_state['reviews']) - approved} rejected")

        pipeline_state["status"] = "complete"
        pipeline_state["step"] = 5
        _log("Pipeline complete!")

    except Exception as e:
        pipeline_state["status"] = "error"
        pipeline_state["error"] = str(e)
        _log(f"Error: {str(e)}")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/start", methods=["POST"])
def start_pipeline():
    """Start the pipeline in a background thread."""
    # Reset state
    pipeline_state.update({
        "status": "starting",
        "step": 0,
        "scan_result": None,
        "classifications": [],
        "fixes": [],
        "reviews": [],
        "logs": [],
        "error": None,
    })

    repo_path = _get_mock_repo_path()
    if not repo_path:
        return jsonify({"error": "Mock repo not found"}), 404

    thread = Thread(target=_run_pipeline, args=(repo_path,), daemon=True)
    thread.start()

    return jsonify({"status": "started"})


@app.route("/api/status")
def get_status():
    """Get current pipeline status."""
    return jsonify(pipeline_state)


@app.route("/api/scan-only", methods=["POST"])
def scan_only():
    """Run scan only (no AI) and return results immediately."""
    repo_path = _get_mock_repo_path()
    if not repo_path:
        return jsonify({"error": "Mock repo not found"}), 404

    result, _, _ = _run_scan(repo_path)

    violations = []
    for v in result.violations:
        violations.append({
            "file_name": v.file_path.split("/")[-1],
            "line_number": v.line_number,
            "line_content": v.line_content[:120],
            "violation_type": v.violation_type.value,
            "severity": v.severity.value,
            "platform": v.platform.value,
        })

    return jsonify({
        "total": len(violations),
        "stats": result.stats,
        "violations": violations,
    })


def run_server(port=5001, debug=False):
    """Run the Flask development server."""
    print(f"\n  db-hygiene-scanner Web UI")
    print(f"  Open: http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=debug)


if __name__ == "__main__":
    run_server(debug=True)
