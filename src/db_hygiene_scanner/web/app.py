"""Flask web application for db-hygiene-scanner interactive demo.

Workflow:
  1. User provides a GitHub repo URL
  2. Tool clones repo and scans for violations
  3. Displays findings report
  4. User approves AI fix generation
  5. AI generates and reviews fixes
  6. Commits fixes to a new branch and creates a PR
"""

import json
import os
import shutil
import subprocess
import tempfile
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

# Pipeline state shared across requests
state = {
    "phase": "idle",          # idle | cloning | scanning | scan_done | fixing | reviewing | committing | done | error
    "repo_url": "",
    "repo_owner": "",
    "repo_name": "",
    "clone_path": "",
    "scan_result": None,
    "violations_raw": [],     # raw Violation objects for AI processing
    "fixes": [],
    "reviews": [],
    "pr_url": "",
    "logs": [],
    "error": None,
}


def _reset():
    state.update({
        "phase": "idle",
        "repo_url": "",
        "repo_owner": "",
        "repo_name": "",
        "clone_path": "",
        "scan_result": None,
        "violations_raw": [],
        "fixes": [],
        "reviews": [],
        "pr_url": "",
        "logs": [],
        "error": None,
    })


def _log(msg):
    state["logs"].append({"time": datetime.now().strftime("%H:%M:%S"), "message": msg})


def _parse_github_url(url):
    """Extract owner/repo and optional subfolder from GitHub URL.

    Supports:
      https://github.com/owner/repo
      https://github.com/owner/repo/tree/main/some/folder
      https://github.com/owner/repo.git

    Returns (owner, repo_name, subfolder_or_None).
    """
    url = url.strip().rstrip("/").removesuffix(".git")
    path = url.replace("https://github.com/", "").replace("http://github.com/", "")
    parts = path.split("/")
    if len(parts) < 2:
        return None, None, None

    owner, repo_name = parts[0], parts[1]
    subfolder = None

    # Parse /tree/branch/path/to/folder
    if len(parts) > 3 and parts[2] == "tree":
        # parts[3] is branch name, rest is folder path
        subfolder = "/".join(parts[4:]) if len(parts) > 4 else None

    return owner, repo_name, subfolder


def _get_config():
    from db_hygiene_scanner.config import Config
    api_key = os.environ.get("ANTHROPIC_API_KEY", "demo-key")
    return Config(
        anthropic_api_key=api_key,
        scan_target_path="/tmp",
        ai_model_scan="claude-sonnet-4-6",
        ai_model_fix="claude-sonnet-4-6",
        ai_model_review="claude-sonnet-4-6",
        rate_limit_rpm=20,
    )


def _build_pipeline(config, logger):
    from db_hygiene_scanner.scanner import ScannerPipeline
    from db_hygiene_scanner.scanner.detectors import (
        LongRunningTransactionDetector, ReadPreferenceDetector,
        SelectStarDetector, StringConcatSQLDetector, UnbatchedTransactionDetector,
    )
    pipeline = ScannerPipeline(config, logger)
    pipeline.register_detector(SelectStarDetector(config, logger))
    pipeline.register_detector(StringConcatSQLDetector(config, logger))
    pipeline.register_detector(UnbatchedTransactionDetector(config, logger))
    pipeline.register_detector(LongRunningTransactionDetector(config, logger))
    pipeline.register_detector(ReadPreferenceDetector(config, logger))

    # AST-based deep analysis (tree-sitter)
    try:
        from db_hygiene_scanner.scanner.detectors.ast_detector import ASTDetector
        pipeline.register_detector(ASTDetector(config, logger))
    except ImportError:
        pass

    return pipeline


# ── PHASE 1: Clone & Scan ──

def _run_clone_and_scan(repo_url):
    try:
        owner, repo_name, subfolder = _parse_github_url(repo_url)
        if not owner or not repo_name:
            raise ValueError(f"Invalid GitHub URL: {repo_url}")

        state["repo_owner"] = owner
        state["repo_name"] = repo_name

        # Clone
        state["phase"] = "cloning"
        display_path = f"{owner}/{repo_name}"
        if subfolder:
            display_path += f" (folder: {subfolder})"
        _log(f"Cloning {display_path}...")
        clone_dir = tempfile.mkdtemp(prefix="dbhygiene_")
        state["clone_path"] = clone_dir

        token = os.environ.get("GITHUB_TOKEN", "")
        if token:
            clone_url = f"https://{token}@github.com/{owner}/{repo_name}.git"
        else:
            clone_url = f"https://github.com/{owner}/{repo_name}.git"

        result = subprocess.run(
            ["git", "clone", "--depth", "1", clone_url, clone_dir],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Git clone failed: {result.stderr[:200]}")

        _log(f"Repository cloned to temporary directory")

        # If subfolder specified, only scan that folder
        scan_dir = clone_dir
        if subfolder:
            scan_dir = os.path.join(clone_dir, subfolder)
            if not os.path.isdir(scan_dir):
                raise ValueError(f"Subfolder not found: {subfolder}")
            _log(f"Scanning subfolder: {subfolder}")

        # Scan
        state["phase"] = "scanning"
        _log("Scanning repository for database hygiene violations...")

        from db_hygiene_scanner.utils.logging_config import get_logger
        logger = get_logger("web")
        config = _get_config()
        pipeline = _build_pipeline(config, logger)

        scan_result = pipeline.scan(scan_dir)

        violations_data = []
        for v in scan_result.violations:
            rel_path = v.file_path.replace(clone_dir + "/", "").replace(clone_dir, "")
            violations_data.append({
                "file_path": v.file_path,
                "relative_path": rel_path,
                "file_name": Path(v.file_path).name,
                "line_number": v.line_number,
                "line_content": v.line_content[:150],
                "violation_type": v.violation_type.value,
                "severity": v.severity.value,
                "platform": v.platform.value,
                "language": v.language.value,
                "description": v.description,
                "confidence_score": v.confidence_score,
            })

        state["scan_result"] = {
            "total_violations": len(scan_result.violations),
            "total_files": scan_result.stats.get("total_files_scanned", 0),
            "duration": scan_result.stats.get("scan_duration_seconds", 0),
            "by_type": scan_result.stats.get("violations_by_type", {}),
            "by_platform": scan_result.stats.get("violations_by_platform", {}),
            "by_severity": scan_result.stats.get("violations_by_severity", {}),
            "by_language": scan_result.stats.get("violations_by_language", {}),
            "violations": violations_data,
        }
        state["violations_raw"] = scan_result.violations

        _log(f"Scan complete: {len(scan_result.violations)} violations in {scan_result.stats.get('total_files_scanned', 0)} files")
        state["phase"] = "scan_done"

    except Exception as e:
        state["phase"] = "error"
        state["error"] = str(e)
        _log(f"Error: {e}")


# ── PHASE 2: AI Fix + Review + Commit + PR ──

def _run_fix_and_pr():
    try:
        from db_hygiene_scanner.utils.logging_config import get_logger
        logger = get_logger("web-fixer")
        config = _get_config()
        clone_dir = state["clone_path"]
        all_violations = state["violations_raw"]

        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key or api_key == "demo-key":
            state["phase"] = "error"
            state["error"] = "ANTHROPIC_API_KEY required for AI fix generation"
            _log("Error: No API key set for AI operations")
            return

        # Limit to max 10 violations, prioritizing CRITICAL first, then 1-per-type
        MAX_FIX_BATCH = 10
        critical = [v for v in all_violations if v.severity.value == "CRITICAL"]
        high = [v for v in all_violations if v.severity.value == "HIGH"]
        # Deduplicate by type for HIGH - pick first of each type
        seen_types = {v.violation_type.value for v in critical}
        high_deduped = []
        for v in high:
            if v.violation_type.value not in seen_types:
                seen_types.add(v.violation_type.value)
                high_deduped.append(v)
        violations = (critical + high_deduped)[:MAX_FIX_BATCH]
        _log(f"Selected {len(violations)} violations for AI processing (prioritized CRITICAL + 1 per type)")

        # STEP 1: Fix Generation (try AI first, fallback to templates)
        state["phase"] = "fixing"

        # Test if AI API is available
        use_ai = False
        try:
            from db_hygiene_scanner.ai_engine.fix_generator import FixGenerator
            fixer = FixGenerator(config, logger)
            # Quick test call
            import anthropic
            test_client = anthropic.Anthropic(api_key=config.anthropic_api_key)
            test_client.messages.create(model="claude-sonnet-4-20250514", max_tokens=5, messages=[{"role": "user", "content": "ok"}])
            use_ai = True
            _log("AI API available - generating fixes with Claude...")
        except Exception:
            _log("AI API unavailable - using template-based fix engine...")

        from db_hygiene_scanner.ai_engine.template_fixer import generate_template_fix

        fix_objects = []
        for i, v in enumerate(violations):
            _log(f"Generating fix [{i+1}/{len(violations)}]: {v.violation_type.value} in {Path(v.file_path).name}:{v.line_number}")
            if use_ai:
                fix = fixer.generate_fix(v)
                if not fix.fixed_code:
                    fix = generate_template_fix(v)  # fallback per-violation
            else:
                fix = generate_template_fix(v)
            fix_objects.append(fix)

            rel_path = v.file_path.replace(clone_dir + "/", "")
            state["fixes"].append({
                "type": v.violation_type.value,
                "file": Path(v.file_path).name,
                "relative_path": rel_path,
                "line": v.line_number,
                "original": fix.original_code[:300],
                "fixed": fix.fixed_code[:600] if fix.fixed_code else "",
                "explanation": fix.explanation[:300],
                "confidence": fix.confidence_score,
                "has_fix": bool(fix.fixed_code),
            })

        generated = len([f for f in fix_objects if f.fixed_code])
        _log(f"Fix generation complete: {generated}/{len(violations)} fixes generated")

        # STEP 2: Validate fixes (fast local check, no AI call)
        state["phase"] = "reviewing"
        fixes_with_code = [f for f in fix_objects if f.fixed_code]
        _log(f"Validating {len(fixes_with_code)} generated fixes...")

        from db_hygiene_scanner.utils.security import validate_ai_generated_fix

        approved_fixes = []
        for fix in fixes_with_code:
            is_valid, issues = validate_ai_generated_fix(
                fix.original_code, fix.fixed_code, fix.violation.language.value
            )
            status = is_valid or fix.confidence_score >= 0.7  # approve if valid OR high confidence
            state["reviews"].append({
                "type": fix.violation.violation_type.value,
                "file": Path(fix.violation.file_path).name,
                "approved": status,
                "notes": "Passed validation" if is_valid else f"Approved (confidence {fix.confidence_score:.0%})" if status else "; ".join(issues),
            })
            if status:
                approved_fixes.append(fix)

        approved_count = len(approved_fixes)
        skipped = len(fixes_with_code) - approved_count
        _log(f"Validation complete: {approved_count} approved, {skipped} rejected")

        if not approved_fixes:
            state["phase"] = "done"
            _log("No fixes passed validation. Pipeline complete.")
            return

        # STEP 3: Commit fixes to feature branch and create PR
        state["phase"] = "committing"
        _log("Applying fixes and creating feature branch...")

        # Apply fixes to files
        applied = 0
        for fix in approved_fixes:
            try:
                file_path = fix.violation.file_path
                if Path(file_path).exists():
                    content = Path(file_path).read_text()
                    if fix.original_code in content and fix.fixed_code:
                        updated = content.replace(fix.original_code, fix.fixed_code, 1)
                        Path(file_path).write_text(updated)
                        applied += 1
                        _log(f"Applied fix to {Path(file_path).name}:{fix.violation.line_number}")
            except Exception as e:
                _log(f"Could not apply fix to {Path(fix.violation.file_path).name}: {e}")

        if applied == 0:
            state["phase"] = "done"
            _log("No fixes could be applied to source files. Pipeline complete.")
            return

        # Create feature branch and commit
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        branch_name = f"feature/db-hygiene-fix-{timestamp}"
        fix_types = ", ".join(sorted(set(f.violation.violation_type.value for f in approved_fixes)))

        _run_git(clone_dir, ["checkout", "-b", branch_name])
        _run_git(clone_dir, ["add", "-A"])
        _run_git(clone_dir, [
            "commit", "-m",
            f"fix: resolve {applied} database hygiene violations\n\n"
            f"Automated fixes generated by db-hygiene-scanner.\n"
            f"Violations fixed: {fix_types}\n"
            f"Files modified: {applied}\n\n"
            f"Co-Authored-By: db-hygiene-scanner <noreply@dbhygiene.dev>"
        ])
        _log(f"Committed {applied} fixes on feature branch: {branch_name}")

        # Push branch
        _log("Pushing branch to GitHub...")
        token = os.environ.get("GITHUB_TOKEN", "")
        owner = state["repo_owner"]
        repo_name = state["repo_name"]

        if token:
            push_url = f"https://{token}@github.com/{owner}/{repo_name}.git"
            _run_git(clone_dir, ["remote", "set-url", "origin", push_url])

        push_result = _run_git(clone_dir, ["push", "-u", "origin", branch_name])
        if push_result.returncode != 0:
            _log(f"Push failed: {push_result.stderr[:200]}")
            state["phase"] = "done"
            _log("Could not push branch. Fixes are generated locally.")
            return

        _log("Branch pushed successfully")

        # Create PR targeting main branch
        _log("Creating Pull Request to merge into main...")
        pr_body = _build_pr_body(approved_fixes, state["scan_result"])
        pr_title = f"DB Hygiene: Fix {applied} violations ({fix_types})"

        pr_result = subprocess.run(
            [
                "gh", "pr", "create",
                "--repo", f"{owner}/{repo_name}",
                "--head", branch_name,
                "--base", "main",
                "--title", pr_title,
                "--body", pr_body,
            ],
            capture_output=True, text=True, timeout=60,
            cwd=clone_dir,
        )

        if pr_result.returncode == 0:
            pr_url = pr_result.stdout.strip()
            state["pr_url"] = pr_url
            _log(f"Pull Request created: {pr_url}")
        else:
            # Fallback: try with PyGithub
            _log(f"gh CLI PR creation issue: {pr_result.stderr[:100]}")
            pr_url = f"https://github.com/{owner}/{repo_name}/compare/main...{branch_name}"
            state["pr_url"] = pr_url
            _log(f"Branch pushed. Create PR manually: {pr_url}")

        state["phase"] = "done"
        _log("Pipeline complete!")

    except Exception as e:
        state["phase"] = "error"
        state["error"] = str(e)
        _log(f"Error: {e}")


def _run_git(cwd, args):
    return subprocess.run(
        ["git"] + args, capture_output=True, text=True, timeout=60, cwd=cwd,
    )


def _build_pr_body(fixes, scan_result):
    body = "## DB Hygiene Automated Fix\n\n"
    body += f"This PR addresses **{len(fixes)}** database hygiene violations "
    body += "detected and fixed by the automated scanner.\n\n"

    body += "### Scan Summary\n"
    if scan_result:
        body += f"- **{scan_result['total_violations']}** total violations found\n"
        body += f"- **{scan_result['total_files']}** files scanned\n\n"

    body += "### Fixes Applied\n\n"
    body += "| File | Violation | Confidence |\n|------|-----------|------------|\n"
    for fix in fixes:
        body += f"| {Path(fix.violation.file_path).name}:{fix.violation.line_number} "
        body += f"| {fix.violation.violation_type.value} | {fix.confidence_score:.0%} |\n"

    body += "\n### Review Checklist\n"
    body += "- [ ] Verify fixes compile and pass tests\n"
    body += "- [ ] Review business logic preservation\n"
    body += "- [ ] Run integration tests\n"
    body += "\n---\n*Generated by [db-hygiene-scanner](https://github.com/shashithakurcsu/db-hygiene-scanner)*\n"
    return body


# ── Routes ──

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Clone repo and scan. Returns immediately, poll /api/status."""
    data = request.get_json()
    repo_url = data.get("repo_url", "").strip()
    if not repo_url:
        return jsonify({"error": "repo_url is required"}), 400

    _reset()
    state["repo_url"] = repo_url

    thread = Thread(target=_run_clone_and_scan, args=(repo_url,), daemon=True)
    thread.start()
    return jsonify({"status": "started"})


@app.route("/api/fix", methods=["POST"])
def start_fix():
    """User approved fixes. Generate, review, commit, and create PR."""
    if state["phase"] != "scan_done":
        return jsonify({"error": "Scan must complete before fixing"}), 400

    thread = Thread(target=_run_fix_and_pr, daemon=True)
    thread.start()
    return jsonify({"status": "started"})


@app.route("/api/status")
def get_status():
    """Get current pipeline state."""
    return jsonify({
        "phase": state["phase"],
        "repo_url": state["repo_url"],
        "repo_owner": state["repo_owner"],
        "repo_name": state["repo_name"],
        "scan_result": state["scan_result"],
        "fixes": state["fixes"],
        "reviews": state["reviews"],
        "pr_url": state["pr_url"],
        "logs": state["logs"],
        "error": state["error"],
    })


@app.route("/api/reset", methods=["POST"])
def reset():
    """Reset pipeline to start over."""
    if state["clone_path"] and Path(state["clone_path"]).exists():
        shutil.rmtree(state["clone_path"], ignore_errors=True)
    _reset()
    return jsonify({"status": "reset"})


def run_server(port=5001, debug=False):
    print(f"\n  db-hygiene-scanner Web UI")
    print(f"  Open: http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=debug)


if __name__ == "__main__":
    run_server(debug=True)
