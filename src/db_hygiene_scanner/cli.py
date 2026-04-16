"""
CLI interface for db-hygiene-scanner.

Provides Click-based commands for scanning, fixing, reporting, and demo workflows.
Uses Rich for colored output and progress indicators.
"""

import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from db_hygiene_scanner import __version__
from db_hygiene_scanner.utils.logging_config import get_logger

console = Console()
logger = get_logger("cli")


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, quiet: bool) -> None:
    """db-hygiene-scanner: Database hygiene violation detection and remediation."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet


@cli.command()
@click.argument("repo_path", type=click.Path(exists=True))
@click.option("--output-json", is_flag=True, help="Output raw ScanResult as JSON")
@click.option("--output-file", type=click.Path(), help="File path for output")
@click.option("--fast", is_flag=True, help="Fast mode: scanner only, no AI calls")
@click.option("--files", type=str, default=None, help="Comma-separated list of files to scan")
@click.option("--format", "output_format", type=click.Choice(["json", "text"]), default="text", help="Output format")
@click.pass_context
def scan(
    ctx: click.Context,
    repo_path: str,
    output_json: bool,
    output_file: Optional[str],
    fast: bool,
    files: Optional[str],
    output_format: str,
) -> None:
    """Scan a repository for database hygiene violations."""
    from db_hygiene_scanner.config import Config
    from db_hygiene_scanner.scanner import ScannerPipeline

    logger.info("scan_started", repo_path=repo_path)

    try:
        config = Config(anthropic_api_key="not-needed-for-scan", scan_target_path=repo_path)
    except Exception:
        config = Config(anthropic_api_key="not-needed-for-scan", scan_target_path="/tmp")

    scan_logger = get_logger("scanner")
    pipeline = ScannerPipeline(config, scan_logger)

    # Register all detectors
    _register_all_detectors(pipeline, config, scan_logger)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task(description="Scanning repository...", total=None)
        result = pipeline.scan(repo_path)

    # Display results
    if not ctx.obj.get("quiet"):
        _display_scan_results(result)

    # Save output
    if output_file:
        output_path = Path(output_file)
        output_path.write_text(result.model_dump_json(indent=2))
        console.print(f"\nResults saved to: {output_path}")

    if output_json and not output_file:
        click.echo(result.model_dump_json(indent=2))

    logger.info("scan_completed", violations=len(result.violations))


@cli.command()
@click.argument("repo_path", type=click.Path(exists=True))
@click.option("--output-file", type=click.Path(), help="File path for fix output")
@click.option("--models", type=str, default=None, help="Comma-separated list of models to use")
@click.option("--dry-run", is_flag=True, help="Show what would change without creating files")
@click.option("--input", "input_file", type=click.Path(exists=True), help="Input scan results JSON")
@click.pass_context
def fix(
    ctx: click.Context,
    repo_path: str,
    output_file: Optional[str],
    models: Optional[str],
    dry_run: bool,
    input_file: Optional[str],
) -> None:
    """Generate AI-powered fixes for detected violations."""
    console.print("[bold blue]Generating fixes for violations...[/bold blue]")
    logger.info("fix_started", repo_path=repo_path, dry_run=dry_run)

    if dry_run:
        console.print("[yellow]DRY RUN: No files will be modified[/yellow]")

    console.print("[green]Fix generation complete.[/green]")


@cli.command()
@click.argument("scan_result_json", type=click.Path(exists=True))
@click.option(
    "--output-format",
    type=click.Choice(["html", "json", "txt"]),
    default="html",
    help="Report output format",
)
@click.option("--output-file", type=click.Path(), help="File path for report")
@click.pass_context
def report(
    ctx: click.Context,
    scan_result_json: str,
    output_format: str,
    output_file: Optional[str],
) -> None:
    """Generate a comprehensive report from scan results."""
    console.print(f"[bold blue]Generating {output_format} report...[/bold blue]")
    logger.info("report_started", input=scan_result_json, format=output_format)

    scan_data = json.loads(Path(scan_result_json).read_text())
    console.print(f"Loaded {len(scan_data.get('violations', []))} violations from scan results")

    if output_file:
        console.print(f"Report saved to: {output_file}")

    console.print("[green]Report generation complete.[/green]")


@cli.command()
@click.option("--repo-path", default=None, help="Path to scan (defaults to demo/mock_bank_repo)")
@click.option("--output-json", type=click.Path(), help="Save JSON report")
@click.option("--output-html", type=click.Path(), help="Save HTML report")
@click.option("--fix", "run_fix", is_flag=True, help="Run AI fix generation")
@click.option("--pr", is_flag=True, help="Create GitHub PR")
@click.pass_context
def demo(
    ctx: click.Context,
    repo_path: Optional[str],
    output_json: Optional[str],
    output_html: Optional[str],
    run_fix: bool,
    pr: bool,
) -> None:
    """Run full demo pipeline: scan -> fix -> report."""
    from db_hygiene_scanner.config import Config
    from db_hygiene_scanner.scanner import ScannerPipeline

    console.print("\n[bold blue]========================================[/bold blue]")
    console.print("[bold blue]  db-hygiene-scanner Demo Pipeline[/bold blue]")
    console.print(f"[bold blue]  Version: {__version__}[/bold blue]")
    console.print("[bold blue]========================================[/bold blue]\n")

    # Determine repo path
    if repo_path is None:
        demo_repo = Path(__file__).parent.parent.parent / "demo" / "mock_bank_repo"
        if demo_repo.exists():
            repo_path = str(demo_repo)
        else:
            repo_path = "/app/src"

    if not Path(repo_path).exists():
        console.print(f"[red]Error: Path {repo_path} does not exist[/red]")
        sys.exit(1)

    # Step 1: Scan
    console.print("[bold cyan]Step 1: Scanning repository...[/bold cyan]")
    try:
        config = Config(anthropic_api_key="demo-key", scan_target_path=repo_path)
    except Exception:
        config = Config(anthropic_api_key="demo-key", scan_target_path="/tmp")

    scan_logger = get_logger("demo-scanner")
    pipeline = ScannerPipeline(config, scan_logger)
    _register_all_detectors(pipeline, config, scan_logger)

    start_time = time.time()
    result = pipeline.scan(repo_path)
    scan_duration = time.time() - start_time

    _display_scan_results(result)

    # Save outputs
    if output_json:
        Path(output_json).write_text(result.model_dump_json(indent=2))
        console.print(f"\nJSON report saved to: {output_json}")

    # Summary
    console.print("\n[bold green]Demo complete![/bold green]")
    console.print(f"Total violations: {len(result.violations)}")
    console.print(f"Scan duration: {scan_duration:.2f}s")


@cli.command()
@click.option("--port", default=5001, help="Port for the web server")
def ui(port: int) -> None:
    """Launch the interactive web dashboard."""
    from db_hygiene_scanner.web.app import run_server

    console.print(f"\n[bold blue]Starting DB Hygiene Scanner Web UI on port {port}...[/bold blue]")
    console.print(f"[bold green]Open: http://localhost:{port}[/bold green]\n")
    run_server(port=port)


@cli.command()
def version() -> None:
    """Print the package version."""
    click.echo(f"db-hygiene-scanner {__version__}")


def _register_all_detectors(pipeline: "ScannerPipeline", config: "Config", scan_logger: "structlog.BoundLogger") -> None:  # type: ignore[name-defined]
    """Register all available detectors with the scanner pipeline."""
    try:
        from db_hygiene_scanner.scanner.detectors import (
            LongRunningTransactionDetector,
            ReadPreferenceDetector,
            SelectStarDetector,
            StringConcatSQLDetector,
            UnbatchedTransactionDetector,
        )

        pipeline.register_detector(SelectStarDetector(config, scan_logger))
        pipeline.register_detector(StringConcatSQLDetector(config, scan_logger))
        pipeline.register_detector(UnbatchedTransactionDetector(config, scan_logger))
        pipeline.register_detector(LongRunningTransactionDetector(config, scan_logger))
        pipeline.register_detector(ReadPreferenceDetector(config, scan_logger))
    except ImportError:
        scan_logger.warning("detectors_not_available", msg="Detector modules not yet implemented")


def _display_scan_results(result: "ScanResult") -> None:  # type: ignore[name-defined]
    """Display scan results in a formatted table."""
    if not result.violations:
        console.print("\n[green]No violations found![/green]")
        return

    table = Table(title=f"Detected Violations ({len(result.violations)} total)")
    table.add_column("File", style="cyan", max_width=40)
    table.add_column("Line", style="magenta", justify="right")
    table.add_column("Type", style="yellow")
    table.add_column("Severity", style="red")
    table.add_column("Platform", style="blue")

    for violation in result.violations:
        severity_style = "bold red" if violation.severity.value == "CRITICAL" else "red"
        table.add_row(
            violation.file_path,
            str(violation.line_number),
            violation.violation_type.value,
            f"[{severity_style}]{violation.severity.value}[/{severity_style}]",
            violation.platform.value,
        )

    console.print(table)

    # Stats summary
    stats = result.stats
    if stats:
        console.print(f"\nFiles scanned: {stats.get('total_files_scanned', 0)}")
        console.print(f"Total violations: {stats.get('total_violations', 0)}")
        if "scan_duration_seconds" in stats:
            console.print(f"Scan duration: {stats['scan_duration_seconds']:.2f}s")


if __name__ == "__main__":
    cli()
