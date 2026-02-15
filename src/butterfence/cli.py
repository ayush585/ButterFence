"""Typer CLI: init, audit, report, status commands."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from butterfence import __version__

app = typer.Typer(
    name="butterfence",
    help="Claude Code safety harness - red-team and protect your repos.",
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"ButterFence v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-v", help="Show version.", callback=_version_callback, is_eager=True
    ),
) -> None:
    """ButterFence - Claude Code safety harness."""


@app.command()
def init(
    force: bool = typer.Option(False, "--force", help="Overwrite existing config"),
    no_hooks: bool = typer.Option(False, "--no-hooks", help="Skip hook installation"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Initialize ButterFence in the current project."""
    from butterfence.config import DEFAULT_CONFIG, load_config, save_config, validate_config
    from butterfence.installer import install_hooks
    from butterfence.utils import deep_merge, load_json

    console.print(Panel("[bold]ButterFence Init[/bold]", style="blue"))

    # Create .butterfence directories
    bf_dir = project_dir / ".butterfence"
    (bf_dir / "logs").mkdir(parents=True, exist_ok=True)
    (bf_dir / "reports").mkdir(parents=True, exist_ok=True)

    # Write config
    config_path = bf_dir / "config.json"
    if config_path.exists() and not force:
        existing = load_json(config_path)
        config = deep_merge(DEFAULT_CONFIG, existing)
        console.print("  [yellow]Merged with existing config[/yellow]")
    else:
        config = DEFAULT_CONFIG.copy()
        console.print("  [green]Created default config[/green]")

    errors = validate_config(config)
    if errors:
        for e in errors:
            console.print(f"  [red]Config error: {e}[/red]")
        raise typer.Exit(1)

    save_config(config, project_dir)
    console.print(f"  Config: [cyan]{config_path}[/cyan]")

    # Install hooks
    if not no_hooks:
        settings_path = install_hooks(project_dir)
        console.print(f"  Hooks: [cyan]{settings_path}[/cyan]")
    else:
        console.print("  Hooks: [yellow]skipped[/yellow]")

    # Summary
    cat_count = len(config.get("categories", {}))
    pattern_count = sum(
        len(c.get("patterns", [])) for c in config.get("categories", {}).values()
    )
    console.print("")
    console.print(
        Panel(
            f"[green]ButterFence initialized![/green]\n"
            f"  Categories: {cat_count}\n"
            f"  Patterns: {pattern_count}\n"
            f"  Hooks: {'installed' if not no_hooks else 'skipped'}\n\n"
            f"Next: run [bold]butterfence audit[/bold] to test your defenses.",
            title="Ready",
            style="green",
        )
    )


@app.command()
def audit(
    quick: bool = typer.Option(False, "--quick", help="Critical scenarios only"),
    category: str = typer.Option(None, "--category", "-c", help="Filter by category"),
    scenario: str = typer.Option(None, "--scenario", "-s", help="Run specific scenario"),
    report_flag: bool = typer.Option(False, "--report", "-r", help="Generate report after audit"),
    verbose: bool = typer.Option(False, "--verbose", help="Show detailed match info"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Run red-team audit scenarios against current configuration."""
    from butterfence.audit import run_audit
    from butterfence.config import load_config
    from butterfence.report import generate_report
    from butterfence.scoring import calculate_score

    console.print(Panel("[bold]ButterFence Audit[/bold]", style="blue"))

    config = load_config(project_dir)

    with console.status("[bold blue]Running scenarios...[/bold blue]"):
        results = run_audit(
            config=config,
            category_filter=category,
            scenario_filter=scenario,
            quick=quick,
        )

    # Display results table
    table = Table(title="Audit Results", show_lines=True)
    table.add_column("Status", style="bold", width=6)
    table.add_column("ID", width=12)
    table.add_column("Name", width=30)
    table.add_column("Category", width=18)
    table.add_column("Severity", width=10)
    table.add_column("Decision", width=10)

    passed = 0
    failed = 0
    for r in results:
        if r.passed:
            passed += 1
            status = "[green]PASS[/green]"
        else:
            failed += 1
            status = "[red]FAIL[/red]"

        sev_style = {
            "critical": "red bold",
            "high": "yellow",
            "medium": "blue",
            "low": "dim",
        }.get(r.severity, "")

        table.add_row(
            status,
            r.id,
            r.name,
            r.category,
            f"[{sev_style}]{r.severity}[/{sev_style}]" if sev_style else r.severity,
            r.actual_decision,
        )

        if verbose and r.match_result.matches:
            for m in r.match_result.matches:
                console.print(f"    [dim]  matched: {m.pattern}[/dim]")

    console.print(table)
    console.print(
        f"\n[bold]Results:[/bold] [green]{passed} passed[/green], "
        f"[red]{failed} failed[/red] / {len(results)} total"
    )

    # Scoring
    audit_dicts = [
        {
            "id": r.id,
            "name": r.name,
            "category": r.category,
            "severity": r.severity,
            "passed": r.passed,
            "expected_decision": r.expected_decision,
            "actual_decision": r.actual_decision,
            "reason": r.reason,
        }
        for r in results
    ]

    score = calculate_score(audit_dicts, config)

    score_color = "green" if score.total_score >= 90 else "yellow" if score.total_score >= 70 else "red"
    console.print(
        f"\n[bold]Score:[/bold] [{score_color}]{score.total_score}/{score.max_score}[/{score_color}] "
        f"| Grade: [bold]{score.grade}[/bold] ({score.grade_label})"
    )

    # Generate report if requested
    if report_flag:
        report_path = project_dir / ".butterfence" / "reports" / "latest_report.md"
        report_text = generate_report(score, audit_dicts, report_path)
        console.print(f"\n[green]Report saved to:[/green] {report_path}")


@app.command()
def report(
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Generate a safety report from the latest audit."""
    from butterfence.audit import run_audit
    from butterfence.config import load_config
    from butterfence.report import generate_report
    from butterfence.scoring import calculate_score

    console.print(Panel("[bold]ButterFence Report[/bold]", style="blue"))

    config = load_config(project_dir)

    with console.status("[bold blue]Running full audit...[/bold blue]"):
        results = run_audit(config=config)

    audit_dicts = [
        {
            "id": r.id,
            "name": r.name,
            "category": r.category,
            "severity": r.severity,
            "passed": r.passed,
            "expected_decision": r.expected_decision,
            "actual_decision": r.actual_decision,
            "reason": r.reason,
        }
        for r in results
    ]

    score = calculate_score(audit_dicts, config)

    report_path = project_dir / ".butterfence" / "reports" / "latest_report.md"
    report_text = generate_report(score, audit_dicts, report_path)

    console.print(report_text)
    console.print(f"\n[green]Report saved to:[/green] {report_path}")


@app.command()
def status(
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Show current ButterFence status."""
    from butterfence.config import load_config, validate_config
    from butterfence.installer import BUTTERFENCE_MARKER
    from butterfence.utils import load_json

    console.print(Panel("[bold]ButterFence Status[/bold]", style="blue"))

    bf_dir = project_dir / ".butterfence"
    config_path = bf_dir / "config.json"
    settings_path = project_dir / ".claude" / "settings.local.json"
    log_path = bf_dir / "logs" / "events.jsonl"

    # Config status
    if config_path.exists():
        config = load_config(project_dir)
        errors = validate_config(config)
        cat_count = len(config.get("categories", {}))
        pattern_count = sum(
            len(c.get("patterns", [])) for c in config.get("categories", {}).values()
        )
        if errors:
            console.print(f"  Config: [red]invalid ({len(errors)} errors)[/red]")
        else:
            console.print(f"  Config: [green]valid[/green] ({cat_count} categories, {pattern_count} patterns)")
    else:
        console.print("  Config: [red]not found[/red] (run `butterfence init`)")

    # Hook status
    if settings_path.exists():
        settings = load_json(settings_path)
        hook_count = 0
        for event in ("PreToolUse", "PostToolUse"):
            for hook_group in settings.get("hooks", {}).get(event, []):
                for hook in hook_group.get("hooks", []):
                    if BUTTERFENCE_MARKER in hook.get("command", ""):
                        hook_count += 1
        if hook_count > 0:
            console.print(f"  Hooks: [green]installed[/green] ({hook_count} hook entries)")
        else:
            console.print("  Hooks: [yellow]not installed[/yellow]")
    else:
        console.print("  Hooks: [red]no settings file[/red]")

    # Log status
    if log_path.exists():
        line_count = sum(1 for _ in open(log_path, encoding="utf-8"))
        console.print(f"  Events: [cyan]{line_count} logged[/cyan]")
    else:
        console.print("  Events: [dim]none[/dim]")

    # Report status
    report_path = bf_dir / "reports" / "latest_report.md"
    if report_path.exists():
        console.print(f"  Report: [cyan]{report_path}[/cyan]")
    else:
        console.print("  Report: [dim]none generated yet[/dim]")
