"""Typer CLI: init, audit, report, status + new commands."""

from __future__ import annotations

import os
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from butterfence import __version__

BANNER = r"""
[bold yellow]
 ____        _   _            _____
| __ ) _   _| |_| |_ ___ _ _|  ___|__ _ __   ___ ___
|  _ \| | | | __| __/ _ \ '__| |_ / _ \ '_ \ / __/ _ \
| |_) | |_| | |_| ||  __/ |  |  _|  __/ | | | (_|  __/
|____/ \__,_|\__|\__\___|_|  |_|  \___|_| |_|\___\___|
[/bold yellow]
[dim]Claude Code Safety Harness v{version}[/dim]
"""

app = typer.Typer(
    name="butterfence",
    help="Claude Code safety harness - red-team and protect your repos.",
)
pack_app = typer.Typer(help="Manage community rule packs.")
app.add_typer(pack_app, name="pack")
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(BANNER.format(version=__version__))
        raise typer.Exit()


def _validate_project_dir(project_dir: Path) -> None:
    """Validate that the project directory exists and is accessible."""
    if not project_dir.exists():
        console.print(f"[red]Error:[/red] Directory not found: {project_dir}")
        raise typer.Exit(1)
    if not project_dir.is_dir():
        console.print(f"[red]Error:[/red] Not a directory: {project_dir}")
        raise typer.Exit(1)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-v", help="Show version.", callback=_version_callback, is_eager=True
    ),
) -> None:
    """ButterFence - Claude Code safety harness."""
    if ctx.invoked_subcommand is None and not version:
        console.print(BANNER.format(version=__version__))
        console.print("Run [bold]butterfence --help[/bold] for available commands.\n")


@app.command()
def init(
    force: bool = typer.Option(False, "--force", help="Overwrite existing config"),
    no_hooks: bool = typer.Option(False, "--no-hooks", help="Skip hook installation"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Initialize ButterFence in the current project."""
    _validate_project_dir(project_dir)
    from butterfence.config import DEFAULT_CONFIG, load_config, save_config, validate_config
    from butterfence.installer import install_hooks
    from butterfence.utils import deep_merge, load_json

    console.print(BANNER.format(version=__version__))

    bf_dir = project_dir / ".butterfence"
    (bf_dir / "logs").mkdir(parents=True, exist_ok=True)
    (bf_dir / "reports").mkdir(parents=True, exist_ok=True)

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

    if not no_hooks:
        settings_path = install_hooks(project_dir)
        console.print(f"  Hooks: [cyan]{settings_path}[/cyan]")
    else:
        console.print("  Hooks: [yellow]skipped[/yellow]")

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
    _validate_project_dir(project_dir)
    from butterfence.audit import run_audit
    from butterfence.config import load_config
    from butterfence.report import generate_report
    from butterfence.scoring import calculate_score

    console.print(BANNER.format(version=__version__))

    config = load_config(project_dir)

    with console.status("[bold blue]Running scenarios...[/bold blue]"):
        results = run_audit(
            config=config,
            category_filter=category,
            scenario_filter=scenario,
            quick=quick,
        )

    table = Table(title="Audit Results", expand=True)
    table.add_column("", style="bold", width=4, no_wrap=True)
    table.add_column("ID", no_wrap=True, ratio=2)
    table.add_column("Name", ratio=4)
    table.add_column("Category", no_wrap=True, ratio=3)
    table.add_column("Sev", no_wrap=True, width=8)
    table.add_column("Result", no_wrap=True, width=7)

    passed = 0
    failed = 0
    for r in results:
        if r.passed:
            passed += 1
            status = "[green]OK[/green]"
        else:
            failed += 1
            status = "[red]FAIL[/red]"

        sev_colors = {"critical": "red bold", "high": "yellow", "medium": "blue", "low": "dim"}
        sev_short = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW"}
        sev_s = sev_short.get(r.severity, r.severity)
        sev_c = sev_colors.get(r.severity, "")

        table.add_row(
            status,
            r.id,
            r.name,
            r.category,
            f"[{sev_c}]{sev_s}[/{sev_c}]" if sev_c else sev_s,
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

    if report_flag:
        report_path = project_dir / ".butterfence" / "reports" / "latest_report.md"
        generate_report(score, audit_dicts, report_path)
        console.print(f"\n[green]Report saved to:[/green] {report_path}")


@app.command()
def report(
    fmt: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown|html|json|sarif|junit"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Generate a safety report from the latest audit."""
    _validate_project_dir(project_dir)
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

    if fmt == "html":
        from butterfence.exporters.html_report import generate_html_report
        report_text = generate_html_report(score, audit_dicts)
        default_ext = "html"
    elif fmt == "json":
        import json
        from butterfence.exporters.json_export import audit_to_json
        report_text = json.dumps(audit_to_json(score, audit_dicts), indent=2)
        default_ext = "json"
    elif fmt == "sarif":
        import json
        from butterfence.exporters.sarif import audit_to_sarif
        report_text = json.dumps(audit_to_sarif(audit_dicts, config), indent=2)
        default_ext = "sarif"
    elif fmt == "junit":
        from butterfence.exporters.junit import audit_to_junit
        report_text = audit_to_junit(audit_dicts)
        default_ext = "xml"
    else:
        report_path = output or (project_dir / ".butterfence" / "reports" / "latest_report.md")
        generate_report(score, audit_dicts, report_path)
        score_color = "green" if score.total_score >= 90 else "yellow" if score.total_score >= 70 else "red"
        console.print(
            f"\n[bold]Score:[/bold] [{score_color}]{score.total_score}/{score.max_score}[/{score_color}] "
            f"| Grade: [bold]{score.grade}[/bold] ({score.grade_label})"
        )
        console.print(f"[green]Report saved to:[/green] {report_path}")
        return

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report_text, encoding="utf-8")
        console.print(f"[green]Report saved to:[/green] {output}")
    else:
        default_path = project_dir / ".butterfence" / "reports" / f"latest_report.{default_ext}"
        default_path.parent.mkdir(parents=True, exist_ok=True)
        default_path.write_text(report_text, encoding="utf-8")
        console.print(f"[green]Report saved to:[/green] {default_path}")


@app.command()
def status(
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Show current ButterFence status."""
    _validate_project_dir(project_dir)
    from butterfence.config import load_config, validate_config
    from butterfence.installer import BUTTERFENCE_MARKER
    from butterfence.utils import load_json

    console.print(Panel("[bold]ButterFence Status[/bold]", style="blue"))

    bf_dir = project_dir / ".butterfence"
    config_path = bf_dir / "config.json"
    settings_path = project_dir / ".claude" / "settings.local.json"
    log_path = bf_dir / "logs" / "events.jsonl"

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

    if log_path.exists():
        line_count = sum(1 for _ in open(log_path, encoding="utf-8"))
        console.print(f"  Events: [cyan]{line_count} logged[/cyan]")
    else:
        console.print("  Events: [dim]none[/dim]")

    report_path = bf_dir / "reports" / "latest_report.md"
    if report_path.exists():
        console.print(f"  Report: [cyan]{report_path}[/cyan]")
    else:
        console.print("  Report: [dim]none generated yet[/dim]")


@app.command()
def watch(
    refresh: float = typer.Option(0.5, "--refresh", help="Refresh interval in seconds"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Live monitoring dashboard for ButterFence events."""
    _validate_project_dir(project_dir)
    from butterfence.watcher import run_watcher

    run_watcher(project_dir, refresh=refresh)


@app.command()
def scan(
    fix: bool = typer.Option(False, "--fix", help="Show remediation suggestions"),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table|json|sarif"),
    entropy_threshold: float = typer.Option(4.5, "--entropy-threshold", help="Entropy detection threshold"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Scan repository for secrets and security issues."""
    _validate_project_dir(project_dir)
    import json

    from butterfence.scanner import scan_repo

    console.print(Panel("[bold]ButterFence Repo Scanner[/bold]", style="blue"))

    with console.status("[bold blue]Scanning repository...[/bold blue]"):
        result = scan_repo(project_dir, entropy_threshold=entropy_threshold, fix=fix)

    console.print(
        f"\n  Files scanned: [cyan]{result.files_scanned}[/cyan], "
        f"skipped: [dim]{result.files_skipped}[/dim], "
        f"findings: [{'red' if result.findings else 'green'}]{len(result.findings)}[/{'red' if result.findings else 'green'}]"
    )

    if fmt == "json":
        data = {
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "findings": [
                {
                    "file": f.file,
                    "line": f.line,
                    "rule": f.rule,
                    "severity": f.severity,
                    "matched_text": f.matched_text,
                    "suggestion": f.suggestion,
                }
                for f in result.findings
            ],
        }
        out = json.dumps(data, indent=2)
        if output:
            output.write_text(out, encoding="utf-8")
            console.print(f"[green]Output saved to:[/green] {output}")
        else:
            console.print(out)
        return

    if fmt == "sarif":
        from butterfence.exporters.sarif import audit_to_sarif

        audit_dicts = [
            {
                "id": f"scan-{i}",
                "name": f.rule,
                "category": "scanner",
                "severity": f.severity,
                "passed": False,
                "expected_decision": "block",
                "actual_decision": "allow",
                "reason": f"{f.file}:{f.line} - {f.matched_text}",
            }
            for i, f in enumerate(result.findings, 1)
        ]
        out = json.dumps(audit_to_sarif(audit_dicts), indent=2)
        if output:
            output.write_text(out, encoding="utf-8")
            console.print(f"[green]Output saved to:[/green] {output}")
        else:
            console.print(out)
        return

    # Default: table
    if not result.findings:
        console.print("\n[green]No security issues found![/green]")
        return

    table = Table(title="Scan Findings", show_lines=True)
    table.add_column("Severity", width=10)
    table.add_column("File", width=30)
    table.add_column("Line", width=6)
    table.add_column("Rule", width=25)
    table.add_column("Match", width=40)

    for f in result.findings:
        sev_style = {
            "critical": "red bold",
            "high": "yellow",
            "medium": "blue",
            "low": "dim",
        }.get(f.severity, "")
        table.add_row(
            f"[{sev_style}]{f.severity}[/{sev_style}]",
            f.file,
            str(f.line),
            f.rule,
            f.matched_text[:40],
        )

    console.print(table)

    if fix:
        console.print("\n[bold]Remediation Suggestions:[/bold]")
        seen: set[str] = set()
        for f in result.findings:
            if f.suggestion and f.suggestion not in seen:
                seen.add(f.suggestion)
                console.print(f"  - {f.suggestion}")


@app.command()
def ci(
    min_score: int = typer.Option(80, "--min-score", help="Minimum passing score"),
    fmt: str = typer.Option("json", "--format", "-f", help="Output format: json|sarif|junit"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
    badge: Path = typer.Option(None, "--badge", help="Generate SVG badge file"),
    generate_workflow: bool = typer.Option(False, "--generate-workflow", help="Generate GitHub Actions workflow"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Run audit in CI mode with pass/fail exit codes."""
    _validate_project_dir(project_dir)
    from butterfence.ci import generate_github_workflow, run_ci

    if generate_workflow:
        workflow_path = project_dir / ".github" / "workflows" / "butterfence.yml"
        workflow_path.parent.mkdir(parents=True, exist_ok=True)
        workflow_path.write_text(generate_github_workflow(), encoding="utf-8")
        console.print(f"[green]Workflow written to:[/green] {workflow_path}")
        return

    passed, info = run_ci(
        project_dir=project_dir,
        min_score=min_score,
        output_format=fmt,
        output_file=output,
        badge_file=badge,
    )

    score_color = "green" if passed else "red"
    console.print(
        f"Score: [{score_color}]{info['score']}/{info['max_score']}[/{score_color}] "
        f"({info['grade']}) | Min: {min_score}"
    )
    console.print(
        f"Scenarios: {info['scenarios_passed']} passed, "
        f"{info['scenarios_failed']} failed / {info['scenarios_total']} total"
    )

    if output:
        console.print(f"Output: {output}")
    if badge:
        console.print(f"Badge: {badge}")

    if passed:
        console.print("[green]CI PASSED[/green]")
    else:
        console.print("[red]CI FAILED[/red]")
        raise typer.Exit(1)


@app.command()
def redteam(
    count: int = typer.Option(10, "--count", "-n", help="Number of scenarios to generate"),
    model: str = typer.Option("claude-opus-4-6-20250219", "--model", "-m", help="Anthropic model"),
    categories: str = typer.Option(None, "--categories", "-c", help="Comma-separated categories"),
    save: bool = typer.Option(False, "--save", "-s", help="Save results to JSON"),
    report_flag: bool = typer.Option(False, "--report", "-r", help="Generate report after"),
    fix: bool = typer.Option(False, "--fix", "-f", help="Auto-fix gaps with AI-suggested patterns"),
    verbose: bool = typer.Option(False, "--verbose", help="Show detailed match info"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", "-d", help="Project directory"),
) -> None:
    """AI red-team: use Claude Opus 4.6 to generate novel attack scenarios."""
    _validate_project_dir(project_dir)
    import json as json_mod

    from butterfence.config import get_config_path, load_config
    from butterfence.redteam import (
        APICallError,
        APIKeyMissingError,
        FixSuggestion,
        RedTeamError,
        ScenarioParseError,
        apply_fixes,
        generate_fix_suggestions,
        run_redteam,
    )
    from butterfence.scoring import calculate_score

    console.print(BANNER.format(version=__version__))
    console.print(
        Panel(
            "[bold red]AI Red Team Mode[/bold red]\n"
            "Using Claude Opus 4.6 as adversary to generate novel attacks",
            style="red",
        )
    )

    config = load_config(project_dir)

    cat_list = None
    if categories:
        cat_list = [c.strip() for c in categories.split(",")]

    try:
        with console.status(
            "[bold red]Opus 4.6 is thinking like an attacker...[/bold red]",
            spinner="dots",
        ):
            result = run_redteam(
                config=config,
                target_dir=project_dir,
                count=count,
                model=model,
                categories=cat_list,
            )
    except APIKeyMissingError as exc:
        console.print(f"\n[red]API Key Error:[/red] {exc}")
        console.print("\n[dim]Setup: butterfence auth  |  Or: export ANTHROPIC_API_KEY=...[/dim]")
        raise typer.Exit(1)
    except APICallError as exc:
        console.print(f"\n[red]API Error:[/red] {exc}")
        raise typer.Exit(1)
    except ScenarioParseError as exc:
        console.print(f"\n[red]Parse Error:[/red] {exc}")
        raise typer.Exit(1)
    except RedTeamError as exc:
        console.print(f"\n[red]Red Team Error:[/red] {exc}")
        console.print("\n[dim]Install: pip install anthropic  |  Or: pip install butterfence[redteam][/dim]")
        raise typer.Exit(1)

    # Display repo context
    ctx = result.repo_context
    console.print(f"\n[bold]Repo Context:[/bold]")
    console.print(f"  Tech stack: {', '.join(ctx.tech_stack) or 'Unknown'}")
    console.print(f"  Languages: {', '.join(ctx.languages) or 'Unknown'}")
    console.print(f"  Files scanned: {ctx.total_files}")
    console.print(f"  Sensitive files: {len(ctx.sensitive_files)}")
    console.print(f"  Model: {result.model_used}")
    console.print(f"  Scenarios generated: {result.scenarios_generated}")

    # Results table
    table = Table(title="Red Team Results", expand=True)
    table.add_column("", style="bold", width=6, no_wrap=True)
    table.add_column("ID", no_wrap=True, ratio=2)
    table.add_column("Name", ratio=4)
    table.add_column("Category", no_wrap=True, ratio=3)
    table.add_column("Sev", no_wrap=True, width=8)
    table.add_column("Result", no_wrap=True, width=7)

    for r in result.results:
        status = "[green]CAUGHT[/green]" if r.passed else "[red]MISSED[/red]"
        sev_colors = {"critical": "red bold", "high": "yellow", "medium": "blue", "low": "dim"}
        sev_short = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW"}
        sev_s = sev_short.get(r.severity, r.severity)
        sev_c = sev_colors.get(r.severity, "")

        table.add_row(
            status,
            r.id,
            r.name,
            r.category,
            f"[{sev_c}]{sev_s}[/{sev_c}]" if sev_c else sev_s,
            r.actual_decision,
        )

        if verbose and r.match_result.matches:
            for m in r.match_result.matches:
                console.print(f"    [dim]  matched: {m.pattern}[/dim]")

    console.print(table)

    console.print(
        f"\n[bold]Red Team Summary:[/bold] "
        f"[green]{result.caught} caught[/green], "
        f"[red]{result.missed} missed[/red] / {result.scenarios_run} total "
        f"({result.catch_rate:.0f}% catch rate)"
    )

    # Score
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
        for r in result.results
    ]

    score = calculate_score(audit_dicts, config)
    score_color = "green" if score.total_score >= 90 else "yellow" if score.total_score >= 70 else "red"
    console.print(
        f"\n[bold]Score:[/bold] [{score_color}]{score.total_score}/{score.max_score}[/{score_color}] "
        f"| Grade: [bold]{score.grade}[/bold] ({score.grade_label})"
    )

    # Fix suggestions
    missed = [r for r in result.results if not r.passed]
    if missed and fix:
        try:
            with console.status(
                "[bold yellow]Opus 4.6 is analyzing gaps and generating fixes...[/bold yellow]",
                spinner="dots",
            ):
                suggestions = generate_fix_suggestions(missed, config, model=model, raw_scenarios=result.raw_scenarios)

            if suggestions:
                fix_table = Table(title="Suggested Fixes", show_lines=True)
                fix_table.add_column("Category", width=20)
                fix_table.add_column("New Patterns", ratio=1)
                fix_table.add_column("Explanation", ratio=1)

                for s in suggestions:
                    patterns_str = chr(10).join(s.new_patterns)
                    fix_table.add_row(s.category, patterns_str, s.explanation)

                console.print(fix_table)

                config_path = get_config_path(project_dir)
                added = apply_fixes(suggestions, config, config_path)
                console.print(
                    f"[green]Applied {added} new pattern(s).[/green] "
                    "Re-run [bold]butterfence redteam[/bold] to verify."
                )
            else:
                console.print("[yellow]No fix suggestions could be generated.[/yellow]")
        except (APICallError, RedTeamError) as exc:
            console.print(f"[yellow]Fix generation failed:[/yellow] {exc}")
    elif missed and not fix:
        console.print(
            "[dim]Tip: run with --fix to auto-generate patterns for missed attacks[/dim]"
        )

    # Save results
    if save:
        save_path = project_dir / ".butterfence" / "redteam_results.json"
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_data = {
            "model": result.model_used,
            "scenarios_generated": result.scenarios_generated,
            "caught": result.caught,
            "missed": result.missed,
            "catch_rate": result.catch_rate,
            "score": {
                "total": score.total_score,
                "max": score.max_score,
                "grade": score.grade,
                "label": score.grade_label,
            },
            "repo_context": {
                "root": ctx.root,
                "tech_stack": ctx.tech_stack,
                "languages": ctx.languages,
                "total_files": ctx.total_files,
                "sensitive_files_count": len(ctx.sensitive_files),
            },
            "scenarios": result.raw_scenarios,
            "results": audit_dicts,
        }
        save_path.write_text(json_mod.dumps(save_data, indent=2), encoding="utf-8")
        console.print(f"\n[green]Results saved to:[/green] {save_path}")

    # Generate report
    if report_flag:
        from butterfence.report import generate_report

        report_path = project_dir / ".butterfence" / "reports" / "redteam_report.md"
        generate_report(score, audit_dicts, report_path)
        console.print(f"[green]Report saved to:[/green] {report_path}")


@app.command()
def analytics(
    period: str = typer.Option("all", "--period", "-p", help="Time period: 1h|24h|7d|30d|all"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Show analytics from event log."""
    _validate_project_dir(project_dir)
    from butterfence.analytics import analyze_events

    console.print(Panel("[bold]ButterFence Analytics[/bold]", style="blue"))

    result = analyze_events(project_dir, period=period)

    if result.total_events == 0:
        console.print("\n[dim]No events found. Run some hook events first.[/dim]")
        return

    console.print(f"\n  Total events: [cyan]{result.total_events}[/cyan]")
    console.print(f"  [red]Blocks:[/red] {result.blocks}  [yellow]Warns:[/yellow] {result.warns}  [green]Allows:[/green] {result.allows}")
    console.print(f"  Block rate: {result.block_rate:.1f}%")
    console.print(f"  Threat trend: {result.threat_trend}")

    if result.by_tool:
        console.print("\n[bold]By Tool:[/bold]")
        for tool, count in result.by_tool.most_common():
            console.print(f"  {tool}: {count}")

    if result.by_category:
        console.print("\n[bold]By Category:[/bold]")
        for cat, count in result.by_category.most_common():
            bar = "\u2588" * min(count, 30)
            console.print(f"  {cat:<20} {bar} {count}")

    if result.blocked_patterns:
        console.print("\n[bold]Most Blocked:[/bold]")
        for pat, count in result.blocked_patterns.most_common(10):
            console.print(f"  {pat}: {count}")


@app.command()
def explain(
    scenario_id: str = typer.Argument(..., help="Scenario ID to explain (e.g. shell-001)"),
) -> None:
    """Show educational explanation for a threat scenario."""
    from butterfence.explainer import get_all_scenario_ids, load_explanation

    info = load_explanation(scenario_id)

    if not info:
        all_ids = get_all_scenario_ids()
        console.print(f"[red]Scenario '{scenario_id}' not found.[/red]")
        if all_ids:
            console.print(f"Available: {', '.join(all_ids[:20])}")
        raise typer.Exit(1)

    expl = info.get("explanation", {})
    sev_style = {
        "critical": "red bold",
        "high": "yellow",
        "medium": "blue",
        "low": "dim",
    }.get(info.get("severity", ""), "")

    lines = [
        f"[bold]{info['name']}[/bold] ({info['id']})",
        f"Category: {info['category']}",
        f"Severity: [{sev_style}]{info['severity']}[/{sev_style}]" if sev_style else f"Severity: {info['severity']}",
        "",
    ]

    if expl.get("what"):
        lines.append(f"[bold]What it does:[/bold] {expl['what']}")
    if expl.get("why_dangerous"):
        lines.append(f"[bold]Why dangerous:[/bold] {expl['why_dangerous']}")
    if expl.get("real_world"):
        lines.append(f"[bold]Real-world example:[/bold] {expl['real_world']}")
    if expl.get("safe_alternative"):
        lines.append(f"[bold]Safe alternative:[/bold] {expl['safe_alternative']}")

    if not expl:
        lines.append("[dim]No detailed explanation available for this scenario.[/dim]")

    console.print(Panel("\n".join(lines), title="Threat Explanation", border_style="yellow"))


@app.command()
def auth(
    key: str = typer.Option(None, "--key", "-k", help="API key to save"),
    status_flag: bool = typer.Option(False, "--status", "-s", help="Show current key status"),
    remove: bool = typer.Option(False, "--remove", help="Remove stored key"),
) -> None:
    """Manage Anthropic API key for AI red-team features."""
    from butterfence.auth import (
        check_key_permissions,
        get_key_path,
        load_key,
        mask_key,
        remove_key,
        save_key,
        validate_key_format,
    )

    key_path = get_key_path()

    # --- Remove ---
    if remove:
        removed = remove_key()
        if removed:
            console.print("[green]API key securely removed.[/green]")
        else:
            console.print("[dim]No stored key found.[/dim]")
        return

    # --- Status ---
    if status_flag:
        console.print(Panel("[bold]API Key Status[/bold]", style="blue"))

        # Check env var
        env_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if env_key:
            console.print(f"  Env var: [green]set[/green] [green]OK[/green] ({mask_key(env_key)})")
        else:
            console.print("  Env var: [dim]not set[/dim] [dim]--[/dim]")

        # Check stored key
        stored = load_key()
        if stored:
            console.print(f"  Stored:  [green]saved[/green] [green]OK[/green] ({mask_key(stored)})")
            console.print(f"  Path:    [cyan]{key_path}[/cyan]")
            warnings = check_key_permissions(key_path)
            if warnings:
                for w in warnings:
                    console.print(f"  [yellow]Warning: {w}[/yellow]")
            else:
                console.print("  Perms:   [green]secure[/green]")
        else:
            console.print("  Stored:  [dim]none[/dim] [dim]--[/dim]")

        # Overall
        if env_key or stored:
            console.print("\n  [green]Ready for butterfence redteam[/green]")
        else:
            console.print("\n  [yellow]No key configured. Run: butterfence auth[/yellow]")
        return

    # --- Save (interactive or via --key) ---
    if key:
        api_key = key
    else:
        # Interactive prompt with hidden input
        import getpass

        console.print(
            Panel(
                "[bold]API Key Setup[/bold]\n\n"
                "Get your key at: [cyan]https://console.anthropic.com/settings/keys[/cyan]\n"
                "The key will be stored securely at:\n"
                f"  [cyan]{key_path}[/cyan]\n"
                "with owner-only permissions.",
                style="blue",
            )
        )
        api_key = getpass.getpass("Enter your Anthropic API key: ")

    if not api_key or not api_key.strip():
        console.print("[red]No key provided.[/red]")
        raise typer.Exit(1)

    if not validate_key_format(api_key.strip()):
        console.print("[red]Invalid key format.[/red] Keys must start with 'sk-' and be 20+ characters.")
        raise typer.Exit(1)

    try:
        saved_path = save_key(api_key)
        console.print(f"\n[green]API key saved securely![/green]")
        console.print(f"  Key:  {mask_key(api_key.strip())}")
        console.print(f"  Path: [cyan]{saved_path}[/cyan]")
        console.print(f"  Perms: owner-only read/write")
        console.print(f"\n  Run [bold]butterfence redteam[/bold] to start AI red-teaming.")
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)


@app.command()
def configure(
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Interactive configuration wizard."""
    _validate_project_dir(project_dir)
    from butterfence.configure import run_configure

    run_configure(project_dir)


@app.command()
def uninstall(
    remove_data: bool = typer.Option(False, "--remove-data", help="Also remove .butterfence/ directory"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
) -> None:
    """Remove ButterFence hooks and optionally all data."""
    _validate_project_dir(project_dir)
    import shutil

    from butterfence.installer import uninstall_hooks

    console.print(Panel("[bold]ButterFence Uninstall[/bold]", style="red"))

    result = uninstall_hooks(project_dir)
    if result:
        console.print(f"  Hooks removed from: [cyan]{result}[/cyan]")
    else:
        console.print("  [dim]No hooks found to remove[/dim]")

    if remove_data:
        bf_dir = project_dir / ".butterfence"
        if bf_dir.exists():
            shutil.rmtree(bf_dir)
            console.print(f"  [red]Removed:[/red] {bf_dir}")
        else:
            console.print("  [dim]No .butterfence/ directory found[/dim]")

    console.print("[green]ButterFence uninstalled.[/green]")


# --- Pack sub-commands ---

@pack_app.command("list")
def pack_list(
    packs_dir: Path = typer.Option(None, "--packs-dir", help="Custom packs directory"),
) -> None:
    """List available rule packs."""
    from butterfence.packs import list_packs

    packs = list_packs(packs_dir)
    if not packs:
        console.print("[dim]No packs found.[/dim]")
        return

    table = Table(title="Available Rule Packs", expand=True)
    table.add_column("Pack", no_wrap=True, style="bold cyan", ratio=1)
    table.add_column("Description", ratio=4)
    table.add_column("Rules", no_wrap=True, width=5, justify="right")

    for p in packs:
        desc = p.description[:70] + "..." if len(p.description) > 70 else p.description
        cat_count = sum(len(c.get("patterns", [])) for c in p.categories.values())
        table.add_row(
            p.name,
            desc,
            str(cat_count),
        )

    console.print(table)


@pack_app.command("install")
def pack_install(
    name: str = typer.Argument(..., help="Pack name to install"),
    project_dir: Path = typer.Option(Path.cwd(), "--dir", help="Project directory"),
    packs_dir: Path = typer.Option(None, "--packs-dir", help="Custom packs directory"),
) -> None:
    """Install a rule pack into the current config."""
    from butterfence.packs import install_pack

    success = install_pack(name, project_dir, packs_dir)
    if success:
        console.print(f"[green]Pack '{name}' installed successfully![/green]")
    else:
        console.print(f"[red]Pack '{name}' not found.[/red]")
        raise typer.Exit(1)


@pack_app.command("info")
def pack_info(
    name: str = typer.Argument(..., help="Pack name to inspect"),
    packs_dir: Path = typer.Option(None, "--packs-dir", help="Custom packs directory"),
) -> None:
    """Show details for a rule pack."""
    from butterfence.packs import get_pack_info

    pack = get_pack_info(name, packs_dir)
    if not pack:
        console.print(f"[red]Pack '{name}' not found.[/red]")
        raise typer.Exit(1)

    lines = [
        f"[bold]{pack.name}[/bold] v{pack.version}",
        f"Author: {pack.author}",
        f"Description: {pack.description}",
        "",
        f"[bold]Categories ({len(pack.categories)}):[/bold]",
    ]
    for cat_name, cat_config in pack.categories.items():
        patterns = cat_config.get("patterns", [])
        lines.append(
            f"  {cat_name}: {len(patterns)} patterns | "
            f"{cat_config.get('severity', 'high')} | {cat_config.get('action', 'block')}"
        )

    console.print(Panel("\n".join(lines), title="Pack Info", border_style="cyan"))
