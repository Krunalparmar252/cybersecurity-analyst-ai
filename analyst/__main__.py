import sys
import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from analyst.orchestrator.pipeline import run_pipeline
from analyst.orchestrator.graph import run_pipeline_graph
from analyst.reporting.export import plan_outputs, write_export

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

console = Console(legacy_windows=False)

ENGINES = {
    "linear": run_pipeline,        # original orchestrator (pipeline.py)
    "graph": run_pipeline_graph,   # LangGraph-based orchestrator (graph.py)
}

STAGE_DESCRIPTIONS = {
    "INGEST": "Parsing AST, mapping routes and DB surfaces...",
    "DETECT": "Running static rules & entropy secrets scanner...",
    "REASON": "Querying LLM engine for verification & patch generation...",
    "REPORT": "Generating structured report...",
}
STAGE_ORDER = ["INGEST", "DETECT", "REASON", "REPORT"]


@click.group()
def cli():
    """Autonomous Cybersecurity Analyst AI - CLI Entrypoint"""
    pass


@cli.command()
@click.argument("repo_path")
@click.option("--output", "-o", default="report.md", help="Output report file path")
@click.option("--artifacts", default=None, help="Directory to write intermediate stage artifacts (manifest, findings)")
@click.option("--verbose", "-v", is_flag=True, help="Enable live pipeline stage output")
@click.option(
    "--offline",
    is_flag=True,
    help=(
        "Skip the LLM tier entirely and scan with the deterministic local "
        "engine (regex confirmation + template patches). Useful with no API "
        "key, on an air-gapped host, or to demo the fallback path on demand."
    ),
)
@click.option(
    "--format", "fmt",
    type=click.Choice(["md", "html", "pdf"]),
    default="md",
    help=(
        "Report format. Markdown is always written (the integrity checksum "
        "covers it); html/pdf are rendered from it next to it, e.g. "
        "'-o report.md --format pdf' writes report.md and report.pdf."
    ),
)
@click.option(
    "--engine",
    type=click.Choice(["linear", "graph"]),
    default="linear",
    help=(
        "Orchestrator implementation: 'linear' is the original if/return "
        "routing (pipeline.py, default -- unchanged behavior); 'graph' "
        "routes the same agents through an explicit LangGraph StateGraph "
        "(orchestrator/graph.py). Same agents, same decisions, same "
        "output either way -- this only changes how routing is expressed."
    ),
)
@click.option(
    "--dynamic",
    is_flag=True,
    help=(
        "Enable the exploit verification agent (B-5). When set, the system "
        "will actually attempt to exploit the vulnerable code before and "
        "after patching to prove the fix."
    ),
)
@click.option(
    "--apply",
    "auto_apply",
    is_flag=True,
    help=(
        "Automatically apply all verified patches directly in-place to the "
        "target repository files upon successful scan verification."
    ),
)
@click.option(
    "--incremental",
    is_flag=True,
    help=(
        "Enable incremental scanning (Track C). Compares git history against "
        "the previous scan baseline to only re-scan files that changed and skip "
        "re-reasoning on previously resolved findings."
    ),
)
def scan(repo_path, output, artifacts, verbose, fmt, engine, offline, dynamic, incremental, auto_apply=False):
    """Scan a local repository or git URL for security vulnerabilities.

    REPO_PATH accepts either a local directory path or a git URL
    (https://, git://, or git@ scheme) -- git URLs are shallow-cloned to a
    temp directory that's cleaned up automatically once the scan finishes.
    """

    console.print(Panel.fit(
        "[bold cyan]Autonomous Cybersecurity Analyst AI[/bold cyan]\n"
        "[dim]Static Analysis + LLM Hybrid Pipeline[/dim]",
        border_style="cyan"
    ))

    md_path, target_path = plan_outputs(output, fmt)
    console.print(f"\n[bold blue][*] Target:[/bold blue] {repo_path}")
    console.print(f"[bold blue][*] Output Destination:[/bold blue] {target_path}\n")

    tasks = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=False,
    ) as progress:

        def on_stage_start(stage):
            idx = STAGE_ORDER.index(stage) + 1
            label = f"{idx}/4 {stage}"
            tasks[stage] = progress.add_task(
                description=f"[yellow][{label}][/yellow] {STAGE_DESCRIPTIONS[stage]}",
                total=None,
            )

        def on_stage_done(stage):
            idx = STAGE_ORDER.index(stage) + 1
            label = f"{idx}/4 {stage}"
            progress.update(
                tasks[stage],
                description=f"[green][{label} OK][/green] {STAGE_DESCRIPTIONS[stage]}",
            )

        def on_route(decision):
            # Surfaces orchestrator decisions live -- this is the visible
            # evidence during a demo that routing is data-dependent, not a
            # fixed sequence.
            progress.console.print(f"  [magenta][orchestrator decision][/magenta] {decision}")

        try:
            run_selected = ENGINES[engine]
            result = run_selected(
                repo_path=repo_path,
                output_path=str(md_path),
                artifact_dir=artifacts,
                on_stage_start=on_stage_start,
                on_stage_done=on_stage_done,
                on_route=on_route,
                offline=offline,
                dynamic=dynamic,
                incremental=incremental,
            )
        except Exception as exc:
            console.print(f"\n[bold red]Pipeline failed:[/bold red] {exc}")
            sys.exit(1)

    if result.status == "OK":
        console.print("\n[bold green]Scan completed successfully![/bold green]")
    else:
        console.print("\n[bold yellow]Scan completed with PARTIAL status.[/bold yellow]")
        for stage, err in result.stage_errors.items():
            console.print(f"  [yellow]{stage} error:[/yellow] {err}")

    console.print(
        f"[*] {result.confirmed_count} confirmed finding(s), "
        f"{result.rejected_count} rejected as false positive(s), "
        f"{result.escalated_count} escalated for human review, "
        f"in {result.duration_seconds:.1f}s"
    )
    if result.incremental_summary:
        console.print(f"[*] Incremental scan: {result.incremental_summary}")
    if result.fallbacks:
        console.print(
            f"[bold yellow][!] DEGRADED RUN:[/bold yellow] {len(result.fallbacks)} "
            f"fallback event(s) — findings below were not all produced by full LLM reasoning."
        )
        for event in result.fallbacks[:5]:
            console.print(f"    [yellow]{event['tier']}[/yellow] via {event['trigger']}")

    integrity = result.integrity or {}
    verified = integrity.get("verified")
    console.print(
        f"[*] Integrity: "
        f"{'[green]VERIFIED[/green]' if verified else '[red]FAILED[/red]'} — "
        f"{integrity.get('messages', 0)} signed message(s), "
        f"salt {integrity.get('salt', {}).get('salt_fingerprint', 'n/a')} "
        f"(epoch {integrity.get('salt', {}).get('epoch', 0)}), "
        f"audit head {str(integrity.get('audit_head', ''))[-12:]}"
    )
    if integrity.get("report_checksum_file"):
        console.print(f"[*] Report checksum: [bold]{integrity['report_checksum_file']}[/bold]")
    if fmt != "md":
        write_export(md_path, fmt, target_path)
        console.print(f"[*] Markdown report (checksummed): [bold]{md_path}[/bold]")
    console.print(f"[*] Report written to [bold]{target_path}[/bold]\n")



    if auto_apply:
        import json
        from pathlib import Path
        from analyst.reasoning.patch_loop import apply_patch_to_text
        target_dir = Path(repo_path)
        if not target_dir.exists() or not target_dir.is_dir():
            console.print(f"[bold yellow][!] --apply skipped:[/bold yellow] '{repo_path}' is a remote git URL. Clone locally first to apply.")
        else:
            art_dir = Path(artifacts) if artifacts else Path("artifacts")
            cf_path = art_dir / "confirmed_findings.json"
            if cf_path.exists():
                try:
                    findings_list = json.loads(cf_path.read_text(encoding="utf-8"))
                    applied_count = 0
                    for f in findings_list:
                        diff = f.get("patch_diff")
                        rel_file = f.get("file")
                        if diff and rel_file:
                            fpath = target_dir / rel_file
                            if fpath.exists():
                                orig = fpath.read_text(encoding="utf-8")
                                try:
                                    patched = apply_patch_to_text(orig, diff)
                                    bak = fpath.with_suffix(fpath.suffix + ".orig")
                                    if not bak.exists():
                                        bak.write_text(orig, encoding="utf-8")
                                    fpath.write_text(patched, encoding="utf-8")
                                    applied_count += 1
                                    console.print(f"  [bold green][APPLIED][/bold green] Patched {rel_file} ({f.get('rule_id')})")
                                except Exception as e:
                                    console.print(f"  [yellow][SKIP][/yellow] {rel_file}: {e}")
                    console.print(f"[bold green][*] Successfully auto-applied {applied_count} verified patch(es) to {repo_path}[/bold green]\n")
                except Exception as exc:
                    console.print(f"[bold red][!] Error during auto-apply:[/bold red] {exc}")


@cli.command()
@click.argument("repo_path")
@click.option("--artifacts", default="artifacts", help="Directory containing confirmed_findings.json")
def apply(repo_path, artifacts):
    """Apply verified patches from scan artifacts directly to target repo."""
    import json
    from pathlib import Path
    from analyst.reasoning.patch_loop import apply_patch_to_text
    target_dir = Path(repo_path)
    if not target_dir.exists() or not target_dir.is_dir():
        console.print(f"[bold red][!] Error:[/bold red] '{repo_path}' is not an accessible local directory.")
        sys.exit(1)
    
    art_path = Path(artifacts) / "confirmed_findings.json"
    if not art_path.exists():
        console.print(f"[bold red][!] Error:[/bold red] Artifact findings file not found at {art_path}")
        sys.exit(1)

    findings_list = json.loads(art_path.read_text(encoding="utf-8"))
    applied = 0
    for f in findings_list:
        diff = f.get("patch_diff")
        rel_file = f.get("file")
        if diff and rel_file:
            fpath = target_dir / rel_file
            if fpath.exists():
                orig = fpath.read_text(encoding="utf-8")
                try:
                    patched = apply_patch_to_text(orig, diff)
                    bak = fpath.with_suffix(fpath.suffix + ".orig")
                    if not bak.exists():
                        bak.write_text(orig, encoding="utf-8")
                    fpath.write_text(patched, encoding="utf-8")
                    applied += 1
                    console.print(f"  [bold green][APPLIED][/bold green] Patched {rel_file} ({f.get('rule_id')})")
                except Exception as e:
                    console.print(f"  [bold yellow][FAILED][/bold yellow] {rel_file}: {e}")
            else:
                console.print(f"  [bold yellow][MISSING][/bold yellow] {rel_file} does not exist.")

    console.print(f"\n[bold green][*] Finished. Applied {applied} patch(es) to {repo_path}.[/bold green]\n")


if __name__ == "__main__":
    cli()
