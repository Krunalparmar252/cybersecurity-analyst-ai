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
def scan(repo_path, output, artifacts, verbose, fmt, engine, offline, dynamic):
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


if __name__ == "__main__":
    cli()
