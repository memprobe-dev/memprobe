"""Click CLI entrypoint for memprobe."""

import sys
import tempfile
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich import box

from . import __version__
from .models import MemoryMap
from .parsers import map_gcc, map_iar, detect_iar
from .diff import diff as compute_diff
from . import history as hist
from .report import generate_report, generate_diff_report, _human_bytes
from .bloat import analyze as bloat_analyze
from .budget import load_budgets, check_budgets, BudgetViolation

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)


# -- Helpers -------------------------------------------------------------------

def _load_map(path: Path, debug: bool) -> MemoryMap:
    """Load a MemoryMap from an ELF or map file, with clean error messages."""
    if not path.exists():
        err_console.print(f"[bold red]Error:[/] File not found: {path}")
        sys.exit(1)

    suffix = path.suffix.lower()
    supported = (".map", ".elf", ".axf")

    if suffix == ".map":
        try:
            raw = path.read_bytes()
            mmap = map_iar.parse(path) if detect_iar(raw) else map_gcc.parse(path)
            mmap.timestamp = datetime.now(timezone.utc).isoformat()
            return mmap
        except Exception as e:
            if debug:
                raise
            err_console.print(f"[bold red]Error:[/] Failed to parse map file: {e}")
            sys.exit(1)

    if suffix in (".elf", ".axf"):
        try:
            from .parsers import elf as elf_parser
            mmap = elf_parser.parse(path)
            mmap.timestamp = datetime.now(timezone.utc).isoformat()
            return mmap
        except ImportError:
            err_console.print(
                "[bold red]Error:[/] pyelftools is required to parse ELF files.\n"
                "Install it with: [cyan]pip install pyelftools[/]"
            )
            sys.exit(1)
        except Exception as e:
            if debug:
                raise
            err_console.print(f"[bold red]Error:[/] Failed to parse ELF file: {e}")
            sys.exit(1)

    err_console.print(
        f"[bold red]Error:[/] Unsupported file format: [yellow]{suffix}[/]\n"
        f"Supported formats: {', '.join(supported)}"
    )
    sys.exit(1)


def _print_analyze_summary(mmap: MemoryMap) -> None:
    """Print a rich summary of a MemoryMap to the terminal."""
    src = mmap.source_file
    console.rule(f"[bold]memprobe - {Path(src).name}[/]")
    console.print()

    if mmap.regions:
        for region in mmap.regions:
            if region.length == 0:
                continue
            pct = region.used / region.length
            filled = int(pct * 24)
            bar = "█" * filled + "░" * (24 - filled)
            label = f"  {region.name:<8} [{bar}] {pct*100:5.1f}%   {_human_bytes(region.used)} / {_human_bytes(region.length)}"
            color = "red" if pct > 0.9 else "yellow" if pct > 0.75 else "green"
            console.print(f"[{color}]{label}[/]")
    else:
        console.print(f"  Flash   {_human_bytes(mmap.total_flash)}")
        console.print(f"  RAM     {_human_bytes(mmap.total_ram)}")

    console.print()
    console.print("  [bold]Sections:[/]")
    total_size = sum(s.size for s in mmap.sections) or 1
    for sec in sorted(mmap.sections, key=lambda s: s.size, reverse=True):
        if sec.size == 0:
            continue
        pct = sec.size / total_size
        bar_w = int(pct * 20)
        bar = "█" * bar_w + "░" * (20 - bar_w)
        console.print(f"  {sec.name:<12} {sec.size:>10,} bytes   [{bar}] {pct*100:5.1f}%")

    top_symbols = sorted(mmap.all_symbols, key=lambda s: s.size, reverse=True)[:8]
    if top_symbols:
        console.print()
        console.print("  [bold]Top symbols by size:[/]")
        for sym in top_symbols:
            console.print(f"  [cyan]{sym.name:<40}[/] {sym.size:>8,} bytes  [dim]{sym.section}[/]")

    console.print()


# -- CLI -----------------------------------------------------------------------

@click.group()
@click.version_option(__version__, prog_name="memprobe")
def cli() -> None:
    """Firmware memory map visualizer for embedded systems engineers."""


@cli.command()
@click.argument("file", type=click.Path(exists=False))
@click.option("--json", "output_json", is_flag=True, help="Output JSON instead of HTML.")
@click.option("--no-open", is_flag=True, help="Generate report but don't open browser.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Custom output path.")
@click.option("--budget-flash", type=str, default=None, help="Max flash (e.g. 512KB). Overrides memprobe.toml.")
@click.option("--budget-ram",   type=str, default=None, help="Max RAM   (e.g. 128KB). Overrides memprobe.toml.")
@click.option("--debug", is_flag=True, hidden=True)
def analyze(
    file: str,
    output_json: bool,
    no_open: bool,
    output: Optional[str],
    budget_flash: Optional[str],
    budget_ram: Optional[str],
    debug: bool,
) -> None:
    """Analyze a firmware ELF or map file and generate a visual report."""
    from .budget import parse_size
    path = Path(file)
    mmap = _load_map(path, debug)
    if not output_json:
        _print_analyze_summary(mmap)

    # Save to history
    try:
        hist.save(mmap)
    except Exception:
        pass

    if output_json:
        import json
        data = {
            "source_file": mmap.source_file,
            "toolchain": mmap.toolchain,
            "total_flash": mmap.total_flash,
            "total_ram": mmap.total_ram,
            "sections": [
                {"name": s.name, "size": s.size, "type": s.section_type.value}
                for s in mmap.sections
            ],
            "symbols": [
                {"name": sym.name, "size": sym.size, "section": sym.section, "object_file": sym.object_file}
                for sym in mmap.all_symbols
            ],
        }
        click.echo(json.dumps(data, indent=2))
        return

    if output:
        report_path = Path(output)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = Path(tempfile.gettempdir()) / f"memprobe_report_{ts}.html"

    warnings = bloat_analyze(mmap)
    generate_report(mmap, report_path, warnings)
    console.print(f"  Report: [cyan]{report_path}[/]")

    if not no_open:
        webbrowser.open(report_path.as_uri())
        console.print("  [green]✓ Opened in browser[/]")
    console.print()

    # Budget checks - merge memprobe.toml with CLI overrides
    budgets = load_budgets(path.parent)
    if budget_flash:
        budgets["flash"] = parse_size(budget_flash)
    if budget_ram:
        budgets["ram"] = parse_size(budget_ram)

    if budgets:
        violations = check_budgets(mmap, budgets)
        if violations:
            for v in violations:
                err_console.print(f"[bold red]Budget exceeded:[/] {v.message}")
            sys.exit(1)


@cli.command()
@click.argument("old_file", type=click.Path(exists=False))
@click.argument("new_file", type=click.Path(exists=False))
@click.option("--budget-flash", type=int, default=None, help="Max flash bytes (exit 1 if exceeded).")
@click.option("--budget-ram", type=int, default=None, help="Max RAM bytes (exit 1 if exceeded).")
@click.option("--no-open", is_flag=True, help="Generate report but don't open browser.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Custom output path.")
@click.option("--debug", is_flag=True, hidden=True)
def diff(
    old_file: str,
    new_file: str,
    budget_flash: Optional[int],
    budget_ram: Optional[int],
    no_open: bool,
    output: Optional[str],
    debug: bool,
) -> None:
    """Diff two firmware builds and report size changes."""
    old_path = Path(old_file)
    new_path = Path(new_file)
    old_mmap = _load_map(old_path, debug)
    new_mmap = _load_map(new_path, debug)

    build_diff = compute_diff(old_mmap, new_mmap)

    # Terminal output
    console.rule(f"[bold]memprobe diff - {old_path.name} → {new_path.name}[/]")
    console.print()

    flash_sign = "+" if build_diff.flash_delta >= 0 else ""
    ram_sign = "+" if build_diff.ram_delta >= 0 else ""
    flash_color = "red" if build_diff.flash_delta > 0 else "green" if build_diff.flash_delta < 0 else "white"
    ram_color = "red" if build_diff.ram_delta > 0 else "green" if build_diff.ram_delta < 0 else "white"

    console.print(f"  Flash  [{flash_color}]{flash_sign}{build_diff.flash_delta:,} bytes[/]")
    console.print(f"  RAM    [{ram_color}]{ram_sign}{build_diff.ram_delta:,} bytes[/]")
    console.print()

    if build_diff.symbol_diffs:
        t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold dim")
        t.add_column("Symbol", style="cyan")
        t.add_column("Old", justify="right")
        t.add_column("New", justify="right")
        t.add_column("Delta", justify="right")
        for sym in build_diff.symbol_diffs[:20]:
            sign = "+" if sym.delta >= 0 else ""
            color = "red" if sym.delta > 0 else "green"
            t.add_row(
                sym.name,
                str(sym.old_size) if sym.old_size else "-",
                str(sym.new_size) if sym.new_size else "-",
                f"[{color}]{sign}{sym.delta:,}[/]",
            )
        console.print(t)

    # HTML report
    if output:
        report_path = Path(output)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = Path(tempfile.gettempdir()) / f"memprobe_diff_{ts}.html"

    generate_diff_report(build_diff, old_mmap, new_mmap, report_path)
    console.print(f"  Report: [cyan]{report_path}[/]")

    if not no_open:
        webbrowser.open(report_path.as_uri())
        console.print("  [green]✓ Opened in browser[/]")
    console.print()

    # Budget checks - CLI flags override toml
    budgets = load_budgets(new_path.parent)
    if budget_flash is not None:
        budgets["flash"] = budget_flash
    if budget_ram is not None:
        budgets["ram"] = budget_ram

    if budgets:
        violations = check_budgets(new_mmap, budgets)
        if violations:
            for v in violations:
                err_console.print(f"[bold red]Budget exceeded:[/] {v.message}")
            sys.exit(1)


@cli.group()
def history() -> None:
    """Manage build history."""


@history.command("list")
def history_list() -> None:
    """List past analyzed builds."""
    builds = hist.list_builds()
    if not builds:
        console.print("[dim]No builds in history.[/]")
        return
    t = Table(box=box.SIMPLE_HEAD, show_header=True)
    t.add_column("ID", justify="right")
    t.add_column("File")
    t.add_column("Flash", justify="right")
    t.add_column("RAM", justify="right")
    t.add_column("Branch")
    t.add_column("Timestamp")
    for b in builds:
        t.add_row(
            str(b["id"]),
            Path(b["source_file"]).name,
            _human_bytes(b["total_flash"]),
            _human_bytes(b["total_ram"]),
            b.get("git_branch") or "-",
            b["timestamp"][:19].replace("T", " "),
        )
    console.print(t)


@history.command("show")
@click.argument("build_id", type=int)
def history_show(build_id: int) -> None:
    """Show a past build by ID."""
    record = hist.get_build(build_id)
    if record is None:
        err_console.print(f"[bold red]Error:[/] Build {build_id} not found.")
        sys.exit(1)
    for k, v in record.items():
        console.print(f"  {k:<15} {v}")


@history.command("clear")
@click.confirmation_option(prompt="Clear all build history?")
def history_clear() -> None:
    """Clear all history."""
    hist.clear()
    console.print("[green]History cleared.[/]")



@cli.command()
def version() -> None:
    """Show version."""
    console.print(f"memprobe v{__version__}")
