"""HTML report generator using Jinja2 templates."""

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader

from . import __version__
from .models import MemoryMap, BuildDiff, SectionType
from .bloat import analyze, BloatWarning

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_SECTION_COLORS = {
    SectionType.TEXT:   "#4a9eff",
    SectionType.RODATA: "#34c48a",
    SectionType.DATA:   "#e8a030",
    SectionType.BSS:    "#e05858",
    SectionType.HEAP:   "#9070d0",
    SectionType.STACK:  "#608070",
    SectionType.OTHER:  "#505060",
}


def _human_bytes(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


def _build_treemap_data(mmap: MemoryMap) -> dict:
    """Convert MemoryMap into a D3 treemap-compatible JSON structure.

    Hierarchy:
      firmware → section → [object_file group →] symbol

    When a section's symbols come from multiple object files an intermediate
    object-file grouping node is inserted so the treemap can be drilled into
    arbitrarily deep.
    """
    def _sym_node(s, sec_type: str) -> dict:
        return {
            "name": s.name,
            "size_bytes": s.size,
            "object_file": s.object_file or "",
            "library": s.library or "",
            "type": sec_type,
            "source_location": s.source_location or "",
        }

    # RAM-resident section types: these store no image bytes (occupies_file is
    # False) but genuinely consume target memory, so they belong on the map.
    ram_types = {SectionType.BSS, SectionType.DATA, SectionType.HEAP, SectionType.STACK}

    children = []
    for sec in mmap.sections:
        if sec.size == 0:
            continue
        # Drop sections that are never shipped to the device: link-time-only
        # metadata (.strtab, .symtab, .xt.prop, not SHF_ALLOC) and image-less
        # address-space reservations that aren't RAM either (ESP-IDF's
        # .flash_rodata_dummy). Keeping them would inflate the map with bytes
        # that exist in neither flash nor RAM.
        if not sec.alloc:
            continue
        if not sec.occupies_file and sec.section_type not in ram_types:
            continue
        sec_type = sec.section_type.value
        sec_node: dict = {
            "name": sec.name,
            "size_bytes": sec.size,
            "type": sec_type,
        }
        valid_syms = [s for s in sec.symbols if s.size > 0]
        if valid_syms:
            # Group by object file
            by_obj: dict = defaultdict(list)
            for s in valid_syms:
                by_obj[s.object_file or "(unknown)"].append(s)

            if len(by_obj) <= 1:
                # Single origin - go straight to symbols
                sec_node["children"] = [_sym_node(s, sec_type) for s in valid_syms]
            else:
                # Multiple object files → intermediate grouping level
                obj_nodes = []
                for obj, syms in sorted(by_obj.items(), key=lambda kv: -sum(s.size for s in kv[1])):
                    lib = syms[0].library or ""
                    display = f"{lib} › {obj}" if lib else obj
                    obj_nodes.append({
                        "name": display,
                        "size_bytes": sum(s.size for s in syms),
                        "type": sec_type,
                        "object_file": obj,
                        "library": lib,
                        "is_obj_group": True,
                        "children": [_sym_node(s, sec_type) for s in sorted(syms, key=lambda s: -s.size)],
                    })
                sec_node["children"] = obj_nodes
        children.append(sec_node)

    return {"name": "firmware", "children": children}


def generate_report(
    mmap: MemoryMap,
    output_path: Path,
    warnings: Optional[list[BloatWarning]] = None,
) -> None:
    """Render the main analysis HTML report to output_path."""
    if warnings is None:
        warnings = analyze(mmap)

    env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=False)
    env.filters["human_bytes"] = _human_bytes
    tmpl = env.get_template("report.html.j2")

    treemap_data = _build_treemap_data(mmap)
    # Build a lookup from section name → type for symbol type annotation
    sec_type_map = {sec.name: sec.section_type.value for sec in mmap.sections}
    symbols_json = [
        {
            "name": s.name,
            "size": s.size,
            "section": s.section,
            "type": sec_type_map.get(s.section, "other"),
            "object_file": s.object_file,
            "library": s.library or "",
            "source_location": s.source_location or "",
        }
        for s in sorted(mmap.all_symbols, key=lambda x: x.size, reverse=True)
    ]
    sections_json = [
        {
            "name": sec.name,
            "size": sec.size,
            "type": sec.section_type.value,
            "color": _SECTION_COLORS.get(sec.section_type, "#505060"),
        }
        for sec in mmap.sections if sec.size > 0
    ]

    # Compute region fill percentages
    regions_data = []
    for region in mmap.regions:
        pct = (region.used / region.length * 100) if region.length > 0 else 0
        regions_data.append({
            "name": region.name,
            "used": region.used,
            "length": region.length,
            "pct": round(pct, 1),
            "used_human": _human_bytes(region.used),
            "length_human": _human_bytes(region.length),
        })

    # If no regions, synthesize from flash/ram totals
    if not regions_data:
        regions_data = [
            {"name": "Flash (est.)", "used": mmap.total_flash, "length": 0,
             "pct": 0, "used_human": _human_bytes(mmap.total_flash), "length_human": "?"},
            {"name": "RAM (est.)", "used": mmap.total_ram, "length": 0,
             "pct": 0, "used_human": _human_bytes(mmap.total_ram), "length_human": "?"},
        ]

    warnings_data = [
        {
            "level": w.level,
            "message": w.message,
            "symbol": w.symbol,
            "size": w.size,
            "how_to_fix": w.how_to_fix,
        }
        for w in warnings
    ]

    source_basename = Path(mmap.source_file).name
    html = tmpl.render(
        mmap=mmap,
        treemap_data_json=json.dumps(treemap_data),
        symbols_json=json.dumps(symbols_json),
        sections_json=json.dumps(sections_json),
        regions=regions_data,
        warnings=warnings_data,
        total_flash=mmap.total_flash,
        total_ram=mmap.total_ram,
        total_flash_human=_human_bytes(mmap.total_flash),
        total_ram_human=_human_bytes(mmap.total_ram),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        version=__version__,
        source_file=mmap.source_file,
        source_basename=source_basename,
    )
    output_path.write_text(html, encoding="utf-8")


def generate_diff_report(
    build_diff: BuildDiff,
    old_mmap: MemoryMap,
    new_mmap: MemoryMap,
    output_path: Path,
) -> None:
    """Render a diff HTML report to output_path."""
    env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=False)
    env.filters["human_bytes"] = _human_bytes
    tmpl = env.get_template("diff.html.j2")

    diffs_json = [
        {
            "name": d.name,
            "object_file": d.object_file,
            "old_size": d.old_size,
            "new_size": d.new_size,
            "delta": d.delta,
        }
        for d in build_diff.symbol_diffs
    ]

    html = tmpl.render(
        diff=build_diff,
        old_mmap=old_mmap,
        new_mmap=new_mmap,
        old_basename=Path(build_diff.old_source).name,
        new_basename=Path(build_diff.new_source).name,
        diffs_json=json.dumps(diffs_json),
        flash_delta=build_diff.flash_delta,
        ram_delta=build_diff.ram_delta,
        flash_delta_human=_human_bytes(abs(build_diff.flash_delta)),
        ram_delta_human=_human_bytes(abs(build_diff.ram_delta)),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        version=__version__,
        human_bytes=_human_bytes,
    )
    output_path.write_text(html, encoding="utf-8")
