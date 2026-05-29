"""Modal worker for heavy ELF/map parsing.

The web server receives the upload, sends raw bytes here, and Modal runs the
parse in an isolated container sized to the file. The container shuts down
when done — no persistent state, no stored files.

Memory is estimated as: ceil(file_size_mb * 9.4 * 1.3)
  - 9.4x = measured peak/file-size ratio for typical debug ELFs
  - 1.3x = 30% headroom buffer
  - Minimum 128 MB (Modal floor)

Tiers (pre-defined because Modal requires fixed memory at deploy time):
  parse_file_xs  — 128 MB  — files up to ~10 MB  (warm)
  parse_file_sm  — 512 MB  — files up to ~24 MB  (warm)
  parse_file_md  — 768 MB  — retry tier 1
  parse_file_lg  — 1024 MB — retry tier 2 / last resort

Deploy:
    modal deploy modal_worker.py

Local test:
    modal run modal_worker.py --file /path/to/firmware.elf
"""

from __future__ import annotations

import math
import tempfile
import traceback
from pathlib import Path

import modal

# ---------------------------------------------------------------------------
# Image: installed once, shared across all tiers.
# ---------------------------------------------------------------------------
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "pyelftools>=0.29",
        "click>=8.0",
        "rich>=13.0",
        "jinja2>=3.1",
    )
    .add_local_python_source("memprobe")
)

app = modal.App("memprobe-parser", image=image)


def estimate_mb(file_size: int) -> int:
    """Estimate memory needed: 9.4x file size with 30% headroom, min 128 MB."""
    peak_estimate = (file_size / (1024 * 1024)) * 9.4
    return max(128, math.ceil(peak_estimate * 1.3))


# ---------------------------------------------------------------------------
# Tiered functions — same implementation, different memory allocations.
# ---------------------------------------------------------------------------
# xs and sm are kept warm — covers small files and your typical 20+ MB debug
# ELF. Cold starts add RAM overhead on top of the parse peak so warm containers
# are required for reliability, not just speed.
# Cost: xs ~$0.19/month + sm ~$0.44/month = ~$0.63/month total.
# md and lg cold-start on demand — large files are rare enough that the retry
# from sm gives them time to spin up.
@app.function(memory=128,  cpu=1.0, timeout=300, image=image, min_containers=1, scaledown_window=300)
def parse_file_xs(file_bytes: bytes, filename: str) -> dict:
    return _parse_impl(file_bytes, filename)


@app.function(memory=768,  cpu=4.0, timeout=300, image=image, min_containers=1, scaledown_window=300)
def parse_file_sm(file_bytes: bytes, filename: str) -> dict:
    return _parse_impl(file_bytes, filename)


@app.function(memory=1024, cpu=4.0, timeout=300, image=image)
def parse_file_md(file_bytes: bytes, filename: str) -> dict:
    return _parse_impl(file_bytes, filename)


@app.function(memory=2048, cpu=4.0, timeout=300, image=image)
def parse_file_lg(file_bytes: bytes, filename: str) -> dict:
    return _parse_impl(file_bytes, filename)


# ---------------------------------------------------------------------------
# Shared implementation.
# ---------------------------------------------------------------------------
def _parse_impl(file_bytes: bytes, filename: str) -> dict:
    """Parse an ELF or linker map and return a serialisable dict.

    file_bytes may be zlib-compressed (detected by magic bytes).
    Always includes "peak_ram_mb" and "timings" so the caller can log
    where time is actually spent.
    Returns {"error": str, "traceback": str} on failure.
    """
    import tracemalloc
    import time
    import zlib

    # Decompress if the caller sent zlib-compressed bytes.
    if file_bytes[:2] == b'\x78\x9c' or file_bytes[:2] == b'\x78\xda' or file_bytes[:2] == b'\x78\x01':
        file_bytes = zlib.decompress(file_bytes)

    suffix = Path(filename).suffix.lower()
    t0 = time.monotonic()

    try:
        tracemalloc.start()

        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(file_bytes)
            tmp_path = Path(tmp.name)
        t_write = time.monotonic()

        try:
            if suffix == ".map":
                from memprobe.parsers.map_gcc import parse as parse_gcc
                from memprobe.parsers.map_iar import parse as parse_iar, detect_iar
                if detect_iar(file_bytes[:4096]):
                    mmap = parse_iar(tmp_path)
                else:
                    mmap = parse_gcc(tmp_path)
            else:
                from memprobe.parsers.elf import parse as parse_elf
                mmap = parse_elf(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)
        t_parse = time.monotonic()

        _, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        result = _mmap_to_dict(mmap)
        t_serialize = time.monotonic()

        result["peak_ram_mb"] = round(peak_bytes / 1024 / 1024, 1)
        result["timings"] = {
            "write_s":     round(t_write     - t0,      2),
            "parse_s":     round(t_parse     - t_write, 2),
            "serialize_s": round(t_serialize - t_parse, 2),
            "total_s":     round(t_serialize - t0,      2),
        }
        return result

    except Exception as e:
        tracemalloc.stop()
        return {"error": f"Parse failed: {e}", "traceback": traceback.format_exc()}


def _mmap_to_dict(mmap) -> dict:
    """Serialise a MemoryMap to a plain dict the Django server can reconstruct."""
    sections = []
    for sec in mmap.sections:
        symbols = [
            {
                "name": sym.name,
                "size": sym.size,
                "address": sym.address,
                "section": sym.section,
                "object_file": sym.object_file or "",
                "library": sym.library or "",
                "source_location": sym.source_location or "",
            }
            for sym in sec.symbols
        ]
        sections.append({
            "name": sec.name,
            "size": sec.size,
            "address": sec.address,
            "type": sec.section_type.value,
            "vma": sec.vma,
            "lma": sec.lma,
            "symbols": symbols,
        })

    regions = [
        {
            "name": r.name,
            "origin": r.origin,
            "length": r.length,
            "used": r.used,
        }
        for r in (mmap.regions or [])
    ]

    return {
        "source_file": mmap.source_file,
        "toolchain": mmap.toolchain,
        "target": mmap.target,
        "sections": sections,
        "regions": regions,
        "binary_info": mmap.binary_info or {},
    }


# ---------------------------------------------------------------------------
# Local test entrypoint: modal run modal_worker.py --file firmware.elf
# ---------------------------------------------------------------------------
@app.local_entrypoint()
def main(file: str):
    path = Path(file)
    if not path.exists():
        print(f"File not found: {file}")
        return

    size = path.stat().st_size
    est = estimate_mb(size)

    if est <= 128:
        tier, fn = "xs (128 MB)", parse_file_xs
    elif est <= 300:
        tier, fn = "sm (512 MB)", parse_file_sm
    elif est <= 512:
        tier, fn = "md (768 MB)", parse_file_md
    else:
        tier, fn = "lg (1024 MB)", parse_file_lg

    print(f"File     : {path.name} ({size // 1024} KB)")
    print(f"Estimated: {est} MB needed → tier {tier}")

    file_bytes = path.read_bytes()
    result = fn.remote(file_bytes, path.name)

    if "error" in result:
        print(f"Error: {result['error']}")
        return

    total_syms = sum(len(s["symbols"]) for s in result["sections"])
    print(f"Sections : {len(result['sections'])}")
    print(f"Symbols  : {total_syms}")
    print(f"Regions  : {len(result['regions'])}")
    print(f"Peak RAM : {result.get('peak_ram_mb', '?')} MB")
    print(f"Toolchain: {result['toolchain']}")
