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
import queue as _queue
import tempfile
import threading as _threading
import traceback
from pathlib import Path
from typing import Generator

import modal

# ---------------------------------------------------------------------------
# Image: installed once, shared across all tiers.
# ---------------------------------------------------------------------------
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "pyelftools>=0.29",
        "capstone>=4.0",
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
# Tiered functions — same generator implementation, different memory limits.
# Callers use fn.remote_gen() to receive progress events as the parse runs,
# with the final event carrying the completed result dict.
# ---------------------------------------------------------------------------
@app.function(memory=128,  cpu=1.0, timeout=300, image=image)
def parse_file_xs(file_bytes: bytes, filename: str) -> Generator[dict, None, None]:
    yield from _parse_impl_gen(file_bytes, filename)


@app.function(memory=768,  cpu=4.0, timeout=300, image=image)
def parse_file_sm(file_bytes: bytes, filename: str) -> Generator[dict, None, None]:
    yield from _parse_impl_gen(file_bytes, filename)


@app.function(memory=1024, cpu=4.0, timeout=300, image=image)
def parse_file_md(file_bytes: bytes, filename: str) -> Generator[dict, None, None]:
    yield from _parse_impl_gen(file_bytes, filename)


@app.function(memory=2048, cpu=4.0, timeout=300, image=image)
def parse_file_lg(file_bytes: bytes, filename: str) -> Generator[dict, None, None]:
    yield from _parse_impl_gen(file_bytes, filename)


# ---------------------------------------------------------------------------
# Shared generator implementation.
# ---------------------------------------------------------------------------
# Each yielded dict is either a progress event:
#   {"progress": 0.0-1.0, "stage": str}
# or the final result event:
#   {"progress": 1.0, "stage": "done", "result": dict}
# or an error event:
#   {"progress": 1.0, "stage": "error", "error": str, "traceback": str}
#
# The parse itself is run on a background thread so the generator can yield
# progress events from the parse callbacks without blocking.
# ---------------------------------------------------------------------------
def _parse_impl_gen(file_bytes: bytes, filename: str) -> Generator[dict, None, None]:
    import tracemalloc
    import time
    import zlib

    yield {"progress": 0.05, "stage": "started"}

    # Decompress if the caller sent zlib-compressed bytes.
    if file_bytes[:2] in (b'\x78\x9c', b'\x78\xda', b'\x78\x01'):
        file_bytes = zlib.decompress(file_bytes)

    yield {"progress": 0.10, "stage": "decompressed"}

    suffix = Path(filename).suffix.lower()
    t0 = time.monotonic()
    tracemalloc.start()

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(file_bytes)
        tmp_path = Path(tmp.name)
    t_write = time.monotonic()

    yield {"progress": 0.12, "stage": "file_written"}

    # Run the blocking parse on a background thread so this generator can
    # drain the progress queue and yield events while it runs.
    progress_q: _queue.Queue = _queue.Queue()
    result_box: list = [None]
    error_box:  list = [None]

    def _run_parse():
        try:
            if suffix == ".map":
                from memprobe.parsers.map_gcc import parse as parse_gcc
                from memprobe.parsers.map_iar import parse as parse_iar, detect_iar
                progress_q.put({"progress": 0.40, "stage": "parsing_map"})
                if detect_iar(file_bytes[:4096]):
                    mmap = parse_iar(tmp_path)
                else:
                    mmap = parse_gcc(tmp_path)
            else:
                from memprobe.parsers.elf import parse as parse_elf

                def _on_elf_progress(frac: float, stage: str):
                    # frac is 0-1 within the ELF parse; map to 0.12-0.88 overall.
                    overall = 0.12 + frac * 0.76
                    progress_q.put({"progress": overall, "stage": stage})

                mmap = parse_elf(tmp_path, progress_cb=_on_elf_progress)

            result_box[0] = mmap
        except Exception as exc:
            error_box[0] = exc
        finally:
            progress_q.put(None)  # sentinel: parse is done

    t = _threading.Thread(target=_run_parse, daemon=True)
    t.start()

    # Drain progress events until the sentinel arrives.
    while True:
        try:
            item = progress_q.get(timeout=290)
        except _queue.Empty:
            break
        if item is None:
            break
        yield item

    t.join(timeout=5)
    tmp_path.unlink(missing_ok=True)
    t_parse = time.monotonic()

    if error_box[0] is not None:
        tracemalloc.stop()
        yield {
            "progress": 1.0,
            "stage": "error",
            "error": f"Parse failed: {error_box[0]}",
            "traceback": traceback.format_exc(),
        }
        return

    mmap = result_box[0]
    if mmap is None:
        tracemalloc.stop()
        yield {"progress": 1.0, "stage": "error", "error": "Parse returned no result."}
        return

    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    yield {"progress": 0.90, "stage": "serializing"}

    result = _mmap_to_dict(mmap)
    t_serialize = time.monotonic()

    result["peak_ram_mb"] = round(peak_bytes / 1024 / 1024, 1)
    result["timings"] = {
        "write_s":     round(t_write     - t0,      2),
        "parse_s":     round(t_parse     - t_write, 2),
        "serialize_s": round(t_serialize - t_parse, 2),
        "total_s":     round(t_serialize - t0,      2),
    }

    yield {"progress": 1.0, "stage": "done", "result": result}


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
        "call_graph": mmap.call_graph or {},
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
