"""Deep-insight analysis for firmware memory maps.

All functions operate on a MemoryMap and return plain dicts/lists so the
results can be serialised directly to JSON by the Django view layer.

Design rule: every insight must be 100% accurate with zero false positives.
When in doubt about a heuristic, omit it rather than show wrong data.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import PurePosixPath

from .models import MemoryMap, SectionType

# Section types that count as flash-resident
_FLASH_TYPES  = {SectionType.TEXT, SectionType.RODATA, SectionType.DATA}
# Section types that count as RAM-resident
_RAM_TYPES    = {SectionType.BSS, SectionType.DATA}
# Section types that are read-only data
_RODATA_TYPES = {SectionType.RODATA}

# Path prefixes that indicate toolchain / SDK sources rather than user code.
# These are stripped to a canonical "(toolchain)" label in the directory view.
_TOOLCHAIN_ROOTS = (
    "/Users/", "/home/", "/tmp/", "/opt/", "/usr/",
    "C:\\", "c:\\",  # Windows build agents
)


def _strip_line(loc: str | None) -> str | None:
    """Remove the :line suffix from a source_location string."""
    if not loc:
        return None
    colon = loc.rfind(":")
    if colon > 0 and loc[colon + 1:].isdigit():
        return loc[:colon]
    return loc


def _is_toolchain_path(path: str) -> bool:
    """Return True if path looks like a compiler/SDK internal path."""
    for prefix in _TOOLCHAIN_ROOTS:
        if path.startswith(prefix):
            return True
    return False


def _top_dir(path_str: str) -> str:
    """Return a meaningful top-level directory label for a source path.

    - Relative paths: return the first path component.
    - Absolute toolchain paths: return '(toolchain / SDK)'.
    - Other absolute paths: return the first non-root component.
    """
    if not path_str:
        return "(unknown)"

    if _is_toolchain_path(path_str):
        return "(toolchain / SDK)"

    try:
        parts = [p for p in PurePosixPath(path_str).parts
                 if p not in ("/", ".", "..")]
        if parts:
            return parts[0]
    except Exception:
        pass
    return "(unknown)"


def _shorten(path_str: str, max_components: int = 3) -> str:
    """Truncate a path to its last N components with a leading '...' if needed."""
    try:
        parts = PurePosixPath(path_str).parts
    except Exception:
        return path_str
    if len(parts) <= max_components:
        return path_str
    return ".../" + "/".join(parts[-max_components:])


# ---------------------------------------------------------------------------
# Individual insight computations
# ---------------------------------------------------------------------------

def _file_contributors(mmap: MemoryMap) -> list[dict]:
    """Sum flash and RAM bytes per source file. Exclude toolchain paths.
    Returns top 50 sorted by flash desc."""
    flash: dict[str, int] = defaultdict(int)
    ram:   dict[str, int] = defaultdict(int)

    for sec in mmap.sections:
        is_flash = sec.section_type in _FLASH_TYPES
        is_ram   = sec.section_type in _RAM_TYPES
        if not (is_flash or is_ram):
            continue
        for sym in sec.symbols:
            if sym.size <= 0:
                continue
            loc = _strip_line(sym.source_location)
            if not loc or _is_toolchain_path(loc):
                continue
            if is_flash:
                flash[loc] += sym.size
            if is_ram:
                ram[loc] += sym.size

    all_files = set(flash) | set(ram)
    results = [
        {"file": f, "flash": flash.get(f, 0), "ram": ram.get(f, 0)}
        for f in all_files
    ]
    results.sort(key=lambda x: x["flash"] + x["ram"], reverse=True)
    return results[:50]


def _dir_contributors(mmap: MemoryMap) -> list[dict]:
    """Sum flash bytes per top-level source directory. Toolchain paths are
    grouped under '(toolchain / SDK)'. Returns top 20 by flash desc."""
    totals: dict[str, int] = defaultdict(int)

    for sec in mmap.sections:
        if sec.section_type not in _FLASH_TYPES:
            continue
        for sym in sec.symbols:
            if sym.size <= 0:
                continue
            loc = _strip_line(sym.source_location)
            if not loc:
                continue
            totals[_top_dir(loc)] += sym.size

    results = [{"dir": d, "flash": v} for d, v in totals.items()]
    results.sort(key=lambda x: x["flash"], reverse=True)
    return results[:20]


def _symbol_size_distribution(mmap: MemoryMap) -> list[dict]:
    """Bucket all non-zero symbols by size range."""
    buckets = [
        ("1-16 B",    1,    16),
        ("17-64 B",   17,   64),
        ("65-256 B",  65,   256),
        ("257 B-1 KB",257,  1024),
        ("1-4 KB",    1025, 4096),
        ("> 4 KB",    4097, None),
    ]
    counts = [0] * len(buckets)
    bytes_ = [0] * len(buckets)

    for sym in mmap.all_symbols:
        if sym.size <= 0:
            continue
        for i, (_, lo, hi) in enumerate(buckets):
            if sym.size >= lo and (hi is None or sym.size <= hi):
                counts[i] += 1
                bytes_[i] += sym.size
                break

    return [
        {"label": lbl, "count": counts[i], "bytes": bytes_[i]}
        for i, (lbl, _, _) in enumerate(buckets)
        if counts[i] > 0
    ]


def _padding_waste(mmap: MemoryMap) -> dict:
    """Detect alignment padding gaps (1-32 bytes) between consecutive symbols
    within each section. Returns total and per-section breakdown."""
    MAX_GAP = 32
    by_section: dict[str, int] = defaultdict(int)

    for sec in mmap.sections:
        if len(sec.symbols) < 2:
            continue
        sorted_syms = sorted(
            (s for s in sec.symbols if s.address > 0 and s.size > 0),
            key=lambda s: s.address,
        )
        if len(sorted_syms) < 2:
            continue
        for i in range(len(sorted_syms) - 1):
            cur = sorted_syms[i]
            nxt = sorted_syms[i + 1]
            gap = nxt.address - (cur.address + cur.size)
            if 0 < gap <= MAX_GAP:
                by_section[sec.name] += gap

    total = sum(by_section.values())
    section_list = [
        {"section": s, "bytes": b}
        for s, b in sorted(by_section.items(), key=lambda x: x[1], reverse=True)
    ]
    return {"total_bytes": total, "by_section": section_list}


def _duplicate_symbols(mmap: MemoryMap) -> list[dict]:
    """Find genuinely duplicated global symbols (same name, multiple distinct
    addresses, same size). This pattern indicates COMDAT de-duplication failure
    or identical functions compiled into different translation units.

    Excluded:
    - Symbols containing '$' (GCC internal clones: $isra$, $part$, $constprop$)
    - '_ZL' prefixed symbols (C++ file-scope statics with local linkage --
      having the same name across TUs is expected and correct)
    - Symbols where the sizes differ (likely intentional overloads/overrides)
    """
    name_to_syms: dict[str, list] = defaultdict(list)
    for sym in mmap.all_symbols:
        if not sym.name or sym.size <= 0:
            continue
        # Exclude GCC internal cloned functions
        if "$" in sym.name:
            continue
        # Exclude C++ file-scope statics (local linkage) -- same name in
        # multiple TUs is expected
        if sym.name.startswith("_ZL"):
            continue
        name_to_syms[sym.name].append(sym)

    results = []
    for name, syms in name_to_syms.items():
        addrs = {s.address for s in syms}
        if len(addrs) < 2:
            continue
        sizes = [s.size for s in syms]
        # Only flag if sizes match -- different sizes likely means different
        # functions that happen to share a name (e.g. weak + override)
        if len(set(sizes)) > 1:
            continue
        results.append({
            "name": name,
            "count": len(syms),
            "total_size": sum(sizes),
            "size_each": sizes[0],
        })

    results.sort(key=lambda x: x["total_size"], reverse=True)
    return results[:30]


def _rodata_summary(mmap: MemoryMap) -> dict:
    """Summarise read-only data sections: symbol count, total bytes, and the
    number of distinct source files contributing symbols."""
    count = 0
    total = 0
    source_files: set[str] = set()

    for sec in mmap.sections:
        if sec.section_type not in _RODATA_TYPES:
            continue
        for sym in sec.symbols:
            if sym.size <= 0:
                continue
            count += 1
            total += sym.size
            loc = _strip_line(sym.source_location)
            if loc:
                source_files.add(loc)

    return {
        "symbol_count": count,
        "total_bytes": total,
        "unique_source_files": len(source_files),
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def compute_insights(mmap: MemoryMap) -> dict:
    """Compute all deep insights for a MemoryMap.

    Returns a dict ready for JSON serialisation with keys:
      file_contributors, dir_contributors, symbol_size_distribution,
      padding_waste, duplicate_symbols, rodata_summary
    """
    dup_strings = (mmap.binary_info or {}).get("duplicate_strings", [])

    return {
        "file_contributors":        _file_contributors(mmap),
        "dir_contributors":         _dir_contributors(mmap),
        "symbol_size_distribution": _symbol_size_distribution(mmap),
        "padding_waste":            _padding_waste(mmap),
        "duplicate_symbols":        _duplicate_symbols(mmap),
        "rodata_summary":           _rodata_summary(mmap),
        "duplicate_strings":        dup_strings,
    }
