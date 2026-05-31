"""ELF binary parser using pyelftools."""

import array
import bisect
import gc
import logging
import re
import struct
import sys
import traceback
import zlib

logger = logging.getLogger(__name__)
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Callable, Optional

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from ..models import MemoryMap, Section, Symbol, SectionType
from .map_gcc import _classify_section

_SKIP_SECTION_PREFIXES = (".debug", ".comment", ".note", ".ARM.attr")
_SHF_EXECINSTR = 0x4  # ELF section flag: section contains executable code
_SHF_ALLOC = 0x2  # ELF section flag: section is loaded into memory at runtime


def _compute_lma(sh_addr: int, load_segments: list[tuple[int, int, int]]) -> int:
    """Map a section's VMA to its load (physical) address through PT_LOAD.

    A section's LMA is its VMA shifted by the containing segment's
    vaddr->paddr offset:  lma = p_paddr + (sh_addr - p_vaddr).
    On most desktop ELFs p_paddr == p_vaddr so LMA == VMA; on embedded images
    (e.g. .data initialized from a flash copy) p_paddr is the flash address.
    Sections outside every load segment fall back to their VMA.

    load_segments is a list of (p_vaddr, p_paddr, p_memsz) tuples.
    """
    for p_vaddr, p_paddr, p_memsz in load_segments:
        if p_vaddr <= sh_addr < p_vaddr + p_memsz:
            return p_paddr + (sh_addr - p_vaddr)
    return sh_addr

# Maps e_machine values to human-readable names
_MACHINE_NAMES = {
    "EM_386": "x86 (32-bit)",
    "EM_X86_64": "x86-64",
    "EM_ARM": "ARM",
    "EM_AARCH64": "ARM64 (AArch64)",
    "EM_XTENSA": "Xtensa",
    "EM_RISCV": "RISC-V",
    "EM_MIPS": "MIPS",
    "EM_PPC": "PowerPC",
    "EM_AVR": "AVR",
}

# Infer chip family from architecture + section name patterns
def _infer_chip_family(arch: str, section_names: list[str]) -> Optional[str]:
    if arch == "EM_XTENSA":
        if any("esp" in n or "iram" in n or "dram" in n for n in section_names):
            return "ESP32 (Xtensa LX6/LX7)"
        return "Xtensa"
    if arch == "EM_ARM":
        if any("nrf" in n or "nordic" in n for n in section_names):
            return "Nordic nRF (ARM Cortex-M)"
        if any("stm" in n for n in section_names):
            return "STM32 (ARM Cortex-M)"
        return "ARM Cortex-M"
    if arch == "EM_AARCH64":
        return "ARM Cortex-A (64-bit)"
    if arch == "EM_RISCV":
        return "RISC-V"
    if arch == "EM_AVR":
        return "AVR (8-bit)"
    return None


def _parse_arm_flags(e_flags: int) -> list[str]:
    """Decode ARM EABI e_flags into human-readable feature list."""
    features = []
    eabi = (e_flags >> 24) & 0xFF
    if eabi:
        features.append(f"EABI v{eabi}")
    if e_flags & 0x800:
        features.append("Thumb interwork")
    if e_flags & 0x200:
        features.append("Thumb-2")
    if e_flags & 0x400:
        features.append("hard-float ABI")
    elif e_flags & 0x200:
        features.append("soft-float")
    vfp = (e_flags >> 8) & 0xF
    if vfp:
        features.append(f"VFPv{vfp}")
    return features


def _decode(val) -> str:
    """Decode a bytes-or-str DWARF attribute value."""
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return str(val)


def _extract_die_addr(die, addr_size: int) -> Optional[int]:
    """Extract a static address from a DIE's DW_AT_location (DW_OP_addr) or
    DW_AT_low_pc attribute. Returns None if not a simple absolute address."""
    # DW_AT_low_pc - used on subprograms
    lpc = die.attributes.get("DW_AT_low_pc")
    if lpc is not None:
        return int(lpc.value)
    # DW_AT_location - used on variables; look for DW_OP_addr (0x03)
    loc = die.attributes.get("DW_AT_location")
    if loc is None:
        return None
    val = loc.value
    # exprloc / block forms store the expression as a list of ints or bytes
    if isinstance(val, (list, bytes, bytearray)) and len(val) > addr_size and val[0] == 0x03:
        raw = bytes(val[1: 1 + addr_size])
        fmt = "<I" if addr_size == 4 else "<Q"
        return struct.unpack(fmt, raw)[0]
    return None


def _process_cu_chunk(file_path: str, target_offsets: frozenset) -> tuple[dict, dict, dict]:
    """Worker: process only the CUs at the given byte offsets in .debug_info.

    Runs in a subprocess. Opens its own ELFFile handle so workers don't share
    state. Iterates CUs but skips by reading headers only (fast) until it hits
    a target offset, then breaks as soon as it passes the last target.
    Returns (name_map, die_addr_map, addr_to_loc) partial dicts to be merged.
    """
    import gc as _gc
    from elftools.elf.elffile import ELFFile as _ELFFile

    name_map: dict = {}
    die_addr_map: dict = {}
    addr_to_loc: dict = {}
    _DIE_TAGS = {"DW_TAG_variable", "DW_TAG_subprogram"}

    max_offset = max(target_offsets)

    with open(file_path, "rb") as f:
        elf = _ELFFile(f)
        if not elf.has_dwarf_info():
            return name_map, die_addr_map, addr_to_loc
        dwarf = elf.get_dwarf_info()

        processed = 0
        skipped = 0
        for cu in dwarf.iter_CUs():
            cu_off = cu.cu_offset
            if cu_off > max_offset:
                break  # Past all our targets — stop early.
            if cu_off not in target_offsets:
                # Skip without parsing DIEs.
                if hasattr(cu, "_dielist"):
                    cu._dielist = []
                if hasattr(cu, "_diemap"):
                    cu._diemap = {}
                skipped += 1
                if skipped % 200 == 0:
                    _gc.collect()
                continue

            try:
                top_die = cu.get_top_DIE()
                addr_size = cu["address_size"]
                comp_dir_attr = top_die.attributes.get("DW_AT_comp_dir")
                comp_dir_str = _decode(comp_dir_attr.value) if comp_dir_attr else ""

                lineprog = dwarf.line_program_for_CU(cu)
                file_entries = lineprog.header.file_entry if lineprog else []
                inc_dirs = lineprog.header.include_directory if lineprog else []
                _file_cache: dict = {}

                def _resolve_file(
                    file_idx: int,
                    _cache: dict = _file_cache,
                    _entries: list = file_entries,
                    _dirs: list = inc_dirs,
                    _comp_dir: str = comp_dir_str,
                ) -> str:
                    if file_idx in _cache:
                        return _cache[file_idx]
                    if file_idx == 0 or file_idx > len(_entries):
                        _cache[file_idx] = ""
                        return ""
                    entry = _entries[file_idx - 1]
                    name = _decode(entry.name)
                    dir_idx = entry.dir_index
                    if dir_idx == 0:
                        base = _comp_dir
                    elif dir_idx <= len(_dirs):
                        base = _decode(_dirs[dir_idx - 1])
                    else:
                        base = _comp_dir
                    full = f"{base}/{name}" if base else name
                    if _comp_dir and full.startswith(_comp_dir):
                        full = full[len(_comp_dir):].lstrip("/")
                    _cache[file_idx] = full
                    return full

                stack = [top_die]
                while stack:
                    die = stack.pop()
                    try:
                        if die.tag in _DIE_TAGS:
                            file_attr = die.attributes.get("DW_AT_decl_file")
                            line_attr = die.attributes.get("DW_AT_decl_line")
                            if file_attr and line_attr:
                                path = _resolve_file(int(file_attr.value))
                                if path:
                                    loc_str = f"{path}:{int(line_attr.value)}"
                                    name_attr = die.attributes.get("DW_AT_name")
                                    if name_attr:
                                        uname = _decode(name_attr.value)
                                        if uname not in name_map:
                                            name_map[uname] = loc_str
                                    for lnk_attr_name in ("DW_AT_linkage_name",
                                                          "DW_AT_MIPS_linkage_name"):
                                        lnk = die.attributes.get(lnk_attr_name)
                                        if lnk:
                                            mname = _decode(lnk.value)
                                            if mname not in name_map:
                                                name_map[mname] = loc_str
                                            break
                                    sym_addr = _extract_die_addr(die, addr_size)
                                    if sym_addr is not None and sym_addr not in die_addr_map:
                                        die_addr_map[sym_addr] = loc_str
                    except Exception:
                        pass
                    stack.extend(die.iter_children())

                if lineprog:
                    for entry in lineprog.get_entries():
                        state = entry.state
                        if state is None or state.end_sequence or state.file == 0:
                            continue
                        path = _resolve_file(state.file)
                        if path and state.address not in addr_to_loc:
                            addr_to_loc[state.address] = f"{path}:{state.line}"

            except Exception:
                pass
            finally:
                if hasattr(cu, "_dielist"):
                    cu._dielist = []
                if hasattr(cu, "_diemap"):
                    cu._diemap = {}
                processed += 1
                if processed % 200 == 0:
                    _gc.collect()

    return name_map, die_addr_map, addr_to_loc


def _build_dwarf_maps(elf: ELFFile, file_path: Optional[Path] = None, progress_cb=None) -> tuple[dict[str, str], dict[int, str], list[int], list[str]]:
    """Build lookup structures from DWARF info:

    1. name_map:  symbol name (mangled or unmangled) → "file:line"
    2. die_addr_map: variable/function address → "file:line"  (from DIEs,
       not the line program - so it never crosses section boundaries)
    3. (sorted_addrs, sorted_locs): line-program address map used as last-
       resort fallback only for code symbols with no DIE match.

    """
    if not elf.has_dwarf_info():
        return {}, {}, [], []

    dwarf = elf.get_dwarf_info()
    name_map: dict[str, str] = {}
    die_addr_map: dict[int, str] = {}
    addr_to_loc: dict[int, str] = {}

    # Fast pass: collect CU offsets and sizes (header reads only, no DIE parsing).
    cu_info: list[tuple[int, int]] = []  # (cu_offset, unit_length)
    for cu in dwarf.iter_CUs():
        cu_info.append((cu.cu_offset, cu["unit_length"]))
        if hasattr(cu, "_dielist"):
            cu._dielist = []
        if hasattr(cu, "_diemap"):
            cu._diemap = {}
    total_cus = len(cu_info)

    # Parallel processing: distribute CUs across workers weighted by unit_length
    # so each worker gets roughly equal byte-work rather than equal CU count.
    _PARALLEL_THRESHOLD = 40
    if file_path is not None and total_cus >= _PARALLEL_THRESHOLD:
        n_workers = min(4, total_cus)
        worker_offsets: list[list[int]] = [[] for _ in range(n_workers)]
        worker_loads: list[int] = [0] * n_workers
        for cu_off, cu_len in cu_info:
            w = worker_loads.index(min(worker_loads))
            worker_offsets[w].append(cu_off)
            worker_loads[w] += cu_len

        fp = str(file_path)
        parallel_ok = False
        try:
            with ProcessPoolExecutor(max_workers=n_workers) as pool:
                futures = [
                    pool.submit(_process_cu_chunk, fp, frozenset(offsets))
                    for offsets in worker_offsets
                    if offsets
                ]
                total_futures = len(futures)
                done_count = 0
                for fut in futures:
                    c_name, c_die, c_loc = fut.result()
                    done_count += 1
                    if progress_cb:
                        progress_cb(done_count / total_futures)
                    for k, v in c_name.items():
                        if k not in name_map:
                            name_map[k] = v
                    for k, v in c_die.items():
                        if k not in die_addr_map:
                            die_addr_map[k] = v
                    for k, v in c_loc.items():
                        if k not in addr_to_loc:
                            addr_to_loc[k] = v
            parallel_ok = True
        except Exception:
            # Process forking not supported in this environment — fall through
            # to the sequential path below.
            print(f"[memprobe] parallel DWARF parse failed, falling back to sequential: "
                  f"{traceback.format_exc()}", file=sys.stderr)
            name_map.clear()
            die_addr_map.clear()
            addr_to_loc.clear()

        if parallel_ok:
            raw_addrs = sorted(addr_to_loc)
            sorted_addrs = array.array("Q", raw_addrs)
            sorted_locs = [addr_to_loc[a] for a in raw_addrs]
            return name_map, die_addr_map, sorted_addrs, sorted_locs
        # else: fall through to sequential path below

    _DIE_TAGS = {"DW_TAG_variable", "DW_TAG_subprogram"}

    for cu_idx, cu in enumerate(dwarf.iter_CUs()):
        try:
            top_die = cu.get_top_DIE()
            addr_size = cu["address_size"]
            comp_dir_attr = top_die.attributes.get("DW_AT_comp_dir")
            comp_dir_str = _decode(comp_dir_attr.value) if comp_dir_attr else ""

            lineprog = dwarf.line_program_for_CU(cu)
            file_entries = lineprog.header.file_entry if lineprog else []
            inc_dirs = lineprog.header.include_directory if lineprog else []

            # Memoised per-CU: each unique file index is resolved once and
            # cached for the remainder of this CU's DIE walk + line program.
            _file_cache: dict[int, str] = {}

            def _resolve_file(
                file_idx: int,
                _cache: dict = _file_cache,
                _entries: list = file_entries,
                _dirs: list = inc_dirs,
                _comp_dir: str = comp_dir_str,
            ) -> str:
                if file_idx in _cache:
                    return _cache[file_idx]
                if file_idx == 0 or file_idx > len(_entries):
                    _cache[file_idx] = ""
                    return ""
                entry = _entries[file_idx - 1]
                name = _decode(entry.name)
                dir_idx = entry.dir_index
                if dir_idx == 0:
                    base = _comp_dir
                elif dir_idx <= len(_dirs):
                    base = _decode(_dirs[dir_idx - 1])
                else:
                    base = _comp_dir
                full = f"{base}/{name}" if base else name
                if _comp_dir and full.startswith(_comp_dir):
                    full = full[len(_comp_dir):].lstrip("/")
                _cache[file_idx] = full
                return full

            # -- Iterative DIE walk ----------------------------------------
            # An iterative stack avoids Python recursion overhead and stack
            # overflow on deeply nested DIE trees.  Logic is identical to the
            # former recursive _walk().
            stack = [top_die]
            while stack:
                die = stack.pop()
                try:
                    if die.tag in _DIE_TAGS:
                        file_attr = die.attributes.get("DW_AT_decl_file")
                        line_attr = die.attributes.get("DW_AT_decl_line")
                        if file_attr and line_attr:
                            path = _resolve_file(int(file_attr.value))
                            if path:
                                loc_str = f"{path}:{int(line_attr.value)}"
                                # Index by unmangled name
                                name_attr = die.attributes.get("DW_AT_name")
                                if name_attr:
                                    uname = _decode(name_attr.value)
                                    if uname not in name_map:
                                        name_map[uname] = loc_str
                                # Index by mangled/linkage name (_ZL... etc.)
                                for lnk_attr_name in ("DW_AT_linkage_name",
                                                      "DW_AT_MIPS_linkage_name"):
                                    lnk = die.attributes.get(lnk_attr_name)
                                    if lnk:
                                        mname = _decode(lnk.value)
                                        if mname not in name_map:
                                            name_map[mname] = loc_str
                                        break
                                # Index by address (most reliable for data)
                                sym_addr = _extract_die_addr(die, addr_size)
                                if sym_addr is not None and sym_addr not in die_addr_map:
                                    die_addr_map[sym_addr] = loc_str
                except Exception:
                    pass
                stack.extend(die.iter_children())

            # -- Line program: last-resort fallback for code symbols --------
            if lineprog:
                for entry in lineprog.get_entries():
                    state = entry.state
                    if state is None or state.end_sequence or state.file == 0:
                        continue
                    path = _resolve_file(state.file)
                    if path and state.address not in addr_to_loc:
                        addr_to_loc[state.address] = f"{path}:{state.line}"

        except Exception:
            pass
        finally:
            # pyelftools caches every parsed DIE object in cu._dielist.
            # Without this, all CUs accumulate in memory simultaneously.
            # Clearing after each CU drops peak from O(all CUs) to O(one CU).
            if hasattr(cu, '_dielist'):
                cu._dielist = []
            if hasattr(cu, '_diemap'):
                cu._diemap = {}
            # Collect every 200 CUs so freed DIE objects are actually reclaimed.
            if cu_idx % 200 == 199:
                gc.collect()

    # Build sorted address list as a compact array of unsigned 64-bit ints.
    # array.array stores each address as 8 raw bytes vs ~28 bytes for a Python
    # int object, saving ~20 MB per 1M line-program entries.
    # bisect.bisect_right works on array.array without any changes to callers.
    raw_addrs = sorted(addr_to_loc)
    sorted_addrs = array.array('Q', raw_addrs)
    sorted_locs = [addr_to_loc[a] for a in raw_addrs]
    addr_to_loc.clear()
    return name_map, die_addr_map, sorted_addrs, sorted_locs


def _lookup_source(
    sym_name: str,
    addr: int,
    name_map: dict[str, str],
    die_addr_map: dict[int, str],
    sorted_addrs: list[int],
    sorted_locs: list[str],
) -> Optional[str]:
    """Return the source location for a symbol.

    Priority:
      1. Mangled/unmangled name match from DWARF DIEs  (most accurate)
      2. Exact address match from DWARF DIE location   (catches statics
         whose names are compiler-generated / unavailable)
      3. Line-program bisect fallback                  (code symbols only)
    """
    if sym_name in name_map:
        return name_map[sym_name]
    if addr in die_addr_map:
        return die_addr_map[addr]
    if not sorted_addrs:
        return None
    idx = bisect.bisect_right(sorted_addrs, addr) - 1
    if idx < 0:
        return None
    return sorted_locs[idx]


# Matches the exact output of __DATE__ (e.g. "May 21 2026" or "May  1 2026")
_DATE_RE = re.compile(r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ \d]\d \d{4}$')
# Matches the exact output of __TIME__ (e.g. "15:30:00")
_TIME_RE = re.compile(r'^\d{2}:\d{2}:\d{2}$')


def _analyze_rodata(elf: ELFFile) -> tuple[list[dict], list[dict]]:
    """Scan .rodata sections once, returning (build_stamps, duplicate_strings).

    Uses data.split(b"\\0") for fast C-level null splitting rather than a
    byte-by-byte Python loop. Both analyses share a single pass over each
    section so section data is only read from the ELF once.
    """
    MIN_DUP_LEN = 5
    MAX_DUP_LEN = 256

    seen: dict[str, list[tuple[str, int]]] = {}
    stamps: list[dict] = []

    for sec in elf.iter_sections():
        if not (sec.name == ".rodata" or sec.name.startswith(".rodata.")):
            continue
        try:
            data = sec.data()
            base_addr = sec["sh_addr"]
        except Exception:
            continue

        offset = 0
        for chunk in data.split(b"\x00"):
            addr = base_addr + offset
            length = len(chunk)
            offset += length + 1  # account for the null terminator

            if length == 0:
                continue
            if not all(0x20 <= x <= 0x7E for x in chunk):
                continue
            try:
                s = chunk.decode("ascii")
            except Exception:
                continue

            # Build-stamp detection: __DATE__ = 11 chars, __TIME__ = 8 chars
            if length in (8, 11):
                if _DATE_RE.match(s):
                    stamps.append({"string": s, "type": "date",
                                   "section": sec.name, "address": hex(addr)})
                elif _TIME_RE.match(s):
                    stamps.append({"string": s, "type": "time",
                                   "section": sec.name, "address": hex(addr)})

            # Duplicate-string accumulation
            if MIN_DUP_LEN <= length <= MAX_DUP_LEN:
                if s not in seen:
                    seen[s] = []
                seen[s].append((sec.name, addr))

    dup_results: list[dict] = []
    for s, locs in seen.items():
        if len(locs) < 2:
            continue
        wasted = (len(locs) - 1) * (len(s) + 1)
        dup_results.append({
            "string": s[:120],
            "count": len(locs),
            "length": len(s) + 1,
            "wasted_bytes": wasted,
        })
    dup_results.sort(key=lambda x: x["wasted_bytes"], reverse=True)

    return stamps, dup_results[:40]


def _estimate_ota_size(elf: ELFFile) -> dict:
    """Estimate OTA update size by zlib-compressing non-writable PT_LOAD segments.

    Non-writable (no W flag) PT_LOAD segments contain flash content (code +
    read-only data).  We compress each segment's file image with zlib level 6
    and sum the results.  This gives a realistic lower-bound for what a
    zlib/gzip-based OTA transport would send over the wire.

    Returns a dict with raw_bytes, compressed_bytes, and ratio, or {} if no
    suitable segments were found.
    """
    total_raw = 0
    total_compressed = 0
    for seg in elf.iter_segments():
        if seg["p_type"] != "PT_LOAD":
            continue
        if seg["p_filesz"] == 0:
            continue
        # Skip writable segments - those map to RAM, not flash
        if seg["p_flags"] & 0x2:  # PF_W
            continue
        try:
            data = seg.data()
            if not data:
                continue
            compressed = zlib.compress(data, 6)
            total_raw += len(data)
            total_compressed += len(compressed)
            del data, compressed  # free immediately; don't hold two copies at once
        except Exception:
            continue

    if total_raw == 0:
        return {}
    return {
        "raw_bytes": total_raw,
        "compressed_bytes": total_compressed,
        "ratio": round(total_compressed / total_raw, 3),
    }


# ---------------------------------------------------------------------------
# Call graph
# ---------------------------------------------------------------------------

# Capstone architecture/mode constants mapped from ELF e_machine values.
# Populated lazily on first use so importing this module never requires capstone.
_CS_ARCH_MAP: dict[str, tuple] = {
    # (CS_ARCH, CS_MODE)
    "EM_386":    ("CS_ARCH_X86",   "CS_MODE_32"),
    "EM_X86_64": ("CS_ARCH_X86",   "CS_MODE_64"),
    "EM_AARCH64":("CS_ARCH_ARM64", "CS_MODE_ARM"),
    "EM_MIPS":   ("CS_ARCH_MIPS",  "CS_MODE_MIPS32"),
    "EM_PPC":    ("CS_ARCH_PPC",   "CS_MODE_32"),
    "EM_RISCV":  ("CS_ARCH_RISCV", "CS_MODE_RISCV32"),
}

# Mnemonic prefixes that represent direct function calls for each architecture.
_CALL_MNEMONICS: dict[str, frozenset] = {
    "EM_386":    frozenset({"call"}),
    "EM_X86_64": frozenset({"call"}),
    "EM_ARM":    frozenset({"bl", "blx", "blxns"}),
    "EM_AARCH64":frozenset({"bl", "blr"}),
    "EM_MIPS":   frozenset({"jal", "jalr"}),
    "EM_PPC":    frozenset({"bl", "bla", "blrl"}),
    "EM_RISCV":  frozenset({"jal", "jalr"}),
    "EM_XTENSA": frozenset({"call0", "call4", "call8", "call12", "callx0",
                             "callx4", "callx8", "callx12"}),
}


def _dwarf5_call_graph(elf: ELFFile, addr_to_name: dict[int, str]) -> Optional[dict[str, set[str]]]:
    """Extract caller->callee edges from DWARF call-site DIEs.

    Handles both the DWARF 5 DW_TAG_call_site and GCC's DWARF 4 GNU extension
    DW_TAG_GNU_call_site. Returns a dict of {caller_name: {callee_name, ...}}
    if call-site info is present, or None if unavailable (no DWARF, or a
    toolchain that emits neither tag).
    """
    if not elf.has_dwarf_info():
        return None

    dwarf = elf.get_dwarf_info()
    calls: dict[str, set[str]] = defaultdict(set)
    found_any = False

    try:
        for cu in dwarf.iter_CUs():
            cu_base = cu.cu_offset

            # Single pass: collect die names and raw call edges simultaneously.
            # DW_AT_call_origin values are CU-relative refs (DW_FORM_ref*), so
            # the absolute offset is cu_base + ref. We defer resolution until
            # after the full CU walk so forward references within the CU work.
            die_names: dict[int, str] = {}
            raw_edges: list[tuple[str, int]] = []  # (caller_name, cu_relative_ref)
            current_caller: Optional[str] = None
            current_caller_depth: int = -1
            # pyelftools DIEs carry no depth attribute; track it ourselves.
            # iter_DIEs yields a null DIE to close each child list, so depth
            # rises after a DIE that has_children and falls on each null DIE.
            depth = 0

            for die in cu.iter_DIEs():
                if die.is_null():
                    depth -= 1
                    if current_caller is not None and depth <= current_caller_depth:
                        current_caller = None
                    continue

                tag = die.tag

                # Exit caller scope when depth returns to the caller level or above.
                if current_caller is not None and depth <= current_caller_depth:
                    current_caller = None

                if tag in ("DW_TAG_subprogram", "DW_TAG_subroutine_type"):
                    lnk = die.attributes.get("DW_AT_linkage_name")
                    name = _decode(lnk.value) if lnk else None
                    if not name:
                        nm = die.attributes.get("DW_AT_name")
                        name = _decode(nm.value) if nm else None
                    if name:
                        die_names[die.offset] = name
                    if tag == "DW_TAG_subprogram" and name:
                        current_caller = name
                        current_caller_depth = depth

                elif tag in ("DW_TAG_call_site", "DW_TAG_GNU_call_site") and current_caller is not None:
                    found_any = True
                    # DW_AT_call_origin: direct call; DW_AT_abstract_origin: inlined.
                    # GCC's DWARF 4 GNU extension (DW_TAG_GNU_call_site) carries the
                    # callee reference in DW_AT_abstract_origin instead.
                    orig = die.attributes.get("DW_AT_call_origin")
                    if orig is not None:
                        raw_edges.append((current_caller, int(orig.value)))
                    else:
                        abst = die.attributes.get("DW_AT_abstract_origin")
                        if abst is not None:
                            raw_edges.append((current_caller, int(abst.value)))

                if die.has_children:
                    depth += 1

            # Resolve CU-relative refs now that die_names is complete.
            for caller, raw_ref in raw_edges:
                callee = die_names.get(cu_base + raw_ref)
                if callee and callee != caller:
                    calls[caller].add(callee)
    except Exception as exc:
        print(f"[memprobe] DWARF 5 call graph extraction failed: {exc}", file=sys.stderr)
        return None

    return dict(calls) if found_any else None


def _capstone_call_graph(
    elf: ELFFile,
    arch_tag: str,
    func_symbols: list,
    addr_to_name: dict[int, str],
) -> dict[str, set[str]]:
    """Extract caller->callee edges by disassembling each function with capstone.

    Only resolves direct calls (immediate branch targets). Indirect calls
    through function pointers or vtables are not captured, which is expected
    for this kind of static analysis.

    Raises ImportError if capstone is not installed.
    Raises ValueError if the architecture is not supported.
    """
    import capstone  # noqa: PLC0415

    arch_human = _MACHINE_NAMES.get(arch_tag, arch_tag)
    call_mnemonics = _CALL_MNEMONICS.get(arch_tag, frozenset())
    if not call_mnemonics:
        raise ValueError(f"call graph disassembly is not implemented for {arch_human}")

    # Build a section data cache: section index -> (base_addr, bytes)
    sec_cache: dict[int, tuple[int, bytes]] = {}
    for i, sec in enumerate(elf.iter_sections()):
        if sec["sh_type"] in ("SHT_PROGBITS",) and sec["sh_flags"] & _SHF_EXECINSTR:
            try:
                sec_cache[i] = (sec["sh_addr"], sec.data())
            except Exception:
                pass

    # Also build addr->section data for fast offset lookup.
    # Sorted by base address for binary search.
    sec_ranges: list[tuple[int, int, bytes]] = sorted(
        (base, base + len(data), data)
        for base, data in sec_cache.values()
    )

    def _get_func_bytes(addr: int, size: int) -> Optional[bytes]:
        """Extract raw bytes for a function from the loaded section data."""
        real_addr = addr & ~1  # strip ARM THUMB bit
        for base, end, data in sec_ranges:
            if base <= real_addr < end:
                off = real_addr - base
                return data[off: off + size]
        return None

    # Determine capstone arch/mode.
    if arch_tag == "EM_ARM":
        cs_arch = capstone.CS_ARCH_ARM
        # We'll set mode per-function based on the THUMB bit.
        cs_thumb = capstone.Cs(cs_arch, capstone.CS_MODE_THUMB)
        cs_arm   = capstone.Cs(cs_arch, capstone.CS_MODE_ARM)
        cs_thumb.detail = True
        cs_arm.detail   = True
        cs_instances = None  # handled specially below
    elif arch_tag == "EM_XTENSA":
        # Xtensa disassembly support landed in capstone 6; older releases lack it.
        if not hasattr(capstone, "CS_ARCH_XTENSA"):
            raise ValueError(
                f"Xtensa call graph disassembly requires capstone 6 or newer "
                f"(installed capstone {capstone.__version__} has no Xtensa support)"
            )
        cs_main = capstone.Cs(capstone.CS_ARCH_XTENSA, capstone.CS_MODE_LITTLE_ENDIAN)
        cs_main.detail = True
        cs_instances = cs_main
    else:
        arch_str, mode_str = _CS_ARCH_MAP.get(arch_tag, (None, None))
        if arch_str is None:
            raise ValueError(f"capstone has no disassembler for {arch_human}")
        cs_main = capstone.Cs(getattr(capstone, arch_str), getattr(capstone, mode_str))
        cs_main.detail = True
        cs_instances = cs_main

    calls: dict[str, set[str]] = defaultdict(set)
    # Cap per-function size to avoid spending too long on large functions.
    MAX_FUNC_BYTES = 64 * 1024

    for sym in func_symbols:
        if sym.size <= 0 or sym.size > MAX_FUNC_BYTES:
            continue
        func_bytes = _get_func_bytes(sym.address, sym.size)
        if not func_bytes:
            continue

        real_addr = sym.address & ~1

        if arch_tag == "EM_ARM":
            is_thumb = bool(sym.address & 1)
            cs = cs_thumb if is_thumb else cs_arm
        else:
            cs = cs_instances  # type: ignore[assignment]

        try:
            for insn in cs.disasm(func_bytes, real_addr):
                if insn.mnemonic.lower() not in call_mnemonics:
                    continue
                # Extract the immediate branch target from the operand string.
                # Capstone encodes it as a hex literal in the op_str.
                op = insn.op_str.strip()
                target_addr: Optional[int] = None
                try:
                    if op.startswith("#"):
                        op = op[1:]
                    target_addr = int(op, 16)
                except ValueError:
                    # Indirect call (register operand) — skip.
                    continue

                if target_addr is None:
                    continue
                callee_name = addr_to_name.get(target_addr & ~1)
                if callee_name and callee_name != sym.name:
                    calls[sym.name].add(callee_name)
        except Exception:
            # Disassembly failure on one function should not abort the whole graph.
            continue

    return dict(calls)


def _build_call_graph(
    elf: ELFFile,
    arch_tag: str,
    func_symbols: list,
) -> tuple[Optional[dict[str, dict[str, list[str]]]], str]:
    """Build a call graph for all functions in the ELF.

    Returns a (graph, status) tuple. graph is a dict
    {func_name: {"calls": [...], "called_by": [...]}} containing every function
    with at least one edge, or None when no call information could be extracted.
    status is always a plain-English explanation of the outcome, suitable for
    showing the user verbatim, so an absent graph is never silent.

    Strategy (in order):
      1. DWARF call sites (DWARF 5 DW_TAG_call_site or GCC's DWARF 4
         DW_TAG_GNU_call_site) — zero extra dependencies.
      2. capstone disassembly fallback — covers other toolchains, requires the
         capstone package (pip install memprobe[callgraph]).
    """
    arch_human = _MACHINE_NAMES.get(arch_tag, arch_tag)

    # Build addr -> symbol name map. For ARM strip the THUMB bit so lookups
    # work regardless of whether the caller uses the raw or masked address.
    addr_to_name: dict[int, str] = {}
    for sym in func_symbols:
        real_addr = sym.address & ~1 if arch_tag == "EM_ARM" else sym.address
        if sym.name and sym.size > 0:
            addr_to_name[real_addr] = sym.name

    calls_forward: Optional[dict[str, set[str]]] = None
    method_used = "none"

    # --- Strategy 1: DWARF call sites ---
    dwarf_result = _dwarf5_call_graph(elf, addr_to_name)
    if dwarf_result is not None:
        calls_forward = dwarf_result
        method_used = "dwarf"

    # --- Strategy 2: capstone disassembly ---
    if calls_forward is None:
        try:
            calls_forward = _capstone_call_graph(elf, arch_tag, func_symbols, addr_to_name)
            method_used = "capstone"
        except ImportError:
            msg = ("Call graph unavailable: this binary has no DWARF call-site debug "
                   "info, and the capstone disassembler is not installed. Install it "
                   "with: pip install memprobe[callgraph]")
            print(f"[memprobe] {msg}", file=sys.stderr)
            return None, msg
        except ValueError as exc:
            msg = (f"Call graph not supported: this binary has no DWARF call-site debug "
                   f"info, and {exc}.")
            print(f"[memprobe] {msg}", file=sys.stderr)
            return None, msg
        except Exception as exc:
            msg = f"Call graph unavailable: disassembly failed ({exc})."
            print(f"[memprobe] {msg}", file=sys.stderr)
            return None, msg

    if not calls_forward:
        if method_used == "capstone":
            msg = (f"Call graph empty: disassembled the {arch_human} code but found no "
                   f"direct calls, and this binary has no DWARF call-site debug info. "
                   f"Indirect calls (function pointers, virtual dispatch) are not tracked.")
        else:
            msg = ("Call graph empty: DWARF call-site info is present but no caller/callee "
                   "edges could be resolved.")
        return None, msg

    # Build reverse edges.
    called_by: dict[str, set[str]] = defaultdict(set)
    for caller, callees in calls_forward.items():
        for callee in callees:
            called_by[callee].add(caller)

    # Merge into final structure; include every function that has at least one edge.
    all_funcs = set(calls_forward.keys()) | set(called_by.keys())
    result: dict[str, dict[str, list[str]]] = {}
    for func in sorted(all_funcs):
        result[func] = {
            "calls":     sorted(calls_forward.get(func, set())),
            "called_by": sorted(called_by.get(func, set())),
        }

    source = ("DWARF call-site debug info" if method_used == "dwarf"
              else "capstone disassembly of direct calls")
    status = f"Call graph extracted from {source}: {len(result)} functions."
    logger.debug("[memprobe] call graph: %d functions, method=%s", len(result), method_used)
    return result, status


def parse(elf_file: Path, progress_cb=None) -> MemoryMap:
    """Parse an ELF binary into a MemoryMap.

    progress_cb, if provided, is called with (fraction: float, stage: str)
    at key milestones throughout the parse. fraction is 0.0-1.0 relative to
    the full parse operation (not just the DWARF phase).
    """
    def _emit(frac: float, stage: str):
        if progress_cb:
            progress_cb(frac, stage)

    with open(elf_file, "rb") as f:
        elf = ELFFile(f)

        arch_tag = elf.header["e_machine"]
        arch_human = _MACHINE_NAMES.get(arch_tag, arch_tag)
        bitness = elf.elfclass  # 32 or 64
        e_flags = elf.header.get("e_flags", 0)

        _emit(0.05, "elf_header")

        # Build DWARF lookup maps (name, die-address, line-program).
        # The DWARF walk is the bulk of parse time (0.10-0.85 of total).
        def _dwarf_chunk_done(chunk_frac: float):
            # chunk_frac: 0-1 as each parallel worker finishes.
            _emit(0.10 + chunk_frac * 0.75, "dwarf_chunks")

        dwarf_name_map, dwarf_die_addr_map, dwarf_addrs, dwarf_locs = _build_dwarf_maps(
            elf, elf_file, progress_cb=_dwarf_chunk_done
        )
        _emit(0.87, "dwarf_done")

        # Collect symbol table
        symbols_by_section_idx: dict[int, list[Symbol]] = {}
        symtab = elf.get_section_by_name(".symtab")
        if symtab and isinstance(symtab, SymbolTableSection):
            for sym in symtab.iter_symbols():
                if sym["st_size"] > 0 and sym["st_shndx"] not in ("SHN_UNDEF", "SHN_ABS"):
                    sec_idx = sym["st_shndx"]
                    if isinstance(sec_idx, int):
                        sym_addr = sym["st_value"]
                        # ARM Thumb functions have bit 0 set in the symbol value;
                        # strip it for address lookups.
                        lookup_addr = sym_addr & ~1 if arch_tag == "EM_ARM" else sym_addr
                        symbols_by_section_idx.setdefault(sec_idx, []).append(
                            Symbol(
                                name=sym.name,
                                size=sym["st_size"],
                                address=sym_addr,
                                section="",
                                object_file="(elf)",
                                source_location=_lookup_source(sym.name, lookup_addr, dwarf_name_map, dwarf_die_addr_map, dwarf_addrs, dwarf_locs),
                            )
                        )

        # Free DWARF maps immediately after the symbol scan - they can be large
        # and are no longer needed before the .rodata and OTA passes below.
        del dwarf_name_map, dwarf_die_addr_map, dwarf_addrs, dwarf_locs
        gc.collect()

        # PT_LOAD segments carry the load (physical) addresses. A section's LMA
        # is its VMA mapped through the segment that contains it:
        #   lma = seg.p_paddr + (sec.sh_addr - seg.p_vaddr)
        # On most desktop ELFs p_paddr == p_vaddr, so LMA == VMA. On embedded
        # images (e.g. .data initialized from flash) p_paddr is the flash copy.
        load_segments = [
            (seg["p_vaddr"], seg["p_paddr"], seg["p_memsz"])
            for seg in elf.iter_segments()
            if seg["p_type"] == "PT_LOAD" and seg["p_memsz"] > 0
        ]

        # Collect sections; also track executable section names for the call
        # graph filter so we don't need a separate iter_sections() pass later.
        sections: list[Section] = []
        section_names: list[str] = []
        exec_section_names: set[str] = set()
        for i, sec in enumerate(elf.iter_sections()):
            if sec["sh_flags"] & _SHF_EXECINSTR:
                exec_section_names.add(sec.name)
            if sec["sh_size"] == 0:
                continue
            if any(sec.name.startswith(p) for p in _SKIP_SECTION_PREFIXES):
                continue
            if sec["sh_type"] == "SHT_NULL":
                continue

            sec_type = _classify_section(sec.name)
            syms = symbols_by_section_idx.get(i, [])
            for sym in syms:
                sym.section = sec.name

            sections.append(Section(
                name=sec.name,
                size=sec["sh_size"],
                address=sec["sh_addr"],
                section_type=sec_type,
                symbols=syms,
                vma=sec["sh_addr"],
                lma=_compute_lma(sec["sh_addr"], load_segments),
                occupies_file=sec["sh_type"] != "SHT_NOBITS",
                alloc=bool(sec["sh_flags"] & _SHF_ALLOC),
            ))
            section_names.append(sec.name)

        # Collect PT_LOAD program headers (memory segments)
        segments = []
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD" and seg["p_memsz"] > 0:
                flags_raw = seg["p_flags"]
                perms = (
                    ("r" if flags_raw & 4 else "-") +
                    ("w" if flags_raw & 2 else "-") +
                    ("x" if flags_raw & 1 else "-")
                )
                segments.append({
                    "vaddr": hex(seg["p_vaddr"]),
                    "paddr": hex(seg["p_paddr"]),
                    "filesz": seg["p_filesz"],
                    "memsz": seg["p_memsz"],
                    "flags": perms,
                })

        # Decode ARM flags
        flag_features: list[str] = []
        if arch_tag == "EM_ARM":
            flag_features = _parse_arm_flags(e_flags)

        chip_family = _infer_chip_family(arch_tag, section_names)

        # Build ID from .note.gnu.build-id
        build_id_hex: Optional[str] = None
        build_id_sec = elf.get_section_by_name(".note.gnu.build-id")
        if build_id_sec:
            try:
                raw = build_id_sec.data()
                # Note format: namesz(4) + descsz(4) + type(4) + name + desc
                if len(raw) >= 16:
                    namesz = int.from_bytes(raw[0:4], "little")
                    descsz = int.from_bytes(raw[4:8], "little")
                    desc_start = 12 + namesz
                    desc_start = (desc_start + 3) & ~3  # 4-byte align
                    build_id_hex = raw[desc_start:desc_start + descsz].hex()
            except Exception:
                pass

        # Compiler string from .comment section
        compiler_str: Optional[str] = None
        comment_sec = elf.get_section_by_name(".comment")
        if comment_sec:
            try:
                raw = comment_sec.data()
                # Null-separated strings; take the first non-empty one
                parts = raw.split(b"\x00")
                for p in parts:
                    s = p.decode("utf-8", errors="replace").strip()
                    if s:
                        compiler_str = s
                        break
            except Exception:
                pass

        # Endianness and OS/ABI
        endian = "little-endian" if elf.little_endian else "big-endian"
        osabi = elf.header["e_ident"]["EI_OSABI"]
        osabi_names = {
            "ELFOSABI_NONE": "System V",
            "ELFOSABI_LINUX": "Linux",
            "ELFOSABI_ARM": "ARM",
            "ELFOSABI_STANDALONE": "Embedded",
        }
        osabi_human = osabi_names.get(str(osabi), str(osabi))

        # ELF type
        elf_type_names = {
            "ET_EXEC": "Executable",
            "ET_DYN": "Shared object",
            "ET_REL": "Relocatable",
            "ET_CORE": "Core dump",
        }
        elf_type = elf_type_names.get(elf.header["e_type"], elf.header["e_type"])

        _emit(0.88, "call_graph")
        func_symbols_for_cg = [
            sym
            for sym in (s for sec in sections for s in sec.symbols)
            if sym.size > 0 and sym.section in exec_section_names
        ]
        call_graph = None
        call_graph_status = "Call graph unavailable."
        try:
            call_graph, call_graph_status = _build_call_graph(elf, arch_tag, func_symbols_for_cg)
        except Exception as exc:
            call_graph_status = f"Call graph unavailable: {exc}"
            print(f"[memprobe] call graph failed: {exc}\n{traceback.format_exc()}", file=sys.stderr)
        _emit(0.92, "call_graph_done")

        build_stamps, duplicate_strings = _analyze_rodata(elf)
        ota_estimate = _estimate_ota_size(elf)

        binary_info = {
            "arch": arch_human,
            "arch_tag": arch_tag,
            "bitness": bitness,
            "chip_family": chip_family,
            "e_flags": hex(e_flags),
            "flag_features": flag_features,
            "segments": segments,
            "entry_point": hex(elf.header["e_entry"]),
            "build_id": build_id_hex,
            "compiler": compiler_str,
            "endian": endian,
            "osabi": osabi_human,
            "elf_type": elf_type,
            "section_count": len(section_names),
            "duplicate_strings": duplicate_strings,
            "build_stamps": build_stamps,
            "ota_estimate": ota_estimate,
            "call_graph_status": call_graph_status,
        }

        return MemoryMap(
            source_file=str(elf_file),
            toolchain="gcc",
            target=arch_human,
            sections=sections,
            binary_info=binary_info,
            call_graph=call_graph,
        )
