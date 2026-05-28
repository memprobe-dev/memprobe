"""ELF binary parser using pyelftools."""

import array
import bisect
import gc
import re
import zlib
from pathlib import Path
from typing import Optional

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from ..models import MemoryMap, Section, Symbol, SectionType
from .map_gcc import _classify_section

_SKIP_SECTION_PREFIXES = (".debug", ".comment", ".note", ".ARM.attr")

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
    names_joined = " ".join(section_names).lower()
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
    import struct
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
    if isinstance(val, list) and len(val) > addr_size and val[0] == 0x03:
        raw = bytes(val[1: 1 + addr_size])
        fmt = "<I" if addr_size == 4 else "<Q"
        return struct.unpack(fmt, raw)[0]
    if isinstance(val, (bytes, bytearray)) and len(val) > addr_size and val[0] == 0x03:
        raw = bytes(val[1: 1 + addr_size])
        fmt = "<I" if addr_size == 4 else "<Q"
        return struct.unpack(fmt, raw)[0]
    return None


def _build_dwarf_maps(elf: ELFFile) -> tuple[dict[str, str], dict[int, str], list[int], list[str]]:
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

            def _resolve_file(file_idx: int) -> str:
                if file_idx in _file_cache:
                    return _file_cache[file_idx]
                if file_idx == 0 or file_idx > len(file_entries):
                    _file_cache[file_idx] = ""
                    return ""
                entry = file_entries[file_idx - 1]
                name = _decode(entry.name)
                dir_idx = entry.dir_index
                if dir_idx == 0:
                    base = comp_dir_str
                elif dir_idx <= len(inc_dirs):
                    base = _decode(inc_dirs[dir_idx - 1])
                else:
                    base = comp_dir_str
                full = f"{base}/{name}" if base else name
                if comp_dir_str and full.startswith(comp_dir_str):
                    full = full[len(comp_dir_str):].lstrip("/")
                _file_cache[file_idx] = full
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


def _find_build_stamps(elf: ELFFile) -> list[dict]:
    """Scan .rodata sections for __DATE__ and __TIME__ string literals.

    These are injected by the C preprocessor when source files use the
    __DATE__ or __TIME__ macros.  Their presence makes every build produce
    a different binary even when the source is unchanged, causing spurious
    diffs in history tracking.

    Returns a list of {string, type, section, address} dicts.
    """
    stamps: list[dict] = []
    for sec in elf.iter_sections():
        if not (sec.name == ".rodata" or sec.name.startswith(".rodata.")):
            continue
        try:
            data = sec.data()
            base_addr = sec["sh_addr"]
        except Exception:
            continue

        start = 0
        for i in range(len(data)):
            if data[i] == 0:
                chunk = data[start:i]
                addr = base_addr + start
                start = i + 1
                length = len(chunk)
                # __DATE__ is exactly 11 chars, __TIME__ is exactly 8 chars
                if length not in (8, 11):
                    continue
                if not all(0x20 <= x <= 0x7E for x in chunk):
                    continue
                try:
                    s = chunk.decode("ascii")
                except Exception:
                    continue
                if _DATE_RE.match(s):
                    stamps.append({"string": s, "type": "date",
                                   "section": sec.name, "address": hex(addr)})
                elif _TIME_RE.match(s):
                    stamps.append({"string": s, "type": "time",
                                   "section": sec.name, "address": hex(addr)})
    return stamps


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


def _find_duplicate_strings(elf: ELFFile) -> list[dict]:
    """Scan .rodata sections for duplicate null-terminated ASCII string literals.

    Only reports strings that appear at two or more distinct addresses, meaning
    the linker did NOT merge them (e.g. -fno-merge-constants or cross-section
    strings). Each entry reports the string, how many copies exist, and how many
    bytes are wasted by the redundant copies.

    Filters:
    - Minimum 5 printable ASCII characters (reduces noise from short tokens)
    - Maximum 256 characters (avoids treating binary blobs as strings)
    - All bytes must be in the printable ASCII range 0x20-0x7E
    """
    MIN_LEN = 5
    MAX_LEN = 256

    # string_value -> list of (section_name, address)
    seen: dict[str, list[tuple[str, int]]] = {}

    for sec in elf.iter_sections():
        if not (sec.name == ".rodata" or sec.name.startswith(".rodata.")):
            continue
        try:
            data = sec.data()
            base_addr = sec["sh_addr"]
        except Exception:
            continue

        start = 0
        for i in range(len(data)):
            b = data[i]
            if b == 0:
                chunk = data[start:i]
                string_addr = base_addr + start
                start = i + 1
                length = len(chunk)
                if length < MIN_LEN or length > MAX_LEN:
                    continue
                # All bytes must be printable ASCII
                if not all(0x20 <= x <= 0x7E for x in chunk):
                    continue
                try:
                    s = chunk.decode("ascii")
                except Exception:
                    continue
                if s not in seen:
                    seen[s] = []
                seen[s].append((sec.name, string_addr))

    results = []
    for s, locs in seen.items():
        if len(locs) < 2:
            continue
        wasted = (len(locs) - 1) * (len(s) + 1)
        results.append({
            "string": s[:120],
            "count": len(locs),
            "length": len(s) + 1,  # include null terminator
            "wasted_bytes": wasted,
        })

    results.sort(key=lambda x: x["wasted_bytes"], reverse=True)
    return results[:40]


def parse(elf_file: Path) -> MemoryMap:
    """Parse an ELF binary into a MemoryMap."""
    with open(elf_file, "rb") as f:
        elf = ELFFile(f)

        arch_tag = elf.header["e_machine"]
        arch_human = _MACHINE_NAMES.get(arch_tag, arch_tag)
        bitness = elf.elfclass  # 32 or 64
        e_flags = elf.header.get("e_flags", 0)

        # Build DWARF lookup maps (name, die-address, line-program)
        dwarf_name_map, dwarf_die_addr_map, dwarf_addrs, dwarf_locs = _build_dwarf_maps(elf)

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

        # Collect sections
        sections: list[Section] = []
        section_names: list[str] = []
        for i, sec in enumerate(elf.iter_sections()):
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
                lma=sec["sh_addr"],
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

        duplicate_strings = _find_duplicate_strings(elf)
        build_stamps = _find_build_stamps(elf)
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
        }

        return MemoryMap(
            source_file=str(elf_file),
            toolchain="gcc",
            target=arch_human,
            sections=sections,
            binary_info=binary_info,
        )
