"""GCC linker map file parser."""

import re
from pathlib import Path
from typing import Optional

from ..models import MemoryMap, MemoryRegion, Section, Symbol, SectionType

# Matches memory region lines like:
#   FLASH            0x0000000008000000 0x0000000000080000 xr
_RE_MEMORY_REGION = re.compile(
    r'^(\w+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+\w+'
)

# Archive reference: /path/libgcc.a(memcpy.o)
_RE_ARCHIVE = re.compile(r'^(.*\.a)\((.+\.o)\)$')


def parse(map_file: Path) -> MemoryMap:
    """Parse a GCC linker map file into a MemoryMap."""
    text = map_file.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    regions = _parse_memory_config(lines)
    sections = _parse_sections(lines)

    mmap = MemoryMap(
        source_file=str(map_file),
        toolchain="gcc",
        target=None,
        sections=sections,
        regions=regions,
    )

    # Compute used bytes per region from sections
    for region in mmap.regions:
        end = region.origin + region.length
        for sec in mmap.sections:
            addr = sec.vma if sec.vma else sec.address
            if region.origin <= addr < end:
                region.used += sec.size

    return mmap


def _parse_memory_config(lines: list[str]) -> list[MemoryRegion]:
    """Extract MemoryRegion entries from the Memory Configuration block."""
    regions: list[MemoryRegion] = []
    in_config = False

    for line in lines:
        stripped = line.strip()
        if stripped == "Memory Configuration":
            in_config = True
            continue
        if in_config:
            if stripped.startswith("Linker script"):
                break
            if not stripped or stripped.startswith("Name") or stripped.startswith("-"):
                continue
            m = _RE_MEMORY_REGION.match(stripped)
            if m:
                name = m.group(1)
                if name == "*default*":
                    continue
                regions.append(MemoryRegion(
                    name=name,
                    origin=int(m.group(2), 16),
                    length=int(m.group(3), 16),
                ))

    return regions


def _parse_sections(lines: list[str]) -> list[Section]:
    """Extract Section and Symbol objects from the linker map body.

    GCC map files have two subsection formats:

    Inline (all on one line):
        .text.memcpy   0x0000000008001694   0x24   libgcc.a(memcpy.o)

    Multi-line (name alone, then continuation):
        .text.HAL_UART_Transmit
                        0x0000000008000574   0x4d8   build/hal_uart.o
                        0x0000000008000574           HAL_UART_Transmit
    """
    sections: list[Section] = []
    current_section: Optional[Section] = None
    pending_sub_name: Optional[str] = None   # subsection name waiting for addr/size/obj
    pending_sub: Optional[tuple] = None       # (name, addr, size, obj_file, library)
    pending_sub_got_symbol: bool = False      # whether a symbol address line was emitted
    in_map = False

    for line in lines:
        if "Linker script and memory map" in line:
            in_map = True
            continue
        if not in_map:
            continue

        # Skip filler / blank / comments / wildcard input directives
        if "*fill*" in line:
            continue
        if not line.strip():
            continue
        if line.strip().startswith("#"):
            continue
        if re.match(r"^\s+\*\(", line):
            continue

        # -- Top-level section (begins at column 0) ---------------------------
        m_top = re.match(
            r"^(\.\S+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)"
            r"(?:\s+load address\s+(0x[0-9a-fA-F]+))?",
            line,
        )
        if m_top and not line[0].isspace():
            sec_name = m_top.group(1)
            vma = int(m_top.group(2), 16)
            size = int(m_top.group(3), 16)
            lma_raw = m_top.group(4)
            lma = int(lma_raw, 16) if lma_raw else vma
            current_section = Section(
                name=sec_name,
                size=size,
                address=vma,
                section_type=_classify_section(sec_name),
                vma=vma,
                lma=lma,
            )
            sections.append(current_section)
            pending_sub_name = None
            pending_sub = None
            continue

        if current_section is None:
            continue

        # -- Subsection name-only line:  "   .text.FuncName"  -----------------
        m_name_only = re.match(r"^\s+(\.\S+)\s*$", line)
        if m_name_only:
            _flush_pending(current_section, pending_sub, pending_sub_got_symbol)
            pending_sub_name = m_name_only.group(1)
            pending_sub = None
            pending_sub_got_symbol = False
            continue

        # -- Inline subsection:  "   .text.func  0xADDR  0xSIZE  file.o"  ----
        m_inline = re.match(
            r"^\s+(\.\S+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(\S+)",
            line,
        )
        if m_inline:
            _flush_pending(current_section, pending_sub, pending_sub_got_symbol)
            sub_name = m_inline.group(1)
            sub_addr = int(m_inline.group(2), 16)
            sub_size = int(m_inline.group(3), 16)
            obj_raw = m_inline.group(4)
            pending_sub_name = None
            if sub_size > 0:
                obj_file, library = _parse_object(obj_raw)
                pending_sub = (sub_name, sub_addr, sub_size, obj_file, library)
            else:
                pending_sub = None
            pending_sub_got_symbol = False
            continue

        # -- Continuation line:  "  0xADDR  0xSIZE  file.o"  (multi-line sub) -
        m_cont = re.match(
            r"^\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(\S+)",
            line,
        )
        if m_cont:
            # Only treat as continuation if the second token starts with 0x
            # (distinguishes from a symbol address line where token 2 is a name)
            tok2 = line.split()[1] if len(line.split()) > 1 else ""
            if tok2.startswith("0x"):
                sub_addr = int(m_cont.group(1), 16)
                sub_size = int(m_cont.group(2), 16)
                obj_raw = m_cont.group(3)
                name = pending_sub_name or "(linker)"
                pending_sub_name = None
                if sub_size > 0:
                    obj_file, library = _parse_object(obj_raw)
                    pending_sub = (name, sub_addr, sub_size, obj_file, library)
                    pending_sub_got_symbol = False
                else:
                    pending_sub = None
                    pending_sub_got_symbol = False
                continue

        # -- Symbol address line:  "  0xADDR  symbol_name"  -------------------
        m_sym = re.match(
            r"^\s+(0x[0-9a-fA-F]+)\s+([A-Za-z_][A-Za-z0-9_$.@]*)\s*$",
            line,
        )
        if m_sym and pending_sub is not None:
            sym_name = m_sym.group(2)
            _, sub_addr, sub_size, obj_file, library = pending_sub
            current_section.symbols.append(Symbol(
                name=sym_name,
                size=sub_size,
                address=sub_addr,
                section=current_section.name,
                object_file=obj_file,
                library=library,
            ))
            pending_sub_got_symbol = True
            # Keep pending_sub - next sub line will overwrite it

    # Flush the last pending subsection if it never got a symbol line
    if current_section is not None:
        _flush_pending(current_section, pending_sub, pending_sub_got_symbol)

    return sections


def _flush_pending(
    section: Section,
    pending_sub: Optional[tuple],
    got_symbol: bool,
) -> None:
    """If pending_sub has no symbol yet, synthesize one from the subsection name."""
    if pending_sub is None or got_symbol:
        return
    sub_name, sub_addr, sub_size, obj_file, library = pending_sub
    # Derive a clean symbol name: strip leading section prefix (e.g. .text.)
    parts = sub_name.lstrip(".").split(".", 1)
    sym_name = parts[-1] if len(parts) > 1 else sub_name
    section.symbols.append(Symbol(
        name=sym_name,
        size=sub_size,
        address=sub_addr,
        section=section.name,
        object_file=obj_file,
        library=library,
    ))


def _parse_object(raw: str) -> tuple[str, Optional[str]]:
    """Split 'libfoo.a(bar.o)' into (bar.o, libfoo.a), or return (raw, None)."""
    m = _RE_ARCHIVE.match(raw)
    if m:
        lib_path = m.group(1)
        obj_file = m.group(2)
        lib_name = Path(lib_path).name
        return obj_file, lib_name
    return raw, None


def _classify_section(name: str) -> SectionType:
    """Classify a section name into a SectionType.

    Handles both standard GCC names (.text, .bss, …) and vendor-prefixed
    names used by ESP-IDF, Zephyr, etc. (.iram0.text, .flash.rodata, …).
    """
    n = name.lower()

    # Check for "text" component anywhere in the name
    if "text" in n:
        return SectionType.TEXT
    # rodata before data so .flash.rodata doesn't match DATA
    if "rodata" in n:
        return SectionType.RODATA
    if "data" in n and "rodata" not in n:
        # .dram0.data, .data, .data.rel, etc.
        # But not pure bss aliases
        if "bss" not in n:
            return SectionType.DATA
    if "bss" in n:
        return SectionType.BSS
    if "heap" in n:
        return SectionType.HEAP
    if "stack" in n:
        return SectionType.STACK
    return SectionType.OTHER
