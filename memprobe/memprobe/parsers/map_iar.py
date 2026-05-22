"""IAR ELF Linker map file parser.

Supports IAR EWARM and other IAR EW toolchains (v7–v9+).
Two main sections are consumed:
  - PLACEMENT SUMMARY  → section addresses / sizes / object files
  - ENTRY LIST         → symbol-level sizes, types, and object files
Memory regions are inferred from the placement group address ranges.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ..models import MemoryMap, MemoryRegion, Section, Symbol, SectionType
from .map_gcc import _classify_section


# -- Address helpers ------------------------------------------------------------

def _h(s: str) -> int:
    """Parse an IAR hex address: '0x0800\'1234' or '0x08001234' → int."""
    return int(s.replace("'", "").replace("`", ""), 16)


# -- Regex patterns -------------------------------------------------------------

# Placement group definition lines:
#   "P1":  place in [from 0x800'0000 to 0x807'ffff] { ro };
#   "A0":  place at address 0x800'0000 { ro section .intvec };
_RE_GROUP_RANGE = re.compile(
    r'^"(\w+)"\s*:.*?from\s+(0x[\da-fA-F\'`]+)\s+to\s+(0x[\da-fA-F\'`]+)',
    re.IGNORECASE,
)
_RE_GROUP_AT = re.compile(
    r'^"(\w+)"\s*:.*?at\s+address\s+(0x[\da-fA-F\'`]+)',
    re.IGNORECASE,
)

# Group header in the placement table body:
#   "P1":                      0x0800'01ec
_RE_BODY_GROUP = re.compile(r'^"(\w+)"\s*:\s*(0x[\da-fA-F\'`]+)')

# Section line in PLACEMENT SUMMARY body:
#   .text  ro code  0x0800'01ec  0x48  main.o [2]
#   Initializer bytes  ro data  0x0800'05a4  0x28  <init block>
_RE_SECTION = re.compile(
    r'^\s{2}(\S.*?)\s{2,}'           # section name (at least 2 leading spaces)
    r'(ro code|ro data|rw code|rw data|const|inited|zero|zi|uninit|noinit|readonly)\s+'
    r'(0x[\da-fA-F\'`]+)\s+'
    r'(0x[\da-fA-F\'`]+)\s*'
    r'(.*)?$',
    re.IGNORECASE,
)

# Symbol line under a section (extra leading whitespace, no kind field):
#   "               0x0800'01ed           main"
_RE_SYMBOL_ADDR = re.compile(
    r'^\s{15,}(0x[\da-fA-F\'`]+)\s{2,}(\S+)',
)

# ENTRY LIST line:
#   main                   0x0800'01ed    0x48  Code  main.o [2]
#   __vector_table         0x0800'0000   0x1ec  Data  startup.o [1]
#   CSTACK$$Base           0x2000'0828         --    <Block>
_RE_ENTRY = re.compile(
    r'^(\S+)\s+'
    r'(0x[\da-fA-F\'`]+)\s+'
    r'(?:(0x[\da-fA-F\'`]+)\s+)?'    # size is optional (some symbols have no size)
    r'(Code|Data|--|\w+)\s+'
    r'(.+)$',
    re.IGNORECASE,
)

# HEAP / STACK size lines  (for region computation)
_RE_STACK_SIZE = re.compile(r'^CSTACK\s+size\s*=\s*(0x[\da-fA-F]+|\d+)', re.IGNORECASE)
_RE_HEAP_SIZE  = re.compile(r'^HEAP\s+size\s*=\s*(0x[\da-fA-F]+|\d+)',   re.IGNORECASE)


# -- Section-type mapping -------------------------------------------------------

_KIND_TO_TYPE: dict[str, SectionType] = {
    "ro code":  SectionType.TEXT,
    "rw code":  SectionType.TEXT,
    "ro data":  SectionType.RODATA,
    "const":    SectionType.RODATA,
    "readonly": SectionType.RODATA,
    "inited":   SectionType.DATA,
    "rw data":  SectionType.DATA,
    "zero":     SectionType.BSS,
    "zi":       SectionType.BSS,
    "uninit":   SectionType.BSS,
    "noinit":   SectionType.BSS,
}


def _section_type(kind: str, name: str) -> SectionType:
    """Classify a section by its IAR kind string, falling back to name heuristics."""
    by_kind = _KIND_TO_TYPE.get(kind.lower())
    if by_kind:
        return by_kind
    return _classify_section(name)


def _clean_object(raw: str) -> tuple[str, Optional[str]]:
    """Return (object_file, library) from an IAR object reference.

    IAR uses several formats:
      main.o [2]
      cmain.o [clib]
      C:\\path\\obj\\main.o [3]
      <Block>
      <init block>
    """
    raw = raw.strip()
    # strip trailing [n] or [libname]
    raw = re.sub(r'\s*\[\w+\]$', '', raw).strip()
    if not raw or raw.startswith('<'):
        return ('(iar)', None)

    # Normalise path separators
    obj = raw.replace('\\', '/').strip()
    # Trim absolute paths down to a basename if they look like full paths
    if ':/' in obj or obj.startswith('/'):
        obj = obj.split('/')[-1]

    # Detect library name: IAR sometimes prints "clib" or archive basename
    library: Optional[str] = None
    return (obj, library)


# -- Parser ---------------------------------------------------------------------

def parse(map_file: Path) -> MemoryMap:
    """Parse an IAR ELF Linker map file into a MemoryMap."""
    text = map_file.read_text(encoding='utf-8', errors='replace')
    lines = text.splitlines()

    # -- Pass 1: collect placement group address ranges -------------------------
    group_ranges: dict[str, tuple[int, int]] = {}   # name → (start, end)
    for line in lines:
        m = _RE_GROUP_RANGE.match(line)
        if m:
            group_ranges[m.group(1)] = (_h(m.group(2)), _h(m.group(3)))
            continue
        m = _RE_GROUP_AT.match(line)
        if m:
            addr = _h(m.group(2))
            # Point placement: treat as zero-length, will be sized from sections
            if m.group(1) not in group_ranges:
                group_ranges[m.group(1)] = (addr, addr)

    # -- Pass 2: find section boundaries in the file ---------------------------
    section_starts: dict[str, int] = {}   # section-name → line index
    for i, line in enumerate(lines):
        for marker in (
            "PLACEMENT SUMMARY",
            "ENTRY LIST",
            "MODULE SUMMARY",
            "INIT TABLE",
            "RUNTIME MODEL ATTRIBUTES",
            "HEAP AND STACK SIZES",
        ):
            if marker in line and line.strip().startswith('*'):
                section_starts[marker] = i

    ps_start = section_starts.get("PLACEMENT SUMMARY", -1)
    el_start  = section_starts.get("ENTRY LIST", -1)
    ms_start  = section_starts.get("MODULE SUMMARY", len(lines))

    # -- Pass 3: parse PLACEMENT SUMMARY ---------------------------------------
    # We build a list of (section_name, kind, address, size, object_file, current_group)
    raw_sections: list[dict] = []
    current_group: Optional[str] = None

    ps_end = el_start if el_start > ps_start else ms_start

    if ps_start >= 0:
        in_table = False
        for line in lines[ps_start:ps_end]:
            stripped = line.strip()

            # Detect table header
            if re.match(r'Section\s+Kind\s+Address', stripped):
                in_table = True
                continue
            if re.match(r'-{3,}', stripped) and in_table:
                continue

            if not in_table:
                continue

            # Group header line
            m = _RE_BODY_GROUP.match(line)
            if m:
                current_group = m.group(1)
                continue

            # Section line
            m = _RE_SECTION.match(line)
            if m:
                name_raw = m.group(1).strip()
                kind     = m.group(2).strip().lower()
                addr     = _h(m.group(3))
                size     = _h(m.group(4))
                obj_raw  = m.group(5) or ''
                obj, lib = _clean_object(obj_raw)
                if size > 0:
                    raw_sections.append({
                        'name':    name_raw,
                        'kind':    kind,
                        'address': addr,
                        'size':    size,
                        'object':  obj,
                        'library': lib,
                        'group':   current_group,
                    })
                continue

            # Symbol address annotation line (skip - we get symbols from ENTRY LIST)

    # -- Pass 4: parse ENTRY LIST for symbols ----------------------------------
    raw_symbols: list[dict] = []

    if el_start >= 0:
        in_entries = False
        for line in lines[el_start:]:
            stripped = line.strip()
            if re.match(r'Entry\s+Address\s+Size', stripped):
                in_entries = True
                continue
            if re.match(r'-{3,}', stripped) and in_entries:
                continue
            if not in_entries or not stripped:
                continue
            # Stop at next major section
            if stripped.startswith('*') and len(stripped) > 20:
                break

            m = _RE_ENTRY.match(line)
            if m:
                sym_name = m.group(1)
                addr     = _h(m.group(2))
                size     = _h(m.group(3)) if m.group(3) else 0
                kind     = m.group(4).lower()
                obj_raw  = m.group(5)
                obj, lib = _clean_object(obj_raw)
                if size > 0 and kind not in ('--',):
                    raw_symbols.append({
                        'name':    sym_name,
                        'address': addr,
                        'size':    size,
                        'kind':    kind,
                        'object':  obj,
                        'library': lib,
                    })

    # -- Merge sections: aggregate same-name sections ---------------------------
    # IAR emits one line per object file for .text, so we merge them.
    sec_map: dict[str, dict] = {}
    for rs in raw_sections:
        key = rs['name']
        if key not in sec_map:
            sec_map[key] = {
                'name':    rs['name'],
                'kind':    rs['kind'],
                'address': rs['address'],
                'size':    rs['size'],
                'group':   rs['group'],
                'objects': [rs['object']],
            }
        else:
            sec_map[key]['size']    += rs['size']
            sec_map[key]['objects'].append(rs['object'])

    # -- Build Section objects --------------------------------------------------
    # Map symbol address → section name for assignment
    # Build address range list: (start, end, section_name)
    address_ranges: list[tuple[int, int, str]] = []
    for rs in raw_sections:
        address_ranges.append((rs['address'], rs['address'] + rs['size'], rs['name']))
    address_ranges.sort()

    def _find_section(addr: int) -> str:
        """Find the section name that contains this address."""
        for start, end, name in address_ranges:
            if start <= addr < end:
                return name
        return ''

    # Build symbols first, assigning them to sections
    symbols_by_section: dict[str, list[Symbol]] = {}
    for rs in raw_symbols:
        sec_name = _find_section(rs['address'])
        sym = Symbol(
            name=rs['name'],
            size=rs['size'],
            address=rs['address'],
            section=sec_name,
            object_file=rs['object'],
            library=rs['library'],
        )
        symbols_by_section.setdefault(sec_name, []).append(sym)

    sections: list[Section] = []
    for name, sd in sec_map.items():
        syms = symbols_by_section.get(name, [])
        stype = _section_type(sd['kind'], name)
        sections.append(Section(
            name=name,
            size=sd['size'],
            address=sd['address'],
            section_type=stype,
            symbols=syms,
            vma=sd['address'],
            lma=sd['address'],
        ))

    # -- Build MemoryRegion objects from placement group ranges -----------------
    regions: list[MemoryRegion] = []
    for gname, (gstart, gend) in sorted(group_ranges.items(), key=lambda x: x[1][0]):
        # IAR range is [from X to Y] inclusive, so length = Y - X + 1
        length = gend - gstart + 1 if gend > gstart else 0
        if length <= 0:
            continue
        # Compute used bytes from sections in this address range
        used = sum(
            s.size for s in sections
            if gstart <= s.address < gend
        )
        # Guess a human name
        human = gname
        if gstart >= 0x20000000 and gstart < 0x40000000:
            human = "RAM"
        elif gstart >= 0x08000000 and gstart < 0x20000000:
            human = "FLASH"

        regions.append(MemoryRegion(
            name=human,
            origin=gstart,
            length=length,
            used=used,
        ))

    return MemoryMap(
        source_file=str(map_file),
        toolchain='iar',
        target=None,
        sections=sections,
        regions=regions,
    )
