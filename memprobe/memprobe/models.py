"""Data models for firmware memory map analysis."""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class SectionType(Enum):
    TEXT = "text"
    DATA = "data"
    BSS = "bss"
    RODATA = "rodata"
    HEAP = "heap"
    STACK = "stack"
    OTHER = "other"


@dataclass
class Symbol:
    """A single symbol (function or variable) within a section."""

    name: str
    size: int
    address: int
    section: str
    object_file: str
    library: Optional[str] = None
    source_location: Optional[str] = None  # "src/hal/uart.c:142" from DWARF


@dataclass
class Section:
    """A linker section (e.g. .text, .data, .bss)."""

    name: str
    size: int
    address: int
    section_type: SectionType
    symbols: list[Symbol] = field(default_factory=list)
    vma: int = 0
    lma: int = 0
    # False for NOBITS sections (e.g. .bss and address-space reservations like
    # ESP-IDF's .flash_rodata_dummy): they occupy runtime memory but zero bytes
    # in the stored image, so they must never be counted toward flash usage.
    occupies_file: bool = True
    # SHF_ALLOC: the section is loaded into the target's address space at runtime.
    # False for link-time-only metadata (.strtab, .symtab, .xt.prop, ...): present
    # in the ELF but never shipped to the device, so excluded from flash and from
    # the treemap/address map. Map-file parsers only ever list allocated sections.
    alloc: bool = True


@dataclass
class MemoryRegion:
    """A named memory region from the linker script (e.g. FLASH, RAM)."""

    name: str
    origin: int
    length: int
    used: int = 0


@dataclass
class MemoryMap:
    """Complete memory layout parsed from an ELF or map file."""

    source_file: str
    toolchain: str
    target: Optional[str]
    sections: list[Section] = field(default_factory=list)
    regions: list[MemoryRegion] = field(default_factory=list)
    build_id: Optional[str] = None
    timestamp: Optional[str] = None
    binary_info: Optional[dict] = None
    # call_graph[func_name] = {"calls": [...], "called_by": [...]}
    # Only populated for ELF files; None when unavailable.
    call_graph: Optional[dict] = None

    @property
    def total_flash(self) -> int:
        """Bytes the loader copies into flash: every allocated section that
        stores content in the image.

        Measured by ELF flags, not section names, so vendor-named content
        sections (e.g. ESP-IDF's .iram0.vectors, .flash.appdesc) are counted
        too. Two exclusions, both because the bytes are not in the stored image:
          - non-allocated metadata (.strtab, .symtab, .xt.prop): alloc is False
          - NOBITS reservations (.bss, .flash_rodata_dummy): occupies_file False

        This counts the loadable content, not the on-disk size of a packaged
        firmware container (e.g. an esptool .bin with its headers and padding).
        """
        return sum(
            s.size for s in self.sections
            if s.alloc and s.occupies_file
        )

    @property
    def total_ram(self) -> int:
        """Sum of all RAM sections."""
        ram_types = {SectionType.BSS, SectionType.DATA, SectionType.HEAP, SectionType.STACK}
        return sum(s.size for s in self.sections if s.section_type in ram_types)

    @property
    def all_symbols(self) -> list[Symbol]:
        """Flat list of all symbols across all sections."""
        return [sym for sec in self.sections for sym in sec.symbols]


@dataclass
class SymbolDiff:
    """Size difference for a single symbol between two builds."""

    name: str
    object_file: str
    old_size: int
    new_size: int
    delta: int


@dataclass
class BuildDiff:
    """Comparison between two firmware builds."""

    old_source: str
    new_source: str
    flash_delta: int
    ram_delta: int
    symbol_diffs: list[SymbolDiff] = field(default_factory=list)

    @property
    def added_symbols(self) -> list[SymbolDiff]:
        """Symbols present in new build but not old."""
        return [s for s in self.symbol_diffs if s.old_size == 0]

    @property
    def removed_symbols(self) -> list[SymbolDiff]:
        """Symbols present in old build but not new."""
        return [s for s in self.symbol_diffs if s.new_size == 0]

    @property
    def changed_symbols(self) -> list[SymbolDiff]:
        """Symbols present in both builds with different sizes."""
        return [s for s in self.symbol_diffs if s.old_size > 0 and s.new_size > 0]
