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

    @property
    def total_flash(self) -> int:
        """Sum of all flash-resident sections."""
        flash_types = {SectionType.TEXT, SectionType.RODATA, SectionType.DATA}
        return sum(s.size for s in self.sections if s.section_type in flash_types)

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
