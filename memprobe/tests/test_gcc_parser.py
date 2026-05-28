"""Tests for the GCC linker map file parser."""

import pytest
from pathlib import Path

from memprobe.parsers.map_gcc import parse, _classify_section
from memprobe.models import SectionType, MemoryMap

FIXTURE = Path(__file__).parent / "fixtures" / "sample_gcc.map"


@pytest.fixture(scope="module")
def mmap():
    return parse(FIXTURE)


# -- MemoryMap structure -------------------------------------------------------

def test_returns_memorymap(mmap):
    assert isinstance(mmap, MemoryMap)


def test_toolchain_gcc(mmap):
    assert mmap.toolchain == "gcc"


# -- Regions -------------------------------------------------------------------

def test_regions_present(mmap):
    assert len(mmap.regions) >= 2


def test_flash_region(mmap):
    flash = next((r for r in mmap.regions if r.name == "FLASH"), None)
    assert flash is not None
    assert flash.origin == 0x08000000
    assert flash.length == 0x00080000


def test_ram_region(mmap):
    ram = next((r for r in mmap.regions if r.name == "RAM"), None)
    assert ram is not None
    assert ram.origin == 0x20000000
    assert ram.length == 0x00020000


def test_regions_used_nonneg(mmap):
    for r in mmap.regions:
        assert r.used >= 0


def test_flash_region_used_positive(mmap):
    flash = next(r for r in mmap.regions if r.name == "FLASH")
    assert flash.used > 0


def test_ram_region_used_positive(mmap):
    ram = next(r for r in mmap.regions if r.name == "RAM")
    assert ram.used > 0


# -- Sections ------------------------------------------------------------------

def test_text_section_present(mmap):
    names = [s.name for s in mmap.sections]
    assert ".text" in names


def test_data_section_present(mmap):
    names = [s.name for s in mmap.sections]
    assert ".data" in names


def test_bss_section_present(mmap):
    names = [s.name for s in mmap.sections]
    assert ".bss" in names


def test_rodata_section_present(mmap):
    names = [s.name for s in mmap.sections]
    assert ".rodata" in names


def test_text_section_type(mmap):
    text = next(s for s in mmap.sections if s.name == ".text")
    assert text.section_type == SectionType.TEXT


def test_bss_section_type(mmap):
    bss = next(s for s in mmap.sections if s.name == ".bss")
    assert bss.section_type == SectionType.BSS


def test_data_section_type(mmap):
    data = next(s for s in mmap.sections if s.name == ".data")
    assert data.section_type == SectionType.DATA


def test_rodata_section_type(mmap):
    rodata = next(s for s in mmap.sections if s.name == ".rodata")
    assert rodata.section_type == SectionType.RODATA


def test_data_section_has_lma(mmap):
    # .data section should have a load address parsed
    data = next(s for s in mmap.sections if s.name == ".data")
    # lma defaults to vma when not separately specified, or a flash address
    assert data.lma >= 0


# -- Symbols -------------------------------------------------------------------

def test_symbols_extracted(mmap):
    assert len(mmap.all_symbols) > 0


def test_main_symbol_present(mmap):
    syms = [s for s in mmap.all_symbols if s.name == "main"]
    assert len(syms) > 0


def test_main_symbol_size(mmap):
    main = next(s for s in mmap.all_symbols if s.name == "main")
    assert main.size == 0x48


def test_hal_init_symbol(mmap):
    sym = next((s for s in mmap.all_symbols if s.name == "HAL_Init"), None)
    assert sym is not None
    assert sym.size == 0x164


def test_bss_symbol(mmap):
    sym = next((s for s in mmap.all_symbols if s.name == "g_rx_buffer"), None)
    assert sym is not None
    assert sym.size == 0x400


def test_symbol_section_assignment(mmap):
    # Symbols in .text should reference .text
    for sym in mmap.all_symbols:
        if sym.name in ("main", "HAL_Init", "Reset_Handler"):
            assert sym.section == ".text"


def test_symbols_have_object_file(mmap):
    for sym in mmap.all_symbols:
        assert sym.object_file != ""


# -- Totals --------------------------------------------------------------------

def test_total_flash_nonzero(mmap):
    assert mmap.total_flash > 0


def test_total_ram_nonzero(mmap):
    assert mmap.total_ram > 0


# -- _classify_section ---------------------------------------------------------

@pytest.mark.parametrize("name,expected", [
    (".text",            SectionType.TEXT),
    (".text.startup",    SectionType.TEXT),
    (".iram0.text",      SectionType.TEXT),
    (".rodata",          SectionType.RODATA),
    (".flash.rodata",    SectionType.RODATA),
    (".data",            SectionType.DATA),
    (".dram0.data",      SectionType.DATA),
    (".bss",             SectionType.BSS),
    (".dram0.bss",       SectionType.BSS),
    (".heap",            SectionType.HEAP),
    (".stack",           SectionType.STACK),
    (".ARM.exidx",       SectionType.OTHER),
])
def test_classify_section(name, expected):
    assert _classify_section(name) == expected


# -- Error handling ------------------------------------------------------------

def test_parse_missing_file_raises():
    with pytest.raises(Exception):
        parse(Path("/nonexistent/path.map"))
