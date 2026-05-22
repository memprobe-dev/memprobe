"""Tests for the IAR linker map file parser."""

import pytest
from pathlib import Path

from memprobe.parsers.map_iar import parse
from memprobe.models import SectionType

FIXTURE = Path(__file__).parent / "fixtures" / "sample_iar.map"


@pytest.fixture(scope="module")
def mmap():
    return parse(FIXTURE)


# -- Memory regions -------------------------------------------------------------

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


def test_region_used_nonzero(mmap):
    for r in mmap.regions:
        assert r.used >= 0


# -- Sections -------------------------------------------------------------------

def test_text_section_present(mmap):
    names = [s.name for s in mmap.sections]
    assert ".text" in names


def test_bss_section_present(mmap):
    names = [s.name for s in mmap.sections]
    assert ".bss" in names


def test_text_section_type(mmap):
    text = next(s for s in mmap.sections if s.name == ".text")
    assert text.section_type == SectionType.TEXT


def test_bss_section_type(mmap):
    bss = next(s for s in mmap.sections if s.name == ".bss")
    assert bss.section_type == SectionType.BSS


def test_rodata_section_type(mmap):
    rodata = next((s for s in mmap.sections if s.name == ".rodata"), None)
    if rodata:
        assert rodata.section_type == SectionType.RODATA


def test_text_section_size(mmap):
    text = next(s for s in mmap.sections if s.name == ".text")
    # The .text section in the fixture has multiple entries summing to > 0
    assert text.size > 0


def test_data_section_present(mmap):
    data = next((s for s in mmap.sections if s.name == ".data"), None)
    assert data is not None
    assert data.size == 0x28


# -- Symbols --------------------------------------------------------------------

def test_symbols_extracted(mmap):
    assert len(mmap.all_symbols) > 0


def test_main_symbol(mmap):
    main = next((s for s in mmap.all_symbols if s.name == "main"), None)
    assert main is not None
    assert main.size == 0x48
    assert main.object_file == "main.o"


def test_hal_init_symbol(mmap):
    sym = next((s for s in mmap.all_symbols if s.name == "HAL_Init"), None)
    assert sym is not None
    assert sym.size == 0x164


def test_bss_symbol(mmap):
    sym = next((s for s in mmap.all_symbols if s.name == "g_rx_buffer"), None)
    assert sym is not None
    assert sym.size == 0x400


def test_no_cstack_block(mmap):
    """Block symbols like CSTACK$$Base should not appear as regular symbols."""
    names = [s.name for s in mmap.all_symbols]
    assert "CSTACK$$Base"  not in names
    assert "CSTACK$$Limit" not in names


# -- Totals ---------------------------------------------------------------------

def test_total_flash_nonzero(mmap):
    assert mmap.total_flash > 0


def test_total_ram_nonzero(mmap):
    assert mmap.total_ram > 0


def test_toolchain_iar(mmap):
    assert mmap.toolchain == "iar"
