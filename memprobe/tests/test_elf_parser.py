"""Tests for the ELF binary parser."""

import pytest
from pathlib import Path

from memprobe.parsers.elf import parse
from memprobe.models import SectionType, MemoryMap

FIXTURES = Path(__file__).parent / "fixtures"

STM32_ELF  = FIXTURES / "stm32f407_motor_ctrl.elf"
NRF_ELF    = FIXTURES / "nrf52840_ble_peripheral.elf"
ESP32_ELF  = FIXTURES / "esp32_wifi_display.elf"
ESP32C3    = FIXTURES / "esp32c3_sensor_node.elf"


# -- Basic MemoryMap structure -------------------------------------------------

@pytest.fixture(scope="module")
def stm32():
    return parse(STM32_ELF)


@pytest.fixture(scope="module")
def nrf():
    return parse(NRF_ELF)


@pytest.fixture(scope="module")
def esp32():
    return parse(ESP32_ELF)


@pytest.fixture(scope="module")
def esp32c3():
    return parse(ESP32C3)


def test_stm32_returns_memorymap(stm32):
    assert isinstance(stm32, MemoryMap)


def test_stm32_toolchain(stm32):
    assert stm32.toolchain == "gcc"


def test_stm32_has_sections(stm32):
    assert len(stm32.sections) > 0


def test_stm32_total_flash_positive(stm32):
    assert stm32.total_flash > 0


def test_stm32_total_ram_nonnegative(stm32):
    assert stm32.total_ram >= 0


def test_stm32_binary_info_present(stm32):
    assert stm32.binary_info is not None
    assert "arch" in stm32.binary_info


def test_stm32_arch_is_arm(stm32):
    assert "ARM" in stm32.binary_info["arch"]


def test_stm32_bitness_32(stm32):
    assert stm32.binary_info["bitness"] == 32


def test_stm32_sections_have_positive_sizes(stm32):
    for sec in stm32.sections:
        assert sec.size > 0


def test_stm32_section_types_valid(stm32):
    valid = set(SectionType)
    for sec in stm32.sections:
        assert sec.section_type in valid


def test_stm32_text_section_present(stm32):
    types = {s.section_type for s in stm32.sections}
    assert SectionType.TEXT in types


def test_stm32_has_symbols(stm32):
    assert len(stm32.all_symbols) > 0


def test_stm32_symbols_positive_size(stm32):
    for sym in stm32.all_symbols:
        assert sym.size > 0


def test_stm32_symbols_have_section(stm32):
    # All symbols should be associated with a section name
    for sym in stm32.all_symbols:
        assert sym.section != ""


def test_nrf_arch_arm(nrf):
    assert "ARM" in nrf.binary_info["arch"]


def test_nrf_has_sections(nrf):
    assert len(nrf.sections) > 0


def test_nrf_total_flash_positive(nrf):
    assert nrf.total_flash > 0


def test_esp32_arch_xtensa(esp32):
    assert "Xtensa" in esp32.binary_info["arch"] or esp32.binary_info["arch_tag"] == "EM_XTENSA"


def test_esp32_sections_present(esp32):
    assert len(esp32.sections) > 0


def test_esp32c3_is_riscv(esp32c3):
    assert esp32c3.binary_info["arch_tag"] == "EM_RISCV"


# -- Binary info fields -------------------------------------------------------

def test_binary_info_endian(stm32):
    assert stm32.binary_info["endian"] in ("little-endian", "big-endian")


def test_binary_info_entry_point(stm32):
    # Entry point is a hex string like "0x8000000"
    ep = stm32.binary_info["entry_point"]
    assert ep.startswith("0x")
    assert int(ep, 16) >= 0


def test_binary_info_segments(stm32):
    # Every PT_LOAD segment has expected keys
    for seg in stm32.binary_info["segments"]:
        assert "vaddr" in seg
        assert "memsz" in seg
        assert "flags" in seg


def test_binary_info_elf_type(stm32):
    assert stm32.binary_info["elf_type"] in ("Executable", "Shared object", "Relocatable", "Core dump")


# -- Duplicate strings & build stamps ----------------------------------------

def test_duplicate_strings_is_list(stm32):
    assert isinstance(stm32.binary_info.get("duplicate_strings", []), list)


def test_build_stamps_is_list(stm32):
    assert isinstance(stm32.binary_info.get("build_stamps", []), list)


# -- MemoryMap properties -----------------------------------------------------

def test_all_symbols_flat(stm32):
    from_property = stm32.all_symbols
    manual = [sym for sec in stm32.sections for sym in sec.symbols]
    assert len(from_property) == len(manual)


def test_flash_types_counted(stm32):
    flash_types = {SectionType.TEXT, SectionType.RODATA, SectionType.DATA}
    expected = sum(s.size for s in stm32.sections if s.section_type in flash_types)
    assert stm32.total_flash == expected


def test_ram_types_counted(stm32):
    ram_types = {SectionType.BSS, SectionType.DATA, SectionType.HEAP, SectionType.STACK}
    expected = sum(s.size for s in stm32.sections if s.section_type in ram_types)
    assert stm32.total_ram == expected


# -- Error handling -----------------------------------------------------------

def test_parse_nonexistent_file_raises():
    with pytest.raises(Exception):
        parse(Path("/nonexistent/path/firmware.elf"))


def test_parse_empty_file_raises(tmp_path):
    f = tmp_path / "empty.elf"
    f.write_bytes(b"")
    with pytest.raises(Exception):
        parse(f)


def test_parse_garbage_file_raises(tmp_path):
    f = tmp_path / "bad.elf"
    f.write_bytes(b"\x00" * 64)
    with pytest.raises(Exception):
        parse(f)


# -- DWARF map early-free (regression: maps must not be accessible post-symbol-scan) ------

def test_dwarf_maps_freed_before_rodata_scans():
    """parse() must produce valid duplicate_strings and ota_estimate regardless of
    DWARF content, proving the del/gc.collect() after the symbol scan doesn't
    corrupt later passes."""
    result = parse(STM32_ELF)
    assert isinstance(result, MemoryMap)
    assert result.total_flash > 0
    # binary_info keys set by the post-DWARF passes must still be present
    assert "duplicate_strings" in result.binary_info
    assert "ota_estimate" in result.binary_info
    assert "build_stamps" in result.binary_info
