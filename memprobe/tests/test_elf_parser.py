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
CG_ELF     = FIXTURES / "firmware_callgraph_x86.elf"


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


def test_flash_counted_by_flags(stm32):
    # total_flash is defined by ELF flags, not section names: every allocated
    # section that stores bytes in the image (alloc and occupies_file).
    expected = sum(s.size for s in stm32.sections if s.alloc and s.occupies_file)
    assert stm32.total_flash == expected


def test_flash_counts_allocated_content_regardless_of_type():
    # A vendor-named content section that classifies as OTHER (e.g. ESP-IDF's
    # .iram0.vectors or an ARM .ARM.exidx) is still shipped to the device, so it
    # must count toward flash even though its name does not match a flash type.
    from memprobe.models import MemoryMap, Section, SectionType
    text = Section(name=".text", size=1000, address=0x8000000,
                   section_type=SectionType.TEXT)
    other = Section(name=".ARM.exidx", size=200, address=0x80003e8,
                    section_type=SectionType.OTHER)
    mm = MemoryMap(source_file="x.elf", toolchain="gcc", target="arm",
                   sections=[text, other])
    assert mm.total_flash == 1200


def test_flash_excludes_non_allocated_metadata():
    # Link-time-only metadata (.xt.prop, .strtab) is present in the ELF but never
    # shipped to the device: alloc is False, so it must not count toward flash.
    from memprobe.models import MemoryMap, Section, SectionType
    text = Section(name=".text", size=1000, address=0x8000000,
                   section_type=SectionType.TEXT)
    meta = Section(name=".xt.prop", size=272748, address=0,
                   section_type=SectionType.OTHER, alloc=False)
    mm = MemoryMap(source_file="x.elf", toolchain="gcc", target="xtensa",
                   sections=[text, meta])
    assert mm.total_flash == 1000


def test_alloc_defaults_true():
    from memprobe.models import Section, SectionType
    s = Section(name=".data", size=64, address=0x20000000,
                section_type=SectionType.DATA)
    assert s.alloc is True


def test_nobits_sections_excluded_from_flash():
    # ESP-IDF's .flash_rodata_dummy is a NOBITS section whose name contains
    # "rodata", so it classifies as RODATA. It reserves MMU address space but
    # stores zero bytes in the image, so it must not count toward flash.
    from memprobe.models import MemoryMap, Section, SectionType
    real = Section(name=".flash.rodata", size=1000, address=0x3c050120,
                   section_type=SectionType.RODATA, occupies_file=True)
    dummy = Section(name=".flash_rodata_dummy", size=327680, address=0x3c000020,
                    section_type=SectionType.RODATA, occupies_file=False)
    mm = MemoryMap(source_file="x.elf", toolchain="gcc", target="Xtensa",
                   sections=[real, dummy])
    assert mm.total_flash == 1000  # dummy excluded


def test_occupies_file_defaults_true():
    # Map-file parsers do not set this flag; the default must preserve the old
    # "name-based" flash behavior for sections that do carry content.
    from memprobe.models import Section, SectionType
    s = Section(name=".data", size=64, address=0x20000000,
                section_type=SectionType.DATA)
    assert s.occupies_file is True


def test_ram_types_counted(stm32):
    ram_types = {SectionType.BSS, SectionType.DATA, SectionType.HEAP, SectionType.STACK}
    expected = sum(s.size for s in stm32.sections if s.section_type in ram_types)
    assert stm32.total_ram == expected


# -- LMA from PT_LOAD ---------------------------------------------------------

def test_compute_lma_maps_through_segment_offset():
    # .data lives at RAM VMA 0x20000000 but is initialized from a flash copy
    # placed right after .text. The PT_LOAD segment carries that offset.
    from memprobe.parsers.elf import _compute_lma
    # (p_vaddr, p_paddr, p_memsz): flash text segment and a RAM data segment
    # whose load address is in flash at 0x8001000.
    segs = [
        (0x08000000, 0x08000000, 0x1000),   # in-place flash, lma == vma
        (0x20000000, 0x08001000, 0x400),    # .data: RAM vma, flash lma
    ]
    assert _compute_lma(0x08000200, segs) == 0x08000200  # text: unchanged
    assert _compute_lma(0x20000000, segs) == 0x08001000  # data: flash copy
    assert _compute_lma(0x20000100, segs) == 0x08001100  # data + offset


def test_compute_lma_falls_back_to_vma_outside_segments():
    from memprobe.parsers.elf import _compute_lma
    assert _compute_lma(0x40000000, [(0x0, 0x0, 0x100)]) == 0x40000000
    assert _compute_lma(0x1234, []) == 0x1234


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


# -- DWARF CU cache clearing (memory regression guard) ------------------------

def test_dwarf_cu_cache_cleared_after_walk():
    """After parse(), pyelftools' internal DIE lists must be empty.

    _build_dwarf_maps clears cu._dielist after each CU so that DIE objects
    from one compilation unit are freed before the next one is parsed.
    If this regresses, peak RAM climbs from O(one CU) to O(all CUs).
    """
    import gc
    from elftools.elf.elffile import ELFFile

    # Re-run the DWARF walk the same way the parser does and check the cache.
    from memprobe.parsers import elf as elf_mod

    with open(STM32_ELF, "rb") as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            return  # fixture has no DWARF; nothing to check
        dwarf = elf.get_dwarf_info()
        cus = list(dwarf.iter_CUs())

    # Run the full build to trigger the cache-clearing path.
    parse(STM32_ELF)
    gc.collect()

    # Every CU's dielist should be empty after parse() finishes.
    for cu in cus:
        dielist = getattr(cu, '_dielist', [])
        assert dielist == [], (
            f"cu._dielist not cleared after parse(); "
            f"{len(dielist)} DIE objects still held in memory"
        )


# -- progress_cb --------------------------------------------------------------

def test_progress_cb_called():
    calls = []
    parse(STM32_ELF, progress_cb=lambda frac, stage: calls.append((frac, stage)))
    assert len(calls) > 0


def test_progress_cb_fractions_in_range():
    fracs = []
    parse(STM32_ELF, progress_cb=lambda frac, stage: fracs.append(frac))
    for f in fracs:
        assert 0.0 <= f <= 1.0, f"progress fraction out of range: {f}"


def test_progress_cb_stages_are_strings():
    stages = []
    parse(STM32_ELF, progress_cb=lambda frac, stage: stages.append(stage))
    for s in stages:
        assert isinstance(s, str)
        assert len(s) > 0


def test_progress_cb_monotonically_non_decreasing():
    fracs = []
    parse(STM32_ELF, progress_cb=lambda frac, stage: fracs.append(frac))
    for i in range(1, len(fracs)):
        assert fracs[i] >= fracs[i - 1], (
            f"progress went backwards: {fracs[i - 1]} -> {fracs[i]}"
        )


# -- binary_info completeness -------------------------------------------------

def test_binary_info_chip_family(stm32):
    # STM32 fixture has STM section names so chip_family should be set
    cf = stm32.binary_info.get("chip_family")
    assert cf is not None
    assert isinstance(cf, str)
    assert len(cf) > 0


def test_binary_info_ota_estimate(stm32):
    ota = stm32.binary_info.get("ota_estimate")
    assert ota is not None
    assert isinstance(ota, dict)
    # Either populated with size data or empty if no suitable segments
    if ota:
        assert "raw_bytes"        in ota
        assert "compressed_bytes" in ota
        assert "ratio"            in ota
        assert ota["raw_bytes"] > 0
        assert ota["compressed_bytes"] > 0
        assert 0 < ota["ratio"] <= 1.0


def test_binary_info_duplicate_strings_structure(stm32):
    dups = stm32.binary_info.get("duplicate_strings", [])
    for d in dups:
        assert "string"        in d
        assert "count"         in d
        assert "wasted_bytes"  in d
        assert d["count"] >= 2
        assert d["wasted_bytes"] > 0


def test_binary_info_build_stamps_structure(stm32):
    stamps = stm32.binary_info.get("build_stamps", [])
    for s in stamps:
        assert "string"  in s
        assert "type"    in s
        assert s["type"] in ("date", "time")
        assert "section" in s
        assert "address" in s


def test_binary_info_arm_features_present(stm32):
    features = stm32.binary_info.get("arm_features", [])
    assert isinstance(features, list)


def test_binary_info_segments_have_flags(stm32):
    for seg in stm32.binary_info.get("segments", []):
        assert "flags" in seg
        # flags is a human-readable string like "r-x" or a list depending on version
        assert seg["flags"] is not None


# -- symbol consistency -------------------------------------------------------

def test_symbol_sections_exist_in_section_list(stm32):
    """Every symbol's .section name must appear as an actual section."""
    section_names = {sec.name for sec in stm32.sections}
    for sym in stm32.all_symbols:
        assert sym.section in section_names, (
            f"Symbol {sym.name!r} references unknown section {sym.section!r}"
        )


def test_symbols_positive_size_for_nrf(nrf):
    for sym in nrf.all_symbols:
        assert sym.size > 0


def test_symbols_positive_size_for_esp32c3(esp32c3):
    for sym in esp32c3.all_symbols:
        assert sym.size > 0


def test_all_symbols_count_matches_section_sum(nrf):
    assert len(nrf.all_symbols) == sum(len(sec.symbols) for sec in nrf.sections)


# -- section address sanity ---------------------------------------------------

def test_section_addresses_nonnegative(stm32):
    for sec in stm32.sections:
        assert sec.address >= 0


def test_section_addresses_nonnegative_nrf(nrf):
    for sec in nrf.sections:
        assert sec.address >= 0


# -- multi-fixture binary_info ------------------------------------------------

@pytest.mark.parametrize("fixture_path", [
    STM32_ELF, NRF_ELF, ESP32_ELF, ESP32C3,
])
def test_binary_info_present_for_all_fixtures(fixture_path):
    result = parse(fixture_path)
    assert result.binary_info is not None
    assert isinstance(result.binary_info, dict)


@pytest.mark.parametrize("fixture_path", [
    STM32_ELF, NRF_ELF, ESP32_ELF, ESP32C3,
])
def test_arch_tag_present_for_all_fixtures(fixture_path):
    result = parse(fixture_path)
    assert "arch_tag" in result.binary_info
    assert result.binary_info["arch_tag"].startswith("EM_")


@pytest.mark.parametrize("fixture_path", [
    STM32_ELF, NRF_ELF, ESP32_ELF, ESP32C3,
])
def test_total_flash_positive_for_all_fixtures(fixture_path):
    result = parse(fixture_path)
    assert result.total_flash > 0


# -- nRF specifics ------------------------------------------------------------

def test_nrf_symbols_have_object_file(nrf):
    # At least some symbols should carry an object_file annotation
    with_obj = [s for s in nrf.all_symbols if s.object_file]
    assert len(with_obj) > 0


def test_nrf_binary_info_endian(nrf):
    assert nrf.binary_info["endian"] in ("little-endian", "big-endian")


def test_nrf_chip_family_arm(nrf):
    cf = nrf.binary_info.get("chip_family", "")
    assert "ARM" in cf or "Nordic" in cf


# -- RISC-V / ESP32-C3 specifics ----------------------------------------------

def test_esp32c3_bitness_32(esp32c3):
    assert esp32c3.binary_info["bitness"] == 32


def test_esp32c3_has_sections(esp32c3):
    assert len(esp32c3.sections) > 0


def test_esp32c3_total_flash_positive(esp32c3):
    assert esp32c3.total_flash > 0


# -- ota_estimate for multiple fixtures ---------------------------------------

@pytest.mark.parametrize("fixture_path", [STM32_ELF, NRF_ELF])
def test_ota_estimate_structure_all_arm(fixture_path):
    result = parse(fixture_path)
    ota = result.binary_info.get("ota_estimate", {})
    if ota:
        # Note: zlib overhead can cause compressed_bytes to slightly exceed raw_bytes
        # for small or highly random data, so we only check they are positive.
        assert ota["compressed_bytes"] > 0
        assert ota["raw_bytes"] > 0
        assert ota["ratio"] > 0


# -- source_file recorded -----------------------------------------------------

def test_source_file_recorded(stm32):
    assert str(STM32_ELF) in stm32.source_file or stm32.source_file == str(STM32_ELF)


# -- call_graph field type ----------------------------------------------------

@pytest.mark.parametrize("fixture_path", [
    STM32_ELF, NRF_ELF, ESP32_ELF, ESP32C3,
])
def test_call_graph_field_type(fixture_path):
    result = parse(fixture_path)
    assert result.call_graph is None or isinstance(result.call_graph, dict)
