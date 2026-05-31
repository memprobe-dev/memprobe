"""Unit tests for private helper functions in memprobe/parsers/elf.py.

These tests exercise the internal helpers in isolation using lightweight mock
objects so they run quickly without real ELF fixtures.
"""

from __future__ import annotations

import struct
import zlib
from unittest.mock import MagicMock, patch

import pytest

from memprobe.parsers import elf as elf_mod
from memprobe.models import Symbol

# ── Expose private helpers ────────────────────────────────────────────────────

_infer_chip_family = elf_mod._infer_chip_family
_parse_arm_flags   = elf_mod._parse_arm_flags
_decode            = elf_mod._decode
_extract_die_addr  = elf_mod._extract_die_addr
_analyze_rodata    = elf_mod._analyze_rodata
_estimate_ota_size = elf_mod._estimate_ota_size
_build_call_graph  = elf_mod._build_call_graph


# ── Shared stubs ──────────────────────────────────────────────────────────────

class _Attr:
    """Minimal pyelftools AttributeValue stand-in."""
    def __init__(self, value):
        self.value = value


class _DIE:
    """Minimal pyelftools DIE stand-in."""
    def __init__(self, attrs: dict):
        self.attributes = attrs


def _sym(name: str, size: int, address: int = 0x8000000) -> Symbol:
    return Symbol(name=name, size=size, address=address, section=".text", object_file="x.o")


def _mock_section(name: str, data: bytes, sh_addr: int = 0x0800_0000):
    """Mock ELF section with .name, .data(), and dict-style access."""
    sec = MagicMock()
    sec.name = name
    sec.data.return_value = data
    sec.__getitem__ = MagicMock(side_effect=lambda k: sh_addr if k == "sh_addr" else 0)
    return sec


def _mock_segment(p_type: str, p_filesz: int, p_flags: int, data: bytes):
    """Mock ELF segment."""
    seg = MagicMock()
    _map = {"p_type": p_type, "p_filesz": p_filesz, "p_flags": p_flags}
    seg.__getitem__ = MagicMock(side_effect=lambda k: _map[k])
    seg.data.return_value = data
    return seg


def _mock_elf(sections=(), segments=()):
    elf = MagicMock()
    elf.iter_sections.return_value = list(sections)
    elf.iter_segments.return_value = list(segments)
    return elf


# ============================================================================
# _infer_chip_family
# ============================================================================

class TestInferChipFamily:

    @pytest.mark.parametrize("sections,expected", [
        ([".iram0.text", ".dram0.data"],   "ESP32 (Xtensa LX6/LX7)"),
        ([".esp_wifi",   ".text"],          "ESP32 (Xtensa LX6/LX7)"),
        ([".text",       ".data"],          "Xtensa"),
    ])
    def test_xtensa_variants(self, sections, expected):
        assert _infer_chip_family("EM_XTENSA", sections) == expected

    @pytest.mark.parametrize("sections,expected", [
        ([".nrf_flash", ".data"],           "Nordic nRF (ARM Cortex-M)"),
        ([".nordic_log", ".bss"],           "Nordic nRF (ARM Cortex-M)"),
        ([".stm_flash",  ".bss"],           "STM32 (ARM Cortex-M)"),
        ([".text",       ".data"],          "ARM Cortex-M"),
    ])
    def test_arm_variants(self, sections, expected):
        assert _infer_chip_family("EM_ARM", sections) == expected

    def test_aarch64(self):
        assert _infer_chip_family("EM_AARCH64", []) == "ARM Cortex-A (64-bit)"

    def test_riscv(self):
        assert _infer_chip_family("EM_RISCV", []) == "RISC-V"

    def test_avr(self):
        assert _infer_chip_family("EM_AVR", []) == "AVR (8-bit)"

    def test_unknown_arch_returns_none(self):
        assert _infer_chip_family("EM_UNKNOWN_XYZ", [".text"]) is None

    def test_empty_section_list_unknown(self):
        assert _infer_chip_family("EM_ARM", []) == "ARM Cortex-M"

    def test_case_sensitive_match(self):
        # Uppercase "NRF" should NOT match the lowercase "nrf" check
        result = _infer_chip_family("EM_ARM", [".NRF_FLASH"])
        assert result == "ARM Cortex-M"


# ============================================================================
# _parse_arm_flags
# ============================================================================

class TestParseArmFlags:

    def test_zero_flags_returns_empty_list(self):
        assert _parse_arm_flags(0) == []

    @pytest.mark.parametrize("eabi,expected_str", [
        (1, "EABI v1"),
        (5, "EABI v5"),
        (7, "EABI v7"),
    ])
    def test_eabi_version_extracted(self, eabi, expected_str):
        flags = eabi << 24
        features = _parse_arm_flags(flags)
        assert expected_str in features

    def test_thumb_interwork_bit(self):
        features = _parse_arm_flags(0x800)
        assert "Thumb interwork" in features

    def test_hard_float_abi_bit(self):
        features = _parse_arm_flags(0x400)
        assert "hard-float ABI" in features

    def test_thumb2_without_hard_float_gives_soft_float(self):
        # 0x200 = Thumb-2 bit; alone means soft-float
        features = _parse_arm_flags(0x200)
        assert "Thumb-2" in features
        assert "soft-float" in features

    def test_thumb2_with_hard_float_no_soft_float(self):
        # Both bits set: hard-float should appear, soft-float should not
        features = _parse_arm_flags(0x200 | 0x400)
        assert "hard-float ABI" in features
        assert "soft-float" not in features

    def test_vfp_version(self):
        # VFP version sits in bits [11:8]. VFPv4 = 4 << 8 = 0x400 clashes with
        # hard-float ABI; use a standalone VFP flag value without other bits.
        # VFPv2 = 2 << 8 = 0x200 clashes with Thumb-2. Use VFPv3 = 3 << 8 = 0x300.
        features = _parse_arm_flags(0x300)
        assert "VFPv3" in features

    def test_combined_flags(self):
        # EABI v5, Thumb interwork, hard-float
        flags = (5 << 24) | 0x800 | 0x400
        features = _parse_arm_flags(flags)
        assert "EABI v5" in features
        assert "Thumb interwork" in features
        assert "hard-float ABI" in features


# ============================================================================
# _decode
# ============================================================================

class TestDecode:

    def test_bytes_decoded_as_utf8(self):
        assert _decode(b"hello") == "hello"

    def test_str_passthrough(self):
        assert _decode("world") == "world"

    def test_non_string_coerced(self):
        assert _decode(42) == "42"

    def test_invalid_utf8_uses_replacement(self):
        result = _decode(b"\xff\xfe invalid")
        assert isinstance(result, str)
        # Replacement character U+FFFD should appear
        assert "�" in result

    def test_empty_bytes(self):
        assert _decode(b"") == ""

    def test_empty_str(self):
        assert _decode("") == ""


# ============================================================================
# _extract_die_addr
# ============================================================================

class TestExtractDieAddr:

    def test_low_pc_returned(self):
        die = _DIE({"DW_AT_low_pc": _Attr(0xDEAD_BEEF)})
        assert _extract_die_addr(die, 4) == 0xDEAD_BEEF

    def test_low_pc_takes_priority_over_location(self):
        loc_bytes = bytes([0x03]) + struct.pack("<I", 0x1234)
        die = _DIE({
            "DW_AT_low_pc":  _Attr(0xAAAA),
            "DW_AT_location": _Attr(loc_bytes),
        })
        assert _extract_die_addr(die, 4) == 0xAAAA

    def test_location_op_addr_4_byte(self):
        addr = 0x0800_1000
        payload = bytes([0x03]) + struct.pack("<I", addr)
        die = _DIE({"DW_AT_location": _Attr(payload)})
        assert _extract_die_addr(die, 4) == addr

    def test_location_op_addr_8_byte(self):
        addr = 0x0000_7FFF_8000_0000
        payload = bytes([0x03]) + struct.pack("<Q", addr)
        die = _DIE({"DW_AT_location": _Attr(payload)})
        assert _extract_die_addr(die, 8) == addr

    def test_location_first_byte_not_op_addr(self):
        # 0x11 is DW_OP_const1u — not an absolute address
        payload = bytes([0x11, 0x42, 0x00, 0x00, 0x00])
        die = _DIE({"DW_AT_location": _Attr(payload)})
        assert _extract_die_addr(die, 4) is None

    def test_location_block_too_short(self):
        # Block is exactly addr_size bytes; we need at least addr_size + 1
        payload = bytes([0x03]) + struct.pack("<I", 0x1000)[:3]  # 4 bytes total but need 5
        die = _DIE({"DW_AT_location": _Attr(payload)})
        assert _extract_die_addr(die, 4) is None

    def test_no_location_no_low_pc_returns_none(self):
        die = _DIE({})
        assert _extract_die_addr(die, 4) is None

    def test_location_as_list(self):
        # pyelftools sometimes gives a list of ints instead of bytes
        addr = 0x1234_5678
        raw = struct.pack("<I", addr)
        payload = [0x03] + list(raw)
        die = _DIE({"DW_AT_location": _Attr(payload)})
        assert _extract_die_addr(die, 4) == addr

    def test_location_as_bytearray(self):
        addr = 0x4321
        raw = struct.pack("<I", addr)
        payload = bytearray([0x03]) + bytearray(raw)
        die = _DIE({"DW_AT_location": _Attr(payload)})
        assert _extract_die_addr(die, 4) == addr


# ============================================================================
# _analyze_rodata
# ============================================================================

class TestAnalyzeRodata:

    def test_empty_elf_returns_empty_results(self):
        elf = _mock_elf(sections=[])
        stamps, dups = _analyze_rodata(elf)
        assert stamps == []
        assert dups == []

    def test_non_rodata_section_ignored(self):
        sec = _mock_section(".text", b"hello\x00world\x00")
        elf = _mock_elf(sections=[sec])
        stamps, dups = _analyze_rodata(elf)
        assert stamps == []
        assert dups == []

    def test_rodata_subsection_included(self):
        # .rodata.str1.4 is a rodata subsection and should be scanned
        data = b"abcdefgh\x00" * 2  # 8-char string repeated twice
        sec = _mock_section(".rodata.str1.4", data)
        elf = _mock_elf(sections=[sec])
        _, dups = _analyze_rodata(elf)
        assert any(d["string"] == "abcdefgh" for d in dups)

    def test_single_occurrence_not_a_duplicate(self):
        data = b"unique_string\x00"
        sec = _mock_section(".rodata", data)
        elf = _mock_elf(sections=[sec])
        _, dups = _analyze_rodata(elf)
        assert not any(d["string"] == "unique_string" for d in dups)

    def test_duplicate_detected_and_wasted_bytes_computed(self):
        s = b"duplicate_key\x00"
        sec = _mock_section(".rodata", s * 3)  # 3 occurrences
        elf = _mock_elf(sections=[sec])
        _, dups = _analyze_rodata(elf)
        hit = next((d for d in dups if d["string"] == "duplicate_key"), None)
        assert hit is not None
        assert hit["count"] == 3
        # wasted = (3-1) * (len("duplicate_key") + 1)
        assert hit["wasted_bytes"] == 2 * (len("duplicate_key") + 1)

    def test_string_shorter_than_min_dup_len_excluded_from_dups(self):
        # MIN_DUP_LEN = 5; "abc" is 3 chars
        data = b"abc\x00" * 3
        sec = _mock_section(".rodata", data)
        elf = _mock_elf(sections=[sec])
        _, dups = _analyze_rodata(elf)
        assert not any(d["string"] == "abc" for d in dups)

    def test_string_longer_than_max_dup_len_excluded_from_dups(self):
        # MAX_DUP_LEN = 256; build a 300-char ASCII string
        long_str = b"A" * 300
        data = long_str + b"\x00" + long_str + b"\x00"
        sec = _mock_section(".rodata", data)
        elf = _mock_elf(sections=[sec])
        _, dups = _analyze_rodata(elf)
        assert not any(d["string"] == "A" * 300 for d in dups)

    def test_non_printable_bytes_skipped(self):
        # Null + non-ascii bytes mixed in
        data = b"\x01\x02\x03\x04\x05\x00"
        sec = _mock_section(".rodata", data)
        elf = _mock_elf(sections=[sec])
        stamps, dups = _analyze_rodata(elf)
        assert stamps == []
        assert dups == []

    def test_build_date_stamp_detected(self):
        # __DATE__ example: "May 21 2026" (exactly 11 chars)
        data = b"May 21 2026\x00"
        sec = _mock_section(".rodata", data)
        elf = _mock_elf(sections=[sec])
        stamps, _ = _analyze_rodata(elf)
        assert any(s["type"] == "date" and s["string"] == "May 21 2026" for s in stamps)

    def test_build_time_stamp_detected(self):
        # __TIME__ example: "15:30:00" (exactly 8 chars)
        data = b"15:30:00\x00"
        sec = _mock_section(".rodata", data)
        elf = _mock_elf(sections=[sec])
        stamps, _ = _analyze_rodata(elf)
        assert any(s["type"] == "time" and s["string"] == "15:30:00" for s in stamps)

    def test_date_with_single_digit_day(self):
        # __DATE__ single-digit day uses space: "May  1 2026"
        data = b"May  1 2026\x00"
        sec = _mock_section(".rodata", data)
        elf = _mock_elf(sections=[sec])
        stamps, _ = _analyze_rodata(elf)
        assert any(s["type"] == "date" for s in stamps)

    def test_stamp_includes_section_and_address(self):
        data = b"12:00:00\x00"
        sec = _mock_section(".rodata", data, sh_addr=0x8020000)
        elf = _mock_elf(sections=[sec])
        stamps, _ = _analyze_rodata(elf)
        assert len(stamps) == 1
        assert stamps[0]["section"] == ".rodata"
        assert stamps[0]["address"] == hex(0x8020000)

    def test_duplicates_sorted_by_wasted_bytes_descending(self):
        # "longerstr" (9 chars) * 3 = 2 * 10 = 20 wasted
        # "short" (5 chars) * 3     = 2 * 6  = 12 wasted
        data = b"longerstr\x00" * 3 + b"short\x00" * 3
        sec = _mock_section(".rodata", data)
        elf = _mock_elf(sections=[sec])
        _, dups = _analyze_rodata(elf)
        wastes = [d["wasted_bytes"] for d in dups]
        assert wastes == sorted(wastes, reverse=True)

    def test_results_capped_at_40_duplicates(self):
        # Generate 50 different strings each duplicated twice
        chunks = b"".join(
            f"string_{i:04d}".encode() + b"\x00" +
            f"string_{i:04d}".encode() + b"\x00"
            for i in range(50)
        )
        sec = _mock_section(".rodata", chunks)
        elf = _mock_elf(sections=[sec])
        _, dups = _analyze_rodata(elf)
        assert len(dups) <= 40

    def test_section_data_error_skipped_gracefully(self):
        good_sec = _mock_section(".rodata", b"abcdef\x00" * 2)
        bad_sec  = _mock_section(".rodata.bad", b"")
        bad_sec.data.side_effect = OSError("read error")
        elf = _mock_elf(sections=[bad_sec, good_sec])
        _, dups = _analyze_rodata(elf)
        # Should not raise; good section still processed
        assert any(d["string"] == "abcdef" for d in dups)


# ============================================================================
# _estimate_ota_size
# ============================================================================

class TestEstimateOtaSize:

    def test_no_segments_returns_empty_dict(self):
        elf = _mock_elf(segments=[])
        assert _estimate_ota_size(elf) == {}

    def test_non_ptload_excluded(self):
        seg = _mock_segment("PT_NOTE", 100, 0x5, b"\x00" * 100)
        elf = _mock_elf(segments=[seg])
        assert _estimate_ota_size(elf) == {}

    def test_ptload_with_filesz_zero_excluded(self):
        seg = _mock_segment("PT_LOAD", 0, 0x5, b"")
        elf = _mock_elf(segments=[seg])
        assert _estimate_ota_size(elf) == {}

    def test_writable_ptload_excluded(self):
        # PF_W = 0x2 — RAM segment, should be excluded
        seg = _mock_segment("PT_LOAD", 100, 0x2, b"\x00" * 100)
        elf = _mock_elf(segments=[seg])
        assert _estimate_ota_size(elf) == {}

    def test_non_writable_ptload_included(self):
        data = bytes(range(256)) * 4   # 1 KB of varied bytes
        seg = _mock_segment("PT_LOAD", len(data), 0x5, data)  # 0x5 = PF_R|PF_X, no PF_W
        elf = _mock_elf(segments=[seg])
        result = _estimate_ota_size(elf)
        assert result["raw_bytes"] == len(data)
        assert result["compressed_bytes"] > 0
        assert result["compressed_bytes"] <= result["raw_bytes"]
        assert 0 < result["ratio"] <= 1.0

    def test_highly_compressible_data(self):
        # All-zero data compresses very well
        data = b"\x00" * 4096
        seg = _mock_segment("PT_LOAD", len(data), 0x5, data)
        elf = _mock_elf(segments=[seg])
        result = _estimate_ota_size(elf)
        assert result["ratio"] < 0.1

    def test_multiple_non_writable_segments_summed(self):
        d1 = b"code_section_data" * 100
        d2 = b"rodata_section___" * 50
        s1 = _mock_segment("PT_LOAD", len(d1), 0x5, d1)
        s2 = _mock_segment("PT_LOAD", len(d2), 0x4, d2)  # PF_R only
        elf = _mock_elf(segments=[s1, s2])
        result = _estimate_ota_size(elf)
        assert result["raw_bytes"] == len(d1) + len(d2)

    def test_ratio_matches_compressed_over_raw(self):
        data = b"x" * 2048
        seg = _mock_segment("PT_LOAD", len(data), 0x5, data)
        elf = _mock_elf(segments=[seg])
        result = _estimate_ota_size(elf)
        expected_ratio = round(result["compressed_bytes"] / result["raw_bytes"], 3)
        assert result["ratio"] == expected_ratio

    def test_segment_data_error_skipped_gracefully(self):
        bad_seg  = _mock_segment("PT_LOAD", 100, 0x5, b"")
        bad_seg.data.side_effect = OSError("read error")
        good_seg = _mock_segment("PT_LOAD", 256, 0x5, b"A" * 256)
        elf = _mock_elf(segments=[bad_seg, good_seg])
        result = _estimate_ota_size(elf)
        assert result["raw_bytes"] == 256


# ============================================================================
# _build_call_graph
# ============================================================================

_MOD = "memprobe.parsers.elf"


class TestBuildCallGraph:
    """Tests the graph-assembly logic of _build_call_graph via mocked inner functions."""

    def _make_elf(self, has_dwarf: bool = False):
        elf = MagicMock()
        elf.has_dwarf_info.return_value = has_dwarf
        return elf

    def test_dwarf5_result_used_when_available(self):
        elf = self._make_elf(has_dwarf=True)
        syms = [_sym("main", 100, 0x1000), _sym("foo", 50, 0x2000)]
        forward = {"main": {"foo"}}

        with patch(f"{_MOD}._dwarf5_call_graph", return_value=forward):
            result, _ = _build_call_graph(elf, "EM_X86_64", syms)

        assert result is not None
        assert result["main"]["calls"] == ["foo"]
        assert result["foo"]["called_by"] == ["main"]

    def test_capstone_used_when_dwarf5_returns_none(self):
        elf = self._make_elf(has_dwarf=False)
        syms = [_sym("init", 40, 0x1000), _sym("run", 60, 0x2000)]
        forward = {"init": {"run"}}

        with patch(f"{_MOD}._dwarf5_call_graph", return_value=None), \
             patch(f"{_MOD}._capstone_call_graph", return_value=forward):
            result, _ = _build_call_graph(elf, "EM_X86_64", syms)

        assert result is not None
        assert result["init"]["calls"] == ["run"]

    def test_capstone_import_error_returns_none(self):
        elf = self._make_elf()
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=None), \
             patch(f"{_MOD}._capstone_call_graph", side_effect=ImportError):
            result, _ = _build_call_graph(elf, "EM_X86_64", [])
        assert result is None

    def test_capstone_value_error_returns_none(self):
        elf = self._make_elf()
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=None), \
             patch(f"{_MOD}._capstone_call_graph", side_effect=ValueError("unsupported")):
            result, _ = _build_call_graph(elf, "EM_XTENSA", [])
        assert result is None

    def test_capstone_exception_returns_none(self):
        elf = self._make_elf()
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=None), \
             patch(f"{_MOD}._capstone_call_graph", side_effect=RuntimeError("oops")):
            result, _ = _build_call_graph(elf, "EM_X86_64", [])
        assert result is None

    def test_both_return_empty_returns_none(self):
        elf = self._make_elf()
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=None), \
             patch(f"{_MOD}._capstone_call_graph", return_value={}):
            result, _ = _build_call_graph(elf, "EM_X86_64", [])
        assert result is None

    def test_reverse_edges_computed_correctly(self):
        elf = self._make_elf(has_dwarf=True)
        # main calls foo and bar; foo calls bar
        forward = {"main": {"foo", "bar"}, "foo": {"bar"}}
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=forward):
            result, _ = _build_call_graph(elf, "EM_X86_64", [])

        assert "main" in result["foo"]["called_by"]
        assert "main" in result["bar"]["called_by"]
        assert "foo"  in result["bar"]["called_by"]
        assert result["bar"]["calls"] == []

    def test_result_keys_sorted_alphabetically(self):
        elf = self._make_elf(has_dwarf=True)
        forward = {"zebra": {"alpha"}, "mango": {"alpha"}, "alpha": {"banana"}}
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=forward):
            result, _ = _build_call_graph(elf, "EM_X86_64", [])

        keys = list(result.keys())
        assert keys == sorted(keys)

    def test_calls_and_called_by_lists_are_sorted(self):
        elf = self._make_elf(has_dwarf=True)
        forward = {"z_caller": {"m_func", "a_func", "t_func"}}
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=forward):
            result, _ = _build_call_graph(elf, "EM_X86_64", [])

        calls_list = result["z_caller"]["calls"]
        assert calls_list == sorted(calls_list)

    def test_function_only_in_called_by_included_in_result(self):
        elf = self._make_elf(has_dwarf=True)
        # leaf_fn is only ever called, never a caller itself
        forward = {"entry": {"leaf_fn"}}
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=forward):
            result, _ = _build_call_graph(elf, "EM_X86_64", [])

        assert "leaf_fn" in result
        assert result["leaf_fn"]["calls"] == []
        assert "entry" in result["leaf_fn"]["called_by"]

    def test_arm_thumb_bit_stripped_for_addr_map(self):
        # Symbol at 0x8000001 (THUMB bit set) — its entry in addr_to_name should
        # be keyed at 0x8000000, matching how capstone resolves call targets.
        elf = self._make_elf()
        syms = [_sym("thumb_fn", 40, address=0x8000001)]
        captured = {}

        def _fake_capstone(elf, arch, func_syms, addr_to_name):
            captured.update(addr_to_name)
            return {}

        with patch(f"{_MOD}._dwarf5_call_graph", return_value=None), \
             patch(f"{_MOD}._capstone_call_graph", side_effect=_fake_capstone):
            _build_call_graph(elf, "EM_ARM", syms)

        assert 0x8000000 in captured
        assert 0x8000001 not in captured

    def test_symbol_with_zero_size_excluded_from_addr_map(self):
        elf = self._make_elf()
        syms = [_sym("nosize_fn", 0, address=0x5000), _sym("ok_fn", 100, address=0x6000)]
        captured = {}

        def _fake_capstone(elf, arch, func_syms, addr_to_name):
            captured.update(addr_to_name)
            return {}

        with patch(f"{_MOD}._dwarf5_call_graph", return_value=None), \
             patch(f"{_MOD}._capstone_call_graph", side_effect=_fake_capstone):
            _build_call_graph(elf, "EM_X86_64", syms)

        assert 0x5000 not in captured   # zero-size excluded
        assert 0x6000 in captured

    def test_multiple_callers_and_callees(self):
        elf = self._make_elf(has_dwarf=True)
        forward = {
            "a": {"c", "d"},
            "b": {"c", "d"},
            "c": {"e"},
        }
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=forward):
            result, _ = _build_call_graph(elf, "EM_X86_64", [])

        assert set(result["c"]["called_by"]) == {"a", "b"}
        assert set(result["d"]["called_by"]) == {"a", "b"}
        assert result["e"]["called_by"]      == ["c"]
        assert result["e"]["calls"]          == []
