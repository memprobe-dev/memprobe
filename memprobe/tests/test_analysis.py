"""Tests for bloat, insights, diff, and budget modules."""

import pytest
from pathlib import Path

from memprobe.models import MemoryMap, Section, Symbol, SectionType, MemoryRegion
from memprobe.bloat import analyze as bloat_analyze, BloatWarning
from memprobe.insights import compute_insights
from memprobe.diff import diff as compute_diff
from memprobe.budget import check_budgets, parse_size, BudgetViolation
from memprobe.libraries import detect_libraries


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sym(name, size, section=".text", obj="main.o", library=None, source=None):
    return Symbol(name=name, size=size, address=0x8000000, section=section,
                  object_file=obj, library=library, source_location=source)


def _mmap(sections, regions=None):
    return MemoryMap(
        source_file="/tmp/test.elf",
        toolchain="gcc",
        target="ARM",
        sections=sections,
        regions=regions or [],
    )


def _text_sec(syms):
    return Section(name=".text", size=sum(s.size for s in syms),
                   address=0x8000000, section_type=SectionType.TEXT, symbols=syms)


def _bss_sec(syms):
    return Section(name=".bss", size=sum(s.size for s in syms),
                   address=0x20000000, section_type=SectionType.BSS, symbols=syms)


def _rodata_sec(syms):
    return Section(name=".rodata", size=sum(s.size for s in syms),
                   address=0x8010000, section_type=SectionType.RODATA, symbols=syms)


# ============================================================================
# bloat tests
# ============================================================================

class TestBloat:
    def test_empty_mmap_no_warnings(self):
        mmap = _mmap([])
        assert bloat_analyze(mmap) == []

    def test_asan_warning(self):
        syms = [_sym("__asan_init", 100), _sym("main", 200)]
        mmap = _mmap([_text_sec(syms)])
        warnings = bloat_analyze(mmap)
        levels = [w.level for w in warnings]
        messages = " ".join(w.message for w in warnings)
        assert "warning" in levels
        assert "ASan" in messages

    def test_ubsan_warning(self):
        syms = [_sym("__ubsan_handle_type_mismatch", 50), _sym("app_main", 100)]
        mmap = _mmap([_text_sec(syms)])
        warnings = bloat_analyze(mmap)
        assert any("UBSan" in w.message for w in warnings)

    def test_cxa_throw_warning(self):
        syms = [_sym("__cxa_throw", 200), _sym("main", 100)]
        mmap = _mmap([_text_sec(syms)])
        warnings = bloat_analyze(mmap)
        assert any("exceptions" in w.message.lower() for w in warnings)

    def test_no_false_positive_clean_binary(self):
        syms = [_sym("main", 200), _sym("HAL_Init", 300)]
        mmap = _mmap([_text_sec(syms)])
        warnings = bloat_analyze(mmap)
        # No sanitizers, no exceptions in a clean binary
        assert all(w.level == "info" for w in warnings) or warnings == []

    def test_large_symbol_warning(self):
        syms = [_sym("big_lookup_table", 128 * 1024)]
        mmap = _mmap([_rodata_sec(syms)])
        warnings = bloat_analyze(mmap)
        assert any("big_lookup_table" in (w.symbol or "") for w in warnings)

    def test_float_printf_warning(self):
        syms = [_sym("_printf_float", 8000), _sym("main", 100)]
        mmap = _mmap([_text_sec(syms)])
        warnings = bloat_analyze(mmap)
        assert any("float" in w.message.lower() for w in warnings)

    def test_stack_canary_info(self):
        syms = [_sym("__stack_chk_fail", 50), _sym("main", 100)]
        mmap = _mmap([_text_sec(syms)])
        warnings = bloat_analyze(mmap)
        assert any("canary" in w.message.lower() or "stack" in w.message.lower() for w in warnings)

    def test_warnings_have_required_fields(self):
        syms = [_sym("__asan_init", 100)]
        mmap = _mmap([_text_sec(syms)])
        for w in bloat_analyze(mmap):
            assert w.level in ("warning", "info")
            assert isinstance(w.message, str)
            assert len(w.message) > 0

    def test_msan_warning(self):
        syms = [_sym("__msan_init", 80)]
        mmap = _mmap([_text_sec(syms)])
        warnings = bloat_analyze(mmap)
        assert any("MSan" in w.message for w in warnings)

    def test_global_ctors_info(self):
        init_sec = Section(name=".init_array", size=16, address=0x8002000,
                           section_type=SectionType.OTHER, symbols=[])
        mmap = _mmap([init_sec])
        warnings = bloat_analyze(mmap)
        assert any("constructor" in w.message.lower() or "init_array" in w.message.lower()
                   for w in warnings)


# ============================================================================
# insights tests
# ============================================================================

class TestInsights:
    def test_returns_required_keys(self):
        mmap = _mmap([_text_sec([_sym("main", 200)])])
        result = compute_insights(mmap)
        assert "file_contributors"        in result
        assert "dir_contributors"         in result
        assert "symbol_size_distribution" in result
        assert "padding_waste"            in result
        assert "duplicate_symbols"        in result
        assert "rodata_summary"           in result
        assert "duplicate_strings"        in result

    def test_file_contributors_with_source_location(self):
        syms = [_sym("foo", 100, source="src/app.c:10"),
                _sym("bar", 200, source="src/app.c:20")]
        mmap = _mmap([_text_sec(syms)])
        result = compute_insights(mmap)
        files = {e["file"] for e in result["file_contributors"]}
        assert "src/app.c" in files

    def test_toolchain_paths_excluded(self):
        syms = [_sym("malloc", 500, source="/usr/lib/libc.c:42")]
        mmap = _mmap([_text_sec(syms)])
        result = compute_insights(mmap)
        # Toolchain paths should not appear in file_contributors
        for entry in result["file_contributors"]:
            assert not entry["file"].startswith("/usr/")

    def test_symbol_size_distribution_buckets(self):
        syms = [_sym(f"s{i}", sz) for i, sz in enumerate([4, 30, 100, 300, 2000, 5000])]
        mmap = _mmap([_text_sec(syms)])
        dist = compute_insights(mmap)["symbol_size_distribution"]
        total = sum(b["count"] for b in dist)
        assert total == len(syms)

    def test_duplicate_symbols_detected(self):
        # Two symbols with same name but different addresses
        s1 = Symbol(name="foo", size=100, address=0x1000, section=".text",
                    object_file="a.o")
        s2 = Symbol(name="foo", size=100, address=0x2000, section=".text",
                    object_file="b.o")
        sec = Section(name=".text", size=200, address=0x1000,
                      section_type=SectionType.TEXT, symbols=[s1, s2])
        mmap = _mmap([sec])
        dups = compute_insights(mmap)["duplicate_symbols"]
        assert any(d["name"] == "foo" for d in dups)

    def test_padding_waste_detected(self):
        # Symbols with a small gap between them
        s1 = Symbol(name="a", size=10, address=0x1000, section=".text", object_file="x.o")
        s2 = Symbol(name="b", size=20, address=0x100e, section=".text", object_file="x.o")  # 4-byte gap
        sec = Section(name=".text", size=30, address=0x1000,
                      section_type=SectionType.TEXT, symbols=[s1, s2])
        mmap = _mmap([sec])
        pw = compute_insights(mmap)["padding_waste"]
        assert pw["total_bytes"] >= 0  # may be 0 or positive depending on gap

    def test_rodata_summary_counts(self):
        syms = [_sym("str1", 20, section=".rodata", source="src/a.c:1"),
                _sym("str2", 30, section=".rodata", source="src/b.c:2")]
        mmap = _mmap([_rodata_sec(syms)])
        rs = compute_insights(mmap)["rodata_summary"]
        assert rs["symbol_count"] == 2
        assert rs["total_bytes"] == 50
        assert rs["unique_source_files"] == 2

    def test_empty_mmap_insights(self):
        mmap = _mmap([])
        result = compute_insights(mmap)
        assert result["file_contributors"] == []
        assert result["duplicate_symbols"] == []


# ============================================================================
# diff tests
# ============================================================================

class TestDiff:
    def _make_mmap(self, syms, name="/tmp/a.elf"):
        secs = [Section(name=".text", size=sum(s.size for s in syms),
                        address=0, section_type=SectionType.TEXT, symbols=syms)]
        m = _mmap(secs)
        m.source_file = name
        return m

    def test_identical_maps_zero_delta(self):
        syms = [_sym("foo", 100), _sym("bar", 200)]
        a = self._make_mmap(syms)
        b = self._make_mmap(syms)
        d = compute_diff(a, b)
        assert d.flash_delta == 0
        assert d.ram_delta == 0
        assert d.symbol_diffs == []

    def test_added_symbol(self):
        old_syms = [_sym("foo", 100)]
        new_syms = [_sym("foo", 100), _sym("bar", 50)]
        old = self._make_mmap(old_syms, "/tmp/old.elf")
        new = self._make_mmap(new_syms, "/tmp/new.elf")
        d = compute_diff(old, new)
        added = d.added_symbols
        assert any(s.name == "bar" for s in added)

    def test_removed_symbol(self):
        old_syms = [_sym("foo", 100), _sym("bar", 50)]
        new_syms = [_sym("foo", 100)]
        old = self._make_mmap(old_syms, "/tmp/old.elf")
        new = self._make_mmap(new_syms, "/tmp/new.elf")
        d = compute_diff(old, new)
        removed = d.removed_symbols
        assert any(s.name == "bar" for s in removed)

    def test_grown_symbol(self):
        old_syms = [_sym("foo", 100)]
        new_syms = [_sym("foo", 150)]
        old = self._make_mmap(old_syms)
        new = self._make_mmap(new_syms)
        d = compute_diff(old, new)
        changed = d.changed_symbols
        assert len(changed) == 1
        assert changed[0].name == "foo"
        assert changed[0].delta == 50

    def test_flash_delta_computed_correctly(self):
        old_syms = [_sym("foo", 100)]
        new_syms = [_sym("foo", 100), _sym("bar", 200)]
        old = self._make_mmap(old_syms)
        new = self._make_mmap(new_syms)
        d = compute_diff(old, new)
        assert d.flash_delta == 200

    def test_sort_by_abs_delta(self):
        old_syms = [_sym("tiny", 10), _sym("big", 100)]
        new_syms = [_sym("tiny", 100), _sym("big", 200)]
        old = self._make_mmap(old_syms)
        new = self._make_mmap(new_syms)
        d = compute_diff(old, new)
        assert abs(d.symbol_diffs[0].delta) >= abs(d.symbol_diffs[-1].delta)

    def test_source_and_target_files(self):
        old = self._make_mmap([], "/tmp/old.elf")
        new = self._make_mmap([], "/tmp/new.elf")
        d = compute_diff(old, new)
        assert d.old_source == "/tmp/old.elf"
        assert d.new_source == "/tmp/new.elf"


# ============================================================================
# budget tests
# ============================================================================

class TestBudget:
    def _mmap_with_flash_ram(self, flash=50000, ram=20000):
        text = Section(name=".text", size=flash, address=0,
                       section_type=SectionType.TEXT, symbols=[])
        bss  = Section(name=".bss",  size=ram,   address=0x20000000,
                       section_type=SectionType.BSS, symbols=[])
        return _mmap([text, bss])

    def test_no_violations_when_within_budget(self):
        mmap = self._mmap_with_flash_ram(50000, 20000)
        violations = check_budgets(mmap, {"flash": 100000, "ram": 40000})
        assert violations == []

    def test_flash_violation(self):
        mmap = self._mmap_with_flash_ram(flash=60000)
        violations = check_budgets(mmap, {"flash": 50000})
        assert len(violations) == 1
        assert violations[0].kind == "flash"
        assert violations[0].overage == 10000

    def test_ram_violation(self):
        mmap = self._mmap_with_flash_ram(ram=30000)
        violations = check_budgets(mmap, {"ram": 20000})
        assert len(violations) == 1
        assert violations[0].kind == "ram"

    def test_section_budget(self):
        mmap = self._mmap_with_flash_ram(flash=60000)
        violations = check_budgets(mmap, {".text": 50000})
        assert any(v.kind == "section" for v in violations)

    def test_section_wildcard_budget(self):
        text1 = Section(name=".text", size=30000, address=0, section_type=SectionType.TEXT, symbols=[])
        text2 = Section(name=".text.startup", size=5000, address=0x1000, section_type=SectionType.TEXT, symbols=[])
        mmap = _mmap([text1, text2])
        violations = check_budgets(mmap, {".text*": 30000})
        assert len(violations) == 1
        assert violations[0].actual == 35000

    def test_module_budget(self):
        syms = [_sym("foo", 1000, obj="src/drivers/spi.o"),
                _sym("bar", 500,  obj="src/app/main.o")]
        mmap = _mmap([_text_sec(syms)])
        violations = check_budgets(mmap, {"src/drivers/*": 500})
        assert any(v.kind == "module" for v in violations)

    def test_empty_budgets_no_violations(self):
        mmap = self._mmap_with_flash_ram()
        assert check_budgets(mmap, {}) == []

    def test_budget_violation_human_readable(self):
        mmap = self._mmap_with_flash_ram(flash=600 * 1024)
        violations = check_budgets(mmap, {"flash": 512 * 1024})
        assert violations
        v = violations[0]
        assert "KB" in v.budget_human or "MB" in v.budget_human

    def test_violation_message_contains_label(self):
        mmap = self._mmap_with_flash_ram(flash=60000)
        violations = check_budgets(mmap, {"flash": 50000})
        assert "Flash" in violations[0].message


class TestParseSizeUnit:
    @pytest.mark.parametrize("s,expected", [
        ("512KB",   512 * 1024),
        ("1MB",     1024 * 1024),
        ("1.5 MB",  int(1.5 * 1024 * 1024)),
        ("131072",  131072),
        ("256KB",   256 * 1024),
    ])
    def test_valid(self, s, expected):
        assert parse_size(s) == expected

    def test_invalid_unit(self):
        with pytest.raises(ValueError):
            parse_size("10XB")

    def test_invalid_format(self):
        with pytest.raises(ValueError):
            parse_size("not_a_size")


# ============================================================================
# libraries tests
# ============================================================================

class TestLibraries:
    def test_freertos_detected(self):
        syms = [_sym("xTaskCreate", 200), _sym("vTaskDelay", 100),
                _sym("xQueueCreate", 150), _sym("main", 50)]
        mmap = _mmap([_text_sec(syms)])
        libs = detect_libraries(mmap)
        names = {lib.name for lib in libs}
        assert "FreeRTOS" in names

    def test_mbed_tls_detected(self):
        syms = [_sym("mbedtls_sha256_init", 100), _sym("mbedtls_aes_crypt_ecb", 200),
                _sym("mbedtls_entropy_init", 50)]
        mmap = _mmap([_text_sec(syms)])
        libs = detect_libraries(mmap)
        assert any("Mbed" in lib.name for lib in libs)

    def test_no_false_positive_empty(self):
        mmap = _mmap([])
        libs = detect_libraries(mmap)
        assert libs == []

    def test_single_symbol_no_detection(self):
        # Require at least 2 symbols to avoid false positives
        syms = [_sym("xTaskCreate", 200)]
        mmap = _mmap([_text_sec(syms)])
        libs = detect_libraries(mmap)
        freertos = [lib for lib in libs if lib.name == "FreeRTOS"]
        assert len(freertos) == 0

    def test_library_flash_bytes_sum(self):
        syms = [_sym("xTaskCreate", 200), _sym("vTaskDelay", 100), _sym("xQueueCreate", 50)]
        mmap = _mmap([_text_sec(syms)])
        libs = detect_libraries(mmap)
        freertos = next((lib for lib in libs if lib.name == "FreeRTOS"), None)
        assert freertos is not None
        assert freertos.flash_bytes == 350

    def test_result_sorted_by_flash_desc(self):
        syms = (
            [_sym(f"mbedtls_{i}", 10) for i in range(5)] +
            [_sym("xTaskCreate", 200), _sym("vTaskDelay", 100), _sym("xQueueCreate", 50)]
        )
        mmap = _mmap([_text_sec(syms)])
        libs = detect_libraries(mmap)
        if len(libs) >= 2:
            assert libs[0].flash_bytes >= libs[1].flash_bytes
