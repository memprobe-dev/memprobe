"""Integration and unit tests for call graph extraction.

Integration tests use the firmware_callgraph_x86.elf fixture.
Unit tests exercise _build_call_graph and _dwarf5_call_graph logic.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from memprobe.parsers import elf as elf_mod
from memprobe.parsers.elf import parse, _build_call_graph, _dwarf5_call_graph
from memprobe.models import MemoryMap, Symbol

FIXTURES    = Path(__file__).parent / "fixtures"
CG_ELF      = FIXTURES / "firmware_callgraph_x86.elf"
STM32_ELF   = FIXTURES / "stm32f407_motor_ctrl.elf"


def _sym(name: str, size: int, address: int = 0x1000) -> Symbol:
    return Symbol(name=name, size=size, address=address, section=".text", object_file="x.o")


# ============================================================================
# Integration: firmware_callgraph_x86.elf
# ============================================================================

@pytest.fixture(scope="module")
def cg_result():
    if not CG_ELF.exists():
        pytest.skip("firmware_callgraph_x86.elf fixture not present")
    return parse(CG_ELF)


def test_callgraph_returns_memorymap(cg_result):
    assert isinstance(cg_result, MemoryMap)


def test_callgraph_result_is_none_or_dict(cg_result):
    """call_graph must be None or a dict — never another type."""
    assert cg_result.call_graph is None or isinstance(cg_result.call_graph, dict)


def test_callgraph_from_dwarf_regardless_of_elf_type(cg_result):
    """DWARF call-site extraction does not depend on PT_LOAD segments, so a call
    graph is produced even for a relocatable ELF when the DWARF carries call
    sites. The fixture is compiled with call-site info, so a graph is expected."""
    assert isinstance(cg_result.call_graph, dict)
    assert len(cg_result.call_graph) > 0


def test_callgraph_entries_have_required_keys(cg_result):
    if not cg_result.call_graph:
        pytest.skip("call graph empty")
    for fn, entry in cg_result.call_graph.items():
        assert "calls" in entry,     f"{fn!r} missing 'calls'"
        assert "called_by" in entry, f"{fn!r} missing 'called_by'"


def test_callgraph_calls_are_lists(cg_result):
    if not cg_result.call_graph:
        pytest.skip("call graph empty")
    for fn, entry in cg_result.call_graph.items():
        assert isinstance(entry["calls"],     list), f"{fn!r}.calls is not a list"
        assert isinstance(entry["called_by"], list), f"{fn!r}.called_by is not a list"


def test_callgraph_no_self_loops(cg_result):
    if not cg_result.call_graph:
        pytest.skip("call graph empty")
    for fn, entry in cg_result.call_graph.items():
        assert fn not in entry["calls"],     f"{fn!r} calls itself"
        assert fn not in entry["called_by"], f"{fn!r} is in its own called_by"


def test_callgraph_reverse_edges_consistent(cg_result):
    """For every A -> B edge there must be a B.called_by containing A."""
    if not cg_result.call_graph:
        pytest.skip("call graph empty")
    cg = cg_result.call_graph
    for caller, entry in cg.items():
        for callee in entry["calls"]:
            assert callee in cg, f"{callee!r} in {caller!r}.calls but absent from result"
            assert caller in cg[callee]["called_by"], (
                f"{caller!r} -> {callee!r} edge exists but reverse edge missing"
            )


def test_callgraph_forward_edges_consistent(cg_result):
    """For every B.called_by = A there must be an A.calls containing B."""
    if not cg_result.call_graph:
        pytest.skip("call graph empty")
    cg = cg_result.call_graph
    for callee, entry in cg.items():
        for caller in entry["called_by"]:
            assert caller in cg, f"{caller!r} in {callee!r}.called_by but absent from result"
            assert callee in cg[caller]["calls"], (
                f"Reverse edge {caller!r} -> {callee!r} exists but forward edge missing"
            )


def test_callgraph_keys_sorted(cg_result):
    if not cg_result.call_graph:
        pytest.skip("call graph empty")
    keys = list(cg_result.call_graph.keys())
    assert keys == sorted(keys)


def test_callgraph_calls_lists_sorted(cg_result):
    """All calls/called_by sublists must be sorted alphabetically."""
    if not cg_result.call_graph:
        pytest.skip("call graph empty")
    for fn, entry in cg_result.call_graph.items():
        assert entry["calls"]     == sorted(entry["calls"]),     f"{fn!r}.calls unsorted"
        assert entry["called_by"] == sorted(entry["called_by"]), f"{fn!r}.called_by unsorted"


def test_callgraph_all_call_targets_exist_in_result(cg_result):
    """Every symbol appearing in any 'calls' list must be a top-level key."""
    if not cg_result.call_graph:
        pytest.skip("call graph empty")
    cg = cg_result.call_graph
    for caller, entry in cg.items():
        for callee in entry["calls"]:
            assert callee in cg, f"callee {callee!r} (in {caller!r}.calls) not a top-level key"


def test_callgraph_non_empty(cg_result):
    """The callgraph fixture should produce at least a few edges."""
    if cg_result.call_graph is None:
        pytest.skip("call graph not available")
    assert len(cg_result.call_graph) > 0


# ============================================================================
# Integration: parse() call_graph on a non-callgraph fixture
# ============================================================================

@pytest.fixture(scope="module")
def stm32():
    if not STM32_ELF.exists():
        pytest.skip("STM32 fixture not present")
    return parse(STM32_ELF)


def test_stm32_call_graph_is_none_or_dict(stm32):
    """call_graph should be None or a well-formed dict, never anything else."""
    cg = stm32.call_graph
    assert cg is None or isinstance(cg, dict)


def test_stm32_call_graph_if_present_is_consistent(stm32):
    """If a call graph was extracted from the STM32 fixture, its edges must be consistent."""
    if stm32.call_graph is None:
        pytest.skip("no call graph for this fixture")
    cg = stm32.call_graph
    for caller, entry in cg.items():
        for callee in entry["calls"]:
            assert callee in cg
            assert caller in cg[callee]["called_by"]


# ============================================================================
# Unit: _build_call_graph graph shape logic
# ============================================================================

_MOD = "memprobe.parsers.elf"


class TestBuildCallGraphShape:

    def _elf(self, has_dwarf: bool = True):
        elf = MagicMock()
        elf.has_dwarf_info.return_value = has_dwarf
        return elf

    def test_chain_a_calls_b_calls_c(self):
        forward = {"a": {"b"}, "b": {"c"}}
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=forward):
            result, _ = _build_call_graph(self._elf(), "EM_X86_64", [])

        assert result["a"]["calls"]     == ["b"]
        assert result["b"]["called_by"] == ["a"]
        assert result["b"]["calls"]     == ["c"]
        assert result["c"]["called_by"] == ["b"]
        assert result["c"]["calls"]     == []

    def test_diamond_pattern(self):
        # root -> left, right; left -> sink; right -> sink
        forward = {"root": {"left", "right"}, "left": {"sink"}, "right": {"sink"}}
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=forward):
            result, _ = _build_call_graph(self._elf(), "EM_X86_64", [])

        assert set(result["sink"]["called_by"]) == {"left", "right"}
        assert result["root"]["calls"]          == ["left", "right"]

    def test_disconnected_components_both_included(self):
        forward = {"a": {"b"}, "x": {"y"}}
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=forward):
            result, _ = _build_call_graph(self._elf(), "EM_X86_64", [])

        assert set(result.keys()) >= {"a", "b", "x", "y"}

    def test_single_edge_result_structure(self):
        forward = {"caller": {"callee"}}
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=forward):
            result, _ = _build_call_graph(self._elf(), "EM_X86_64", [])

        assert set(result.keys()) == {"caller", "callee"}
        assert result["caller"]["calls"]     == ["callee"]
        assert result["caller"]["called_by"] == []
        assert result["callee"]["calls"]     == []
        assert result["callee"]["called_by"] == ["caller"]


# ============================================================================
# Unit: _dwarf5_call_graph no-DWARF fast path
# ============================================================================

def test_dwarf5_call_graph_returns_none_without_dwarf():
    elf = MagicMock()
    elf.has_dwarf_info.return_value = False
    assert _dwarf5_call_graph(elf, {}) is None


# ============================================================================
# Unit: _dwarf5_call_graph DIE traversal (depth tracking + GNU call sites)
#
# Regression coverage for two bugs found against a real ESP32-S3 DWARF 4
# firmware: (1) pyelftools DIEs have no .depth attribute, so depth must be
# tracked manually via null DIEs; (2) GCC emits DW_TAG_GNU_call_site, not the
# DWARF 5 DW_TAG_call_site, with the callee in DW_AT_abstract_origin.
# ============================================================================


class _Attr:
    def __init__(self, value):
        self.value = value


class _DIE:
    def __init__(self, tag, offset=0, attributes=None, has_children=False, null=False):
        self.tag = tag
        self.offset = offset
        self.attributes = attributes or {}
        self.has_children = has_children
        self._null = null

    def is_null(self):
        return self._null


def _null():
    return _DIE(tag=None, null=True)


def _subprogram(name, offset, has_children=False):
    return _DIE("DW_TAG_subprogram", offset=offset,
                attributes={"DW_AT_name": _Attr(name.encode())},
                has_children=has_children)


def _elf_with_dies(dies, cu_offset=0):
    cu = MagicMock()
    cu.cu_offset = cu_offset
    cu.iter_DIEs.return_value = iter(dies)
    dwarf = MagicMock()
    dwarf.iter_CUs.return_value = iter([cu])
    elf = MagicMock()
    elf.has_dwarf_info.return_value = True
    elf.get_dwarf_info.return_value = dwarf
    return elf


def test_dwarf5_call_site_forward_ref_resolved():
    """DWARF 5 DW_TAG_call_site, callee defined after the call (forward ref)."""
    dies = [
        _DIE("DW_TAG_compile_unit", has_children=True),
        _subprogram("foo", offset=100, has_children=True),
        _DIE("DW_TAG_call_site", attributes={"DW_AT_call_origin": _Attr(200)}),
        _null(),
        _subprogram("bar", offset=200),
        _null(),
    ]
    result = _dwarf5_call_graph(_elf_with_dies(dies), {})
    assert result == {"foo": {"bar"}}


def test_gnu_call_site_dwarf4_supported():
    """GCC DWARF 4 DW_TAG_GNU_call_site with callee in DW_AT_abstract_origin."""
    dies = [
        _DIE("DW_TAG_compile_unit", has_children=True),
        _subprogram("foo", offset=100, has_children=True),
        _DIE("DW_TAG_GNU_call_site", attributes={"DW_AT_abstract_origin": _Attr(200)}),
        _null(),
        _subprogram("bar", offset=200),
        _null(),
    ]
    result = _dwarf5_call_graph(_elf_with_dies(dies), {})
    assert result == {"foo": {"bar"}}


def test_call_site_outside_subprogram_ignored():
    """A call site with no enclosing subprogram yields no edges (None)."""
    dies = [
        _DIE("DW_TAG_compile_unit", has_children=True),
        _DIE("DW_TAG_GNU_call_site", attributes={"DW_AT_abstract_origin": _Attr(200)}),
        _subprogram("bar", offset=200),
        _null(),
    ]
    assert _dwarf5_call_graph(_elf_with_dies(dies), {}) is None


def test_caller_scope_exits_on_null_die():
    """After a subprogram's children close (null DIE), the next sibling's call
    sites must attribute to the sibling, not the previous caller."""
    dies = [
        _DIE("DW_TAG_compile_unit", has_children=True),
        _subprogram("foo", offset=100, has_children=True),
        _null(),  # closes foo's (empty) child list
        _subprogram("baz", offset=300, has_children=True),
        _DIE("DW_TAG_call_site", attributes={"DW_AT_call_origin": _Attr(100)}),
        _null(),  # closes baz
        _null(),  # closes compile_unit
    ]
    result = _dwarf5_call_graph(_elf_with_dies(dies), {})
    assert result == {"baz": {"foo"}}
    assert "foo" not in result  # foo made no calls


# ============================================================================
# Unit: _build_call_graph explicit status reasons
#
# Complete accuracy: an absent graph must always be accompanied by a plain
# explanation of why, never a silent None.
# ============================================================================


class TestCallGraphStatus:

    def _elf(self, has_dwarf=False):
        elf = MagicMock()
        elf.has_dwarf_info.return_value = has_dwarf
        return elf

    def test_dwarf_success_status_reports_source_and_count(self):
        with patch(f"{_MOD}._dwarf5_call_graph", return_value={"a": {"b"}}):
            graph, status = _build_call_graph(self._elf(True), "EM_X86_64", [])
        assert graph is not None
        assert "DWARF" in status
        assert "2 functions" in status  # a and b

    def test_capstone_success_status_mentions_disassembly(self):
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=None), \
             patch(f"{_MOD}._capstone_call_graph", return_value={"a": {"b"}}):
            graph, status = _build_call_graph(self._elf(), "EM_X86_64", [])
        assert graph is not None
        assert "capstone" in status.lower()

    def test_capstone_missing_status_has_install_hint(self):
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=None), \
             patch(f"{_MOD}._capstone_call_graph", side_effect=ImportError):
            graph, status = _build_call_graph(self._elf(), "EM_X86_64", [])
        assert graph is None
        assert "memprobe[callgraph]" in status

    def test_unsupported_arch_status_includes_reason(self):
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=None), \
             patch(f"{_MOD}._capstone_call_graph",
                   side_effect=ValueError("Xtensa call graph disassembly requires capstone 6 or newer")):
            graph, status = _build_call_graph(self._elf(), "EM_XTENSA", [])
        assert graph is None
        assert "not supported" in status.lower()
        assert "capstone 6" in status

    def test_empty_capstone_status_explains_no_direct_calls(self):
        with patch(f"{_MOD}._dwarf5_call_graph", return_value=None), \
             patch(f"{_MOD}._capstone_call_graph", return_value={}):
            graph, status = _build_call_graph(self._elf(), "EM_ARM", [])
        assert graph is None
        assert "no direct calls" in status.lower()
        assert "ARM" in status

    def test_empty_dwarf_status_explains_no_edges(self):
        with patch(f"{_MOD}._dwarf5_call_graph", return_value={}):
            graph, status = _build_call_graph(self._elf(True), "EM_X86_64", [])
        assert graph is None
        assert "no caller/callee edges" in status.lower()


def test_parse_populates_call_graph_status_in_binary_info():
    """The parse() integration must always set binary_info['call_graph_status']."""
    if not CG_ELF.exists():
        pytest.skip("firmware_callgraph_x86.elf fixture not present")
    mm = parse(CG_ELF)
    status = mm.binary_info.get("call_graph_status")
    assert isinstance(status, str) and status
    assert "DWARF" in status  # this fixture has DWARF call sites
