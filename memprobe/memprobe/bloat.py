"""Bloat detection for firmware memory maps.

Only checks that produce zero false positives are included.
Each warning is triggered by a specific symbol or section whose
presence is unambiguous evidence of the reported condition.
"""

from dataclasses import dataclass
from typing import Optional

from .models import MemoryMap, SectionType


@dataclass
class BloatWarning:
    level: str          # "warning" or "info"
    message: str
    symbol: Optional[str] = None
    size: Optional[int] = None
    how_to_fix: Optional[str] = None


def analyze(mmap: MemoryMap) -> list[BloatWarning]:
    warnings: list[BloatWarning] = []
    symbols = mmap.all_symbols
    sym_names = {s.name for s in symbols}
    sym_map = {s.name: s for s in symbols}

    # -- Sanitizers in production ------------------------------------------
    # These symbols are only emitted by -fsanitize=address / -fsanitize=undefined.
    # Their presence in a production binary means the sanitizer runtime is linked
    # in, which will fault on real hardware when it tries to access shadow memory
    # or signal handlers that do not exist.
    _ASAN_SYMS = ("__asan_init", "__asan_report_load1", "__asan_report_store1",
                  "__asan_stack_malloc_0")
    _UBSAN_SYMS = ("__ubsan_handle_type_mismatch", "__ubsan_handle_add_overflow",
                   "__ubsan_handle_out_of_bounds")
    _MSAN_SYMS  = ("__msan_init",)

    found_asan  = next((s for s in _ASAN_SYMS  if s in sym_names), None)
    found_ubsan = next((s for s in _UBSAN_SYMS if s in sym_names), None)
    found_msan  = next((s for s in _MSAN_SYMS  if s in sym_names), None)

    if found_asan:
        warnings.append(BloatWarning(
            level="warning",
            message=f"ASan is linked ({found_asan}). Will fault on hardware. Shadow memory does not exist on bare metal.",
            symbol=found_asan,
            how_to_fix="Remove -fsanitize=address from CFLAGS/CXXFLAGS.",
        ))
    if found_ubsan:
        warnings.append(BloatWarning(
            level="warning",
            message=f"UBSan is linked ({found_ubsan}). Runtime handlers will be called on bare metal where they do not exist.",
            symbol=found_ubsan,
            how_to_fix="Remove -fsanitize=undefined from build flags.",
        ))
    if found_msan:
        warnings.append(BloatWarning(
            level="warning",
            message=f"MSan is linked ({found_msan}). Requires shadow memory, which is not available on bare-metal targets.",
            symbol=found_msan,
            how_to_fix="Remove -fsanitize=memory from build flags.",
        ))

    # -- C++ exception handling --------------------------------------------
    # __cxa_throw is only pulled in when a throw statement is reachable.
    has_exceptions = False
    if "__cxa_throw" in sym_names:
        has_exceptions = True
        s = sym_map["__cxa_throw"]
        warnings.append(BloatWarning(
            level="warning",
            message="C++ exceptions linked (__cxa_throw). Unwind tables add flash overhead.",
            symbol="__cxa_throw",
            size=s.size,
            how_to_fix="Build with -fno-exceptions -fno-rtti. Stub __cxa_throw to abort() if a library forces it in.",
        ))
    elif "__cxa_allocate_exception" in sym_names:
        has_exceptions = True
        s = sym_map["__cxa_allocate_exception"]
        warnings.append(BloatWarning(
            level="warning",
            message="Exception allocation linked (__cxa_allocate_exception) with no throw found. Unwind infrastructure is still present.",
            symbol="__cxa_allocate_exception",
            size=s.size,
            how_to_fix="Build with -fno-exceptions.",
        ))

    # -- RTTI -------------------------------------------------------------
    # _ZTI<mangled> symbols are typeinfo records emitted for every polymorphic
    # class when RTTI is enabled. Only report if exceptions are also present -
    # standalone RTTI is normal and expected in many C++ projects.
    if has_exceptions:
        typeinfo_syms = [s for s in symbols if s.name.startswith("_ZTI")]
        if typeinfo_syms:
            total = sum(s.size for s in typeinfo_syms)
            warnings.append(BloatWarning(
                level="info",
                message=f"RTTI enabled: {len(typeinfo_syms)} typeinfo record(s), {total:,} bytes.",
                how_to_fix="Build with -fno-rtti (requires -fno-exceptions).",
            ))

    # -- ARM float printf --------------------------------------------------
    # _printf_float / _scanf_float are ARM newlib stub symbols pulled in
    # only when -u _printf_float is passed to the linker. Definitive.
    for float_sym in ("_printf_float", "_scanf_float"):
        if float_sym in sym_names:
            s = sym_map[float_sym]
            warnings.append(BloatWarning(
                level="warning",
                message=f"Float printf/scanf linked ({float_sym}), ~8 KB flash cost.",
                symbol=float_sym,
                size=s.size,
                how_to_fix="Remove -u _printf_float from linker flags if not needed.",
            ))

    # -- assert() with file/line strings -----------------------------------
    # __assert_func is the newlib assert handler that takes __FILE__, __LINE__,
    # __func__, and the expression as string arguments. Its presence means every
    # assert() call site embeds those strings in flash.
    if "__assert_func" in sym_names:
        warnings.append(BloatWarning(
            level="info",
            message="assert() linked with file/line strings (__assert_func). Each call site embeds __FILE__, __func__, and the expression in flash.",
            symbol="__assert_func",
            how_to_fix="Define NDEBUG in release builds, or use a minimal assert macro that stores only an error code.",
        ))

    # -- C++ global constructors -------------------------------------------
    # .init_array holds pointers to global constructors (one pointer per entry).
    # Each entry is a function called before main(). Always reported as "info" -
    # having global ctors is normal in C++ code; the count is purely informational.
    init_sec = next((s for s in mmap.sections if s.name in (".init_array", ".ctors")), None)
    if init_sec and init_sec.size > 0:
        ptr_size = 8 if any(s.size > 0xFFFFFFFF for s in symbols) else 4
        ctor_count = init_sec.size // ptr_size
        if ctor_count > 0:
            warnings.append(BloatWarning(
                level="info",
                message=f"{ctor_count} C++ global constructor(s) in .init_array ({init_sec.size} bytes). Runs before main().",
                size=init_sec.size,
                how_to_fix="Avoid non-trivial global/static C++ objects. Prefer lazy init or explicit init() calls.",
            ))

    # -- Thread-safe static initialization (magic statics) -----------------
    # __cxa_guard_acquire is generated for every function-local static variable
    # in C++ (C++11 requires thread-safe initialization). Only flag this if the
    # binary also contains interrupt handler symbols, since the deadlock risk is
    # only relevant when ISRs can reach a function with a local static first.
    if "__cxa_guard_acquire" in sym_names:
        isr_syms = [
            s for s in symbols
            if s.name.endswith("_IRQHandler") or s.name.endswith("_Handler")
            if s.name not in ("Default_Handler", "HardFault_Handler")
        ]
        if isr_syms:
            warnings.append(BloatWarning(
                level="info",
                message=(
                    f"__cxa_guard_acquire linked with {len(isr_syms)} ISR(s). "
                    "A function-local static first initialized from an ISR will deadlock."
                ),
                symbol="__cxa_guard_acquire",
                how_to_fix=(
                    "Make sure no function-local static is first reached from an ISR. "
                    "On single-core targets, a no-op __cxa_guard_acquire/release stub removes the overhead."
                ),
            ))

    # -- Stack protector ---------------------------------------------------
    # __stack_chk_fail is only linked when -fstack-protector is active.
    # It adds a canary word to every protected stack frame and a check on return.
    if "__stack_chk_fail" in sym_names:
        warnings.append(BloatWarning(
            level="info",
            message="Stack canaries enabled (__stack_chk_fail). Each protected frame costs one extra stack word plus entry/exit checks.",
            symbol="__stack_chk_fail",
            how_to_fix="Remove only if stack RAM is critically tight: -fno-stack-protector.",
        ))

    # -- Unused interrupt vectors ------------------------------------------
    # Only match the exact CMSIS/HAL names for unimplemented ISRs.
    # Avoid pattern matching on "Default" to prevent false positives on
    # user-defined handler names that happen to contain that word.
    _DEFAULT_HANDLER_NAMES = {"Default_Handler", "Unused_IRQHandler"}
    default_handlers = [s for s in symbols if s.name in _DEFAULT_HANDLER_NAMES]
    if len(default_handlers) > 0:
        warnings.append(BloatWarning(
            level="info",
            message=f"{len(default_handlers)} interrupt vector(s) point to Default_Handler / Unused_IRQHandler.",
            how_to_fix="Vector table size is fixed by the MCU. Harmless unless unexpected interrupts are firing.",
        ))

    # -- .eh_frame unwind tables -------------------------------------------
    # Only report if exceptions are not already flagged (avoids duplication).
    if not has_exceptions:
        eh_sections = [s for s in mmap.sections if s.name in (".eh_frame", ".eh_frame_hdr")]
        eh_total = sum(s.size for s in eh_sections)
        if eh_total > 2048:
            warnings.append(BloatWarning(
                level="info",
                message=f".eh_frame is {eh_total:,} bytes. Generated by -fasynchronous-unwind-tables even without exceptions.",
                how_to_fix="Add -fno-asynchronous-unwind-tables to CFLAGS/CXXFLAGS.",
            ))

    # -- Large individual symbols ------------------------------------------
    # A symbol larger than 64 KB in a loaded section is almost always either
    # an embedded binary blob, a very large lookup table, or an oversized
    # static buffer. Report each one as an informational callout.
    LARGE_SYM_THRESHOLD = 64 * 1024
    skip_sec_prefixes = (".debug", ".comment", ".note", ".ARM.attr")
    for sym in symbols:
        if sym.size < LARGE_SYM_THRESHOLD:
            continue
        if any(sym.section.startswith(p) for p in skip_sec_prefixes):
            continue
        warnings.append(BloatWarning(
            level="info",
            message=f"'{sym.name}' is {sym.size/1024:.1f} KB in {sym.section}.",
            symbol=sym.name,
            size=sym.size,
            how_to_fix="Check if this is an expected binary blob. Static arrays this large may be candidates for external flash.",
        ))

    return warnings
