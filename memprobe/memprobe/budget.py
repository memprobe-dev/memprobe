"""Per-module and per-section budget enforcement via memprobe.toml.

Configuration file format (memprobe.toml):

    [budgets]
    flash = "512KB"         # total flash budget
    ram   = "128KB"         # total RAM budget

    # Per-section budgets
    ".text"  = "400KB"
    ".bss"   = "64KB"

    # Per-module budgets (fnmatch glob against object_file path)
    "src/drivers/**" = "32KB"
    "src/ui/**"      = "64KB"
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .models import MemoryMap


# -- Size parser ----------------------------------------------------------------

_UNIT = {
    'b':  1,
    'kb': 1024,
    'mb': 1024 * 1024,
    'gb': 1024 * 1024 * 1024,
}


def parse_size(s: str) -> int:
    """Parse a human size string into bytes.

    Accepts: "512KB", "1MB", "131072", "1.5 MB"
    """
    s = s.strip()
    # Pure integer
    if s.isdigit():
        return int(s)
    import re
    m = re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]+)', s)
    if not m:
        raise ValueError(f"Cannot parse size: {s!r}")
    value = float(m.group(1))
    unit = m.group(2).lower()
    multiplier = _UNIT.get(unit)
    if multiplier is None:
        raise ValueError(f"Unknown size unit: {m.group(2)!r}")
    return int(value * multiplier)


# -- Data model -----------------------------------------------------------------

@dataclass
class BudgetViolation:
    """A single budget constraint that has been exceeded."""

    kind: str            # "flash", "ram", "section", or "module"
    label: str           # human-readable name (e.g. ".text", "src/drivers/**")
    budget: int          # limit in bytes
    actual: int          # actual usage in bytes
    overage: int         # actual - budget

    @property
    def budget_human(self) -> str:
        return _fmt(self.budget)

    @property
    def actual_human(self) -> str:
        return _fmt(self.actual)

    @property
    def overage_human(self) -> str:
        return _fmt(self.overage)

    @property
    def message(self) -> str:
        return (
            f"{self.label}: {self.actual_human} used, "
            f"budget is {self.budget_human} "
            f"(over by {self.overage_human})"
        )


def _fmt(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


# -- Config loader --------------------------------------------------------------

def load_config(search_path: Optional[Path] = None) -> dict:
    """Find and parse the nearest memprobe.toml, returning the raw config dict.

    Searches from search_path (or cwd) upward until the filesystem root.
    Returns an empty dict if no config is found.
    """
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return {}  # No TOML library available; silently skip budgets

    start = (search_path or Path.cwd()).resolve()
    candidates = [start, *start.parents]
    for directory in candidates:
        cfg_file = directory / "memprobe.toml"
        if cfg_file.is_file():
            try:
                return tomllib.loads(cfg_file.read_text(encoding='utf-8'))
            except Exception:
                return {}
    return {}


def load_budgets(search_path: Optional[Path] = None) -> dict[str, int]:
    """Return a flat {name: bytes} budget dict from the nearest memprobe.toml.

    Keys can be:
      "flash"         → total flash budget
      "ram"           → total RAM budget
      ".text"         → section-level budget
      "src/**"        → module glob budget
    """
    cfg = load_config(search_path)
    budgets_raw: dict = cfg.get("budgets", {})
    result: dict[str, int] = {}
    for key, val in budgets_raw.items():
        try:
            result[key] = parse_size(str(val))
        except ValueError:
            pass  # Skip unparseable entries
    return result


# -- Checker --------------------------------------------------------------------

def check_budgets(
    mmap: MemoryMap,
    budgets: dict[str, int],
) -> list[BudgetViolation]:
    """Check a MemoryMap against a budget dict. Returns all violations."""
    violations: list[BudgetViolation] = []

    # Total flash budget
    if "flash" in budgets:
        limit = budgets["flash"]
        actual = mmap.total_flash
        if actual > limit:
            violations.append(BudgetViolation("flash", "Flash", limit, actual, actual - limit))

    # Total RAM budget
    if "ram" in budgets:
        limit = budgets["ram"]
        actual = mmap.total_ram
        if actual > limit:
            violations.append(BudgetViolation("ram", "RAM", limit, actual, actual - limit))

    # Per-section budgets (keys starting with ".")
    sec_size_map = {s.name: s.size for s in mmap.sections}
    for key, limit in budgets.items():
        if not key.startswith('.'):
            continue
        # Support wildcard: ".text*" matches .text, .text.startup, etc.
        matched_size = sum(
            size for name, size in sec_size_map.items()
            if fnmatch.fnmatch(name, key)
        )
        if matched_size > limit:
            violations.append(
                BudgetViolation("section", key, limit, matched_size, matched_size - limit)
            )

    # Per-module glob budgets (keys not starting with "." and not flash/ram)
    reserved = {"flash", "ram"}
    module_globs = {
        k: v for k, v in budgets.items()
        if k not in reserved and not k.startswith('.')
    }
    if module_globs:
        for glob_pattern, limit in module_globs.items():
            total = sum(
                sym.size
                for sym in mmap.all_symbols
                if fnmatch.fnmatch(sym.object_file, glob_pattern)
            )
            if total > limit:
                violations.append(
                    BudgetViolation("module", glob_pattern, limit, total, total - limit)
                )

    return violations
