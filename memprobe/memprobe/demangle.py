"""C++ symbol demangling.

Tries cxxfilt (Python binding to libiberty) first, then falls back to
invoking the system c++filt binary, then returns the name unchanged.
"""

from __future__ import annotations

import subprocess
from functools import lru_cache

try:
    import cxxfilt as _cxxfilt
    _HAVE_CXXFILT = True
except ImportError:
    _HAVE_CXXFILT = False


def is_mangled(name: str) -> bool:
    """Return True if the name looks like an Itanium-ABI mangled symbol."""
    return name.startswith(("_Z", "_GLOBAL__", "__Z"))


@lru_cache(maxsize=4096)
def demangle(name: str) -> str:
    """Return the demangled form of name, or name itself if not mangled / fails."""
    if not is_mangled(name):
        return name

    # Try the Python binding first (no subprocess overhead).
    if _HAVE_CXXFILT:
        try:
            result = _cxxfilt.demangle(name)
            if result and result != name:
                return result
        except Exception:
            pass

    # Fall back to the system c++filt binary.
    try:
        out = subprocess.run(
            ["c++filt", name],
            capture_output=True, text=True, timeout=2
        )
        result = out.stdout.strip()
        if result and result != name:
            return result
    except Exception:
        pass

    return name


def demangle_list(names: list[str]) -> list[str]:
    """Demangle a batch of names efficiently."""
    if not names:
        return []

    # Batch via c++filt for speed when cxxfilt is not available.
    if not _HAVE_CXXFILT:
        try:
            out = subprocess.run(
                ["c++filt"] + names,
                capture_output=True, text=True, timeout=10
            )
            results = out.stdout.splitlines()
            if len(results) == len(names):
                return results
        except Exception:
            pass

    return [demangle(n) for n in names]
