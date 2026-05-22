"""Firmware file parsers."""


def detect_iar(content: bytes) -> bool:
    """Return True if content looks like an IAR ELF Linker map file."""
    try:
        head = content[:4096].decode("utf-8", errors="replace")
        return "IAR" in head and "PLACEMENT SUMMARY" in head
    except Exception:
        return False
