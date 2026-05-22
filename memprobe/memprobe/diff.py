"""Build diff engine - compare two firmware memory maps."""

from .models import MemoryMap, BuildDiff, SymbolDiff


def _aggregate(mmap: MemoryMap) -> dict[tuple[str, str], dict]:
    """Aggregate symbols by (name, section), summing sizes when duplicates exist.

    Why sum instead of pick-one: linker symbol tables frequently contain
    multiple entries that share a name within the same section (e.g. local
    `__func__` strings, anonymous statics, RTTI placeholders). Picking a
    single representative would make the diff order-dependent and would
    invent phantom deltas between two parses of byte-identical files. The
    correct unit of comparison is the total bytes that name occupies in
    that section.
    """
    agg: dict[tuple[str, str], dict] = {}
    for sym in mmap.all_symbols:
        key = (sym.name, sym.section)
        entry = agg.get(key)
        if entry is None:
            agg[key] = {
                'size': sym.size,
                'object_file': sym.object_file,
            }
        else:
            entry['size'] += sym.size
    return agg


def diff(old: MemoryMap, new: MemoryMap) -> BuildDiff:
    """Compare two MemoryMaps and return a BuildDiff.

    Symbols are matched by ``(name, section)``. When more than one symbol in
    a file shares that key, sizes are summed so the comparison is stable and
    deterministic for byte-identical inputs. Added symbols have ``old_size=0``,
    removed have ``new_size=0``. Results are sorted by ``abs(delta)``
    descending.
    """
    old_agg = _aggregate(old)
    new_agg = _aggregate(new)

    all_keys = set(old_agg) | set(new_agg)
    diffs: list[SymbolDiff] = []

    for key in all_keys:
        name, _section = key
        old_e = old_agg.get(key)
        new_e = new_agg.get(key)
        old_size = old_e['size'] if old_e else 0
        new_size = new_e['size'] if new_e else 0
        delta = new_size - old_size
        if delta == 0:
            continue
        diffs.append(SymbolDiff(
            name=name,
            object_file=(new_e or old_e)['object_file'],
            old_size=old_size,
            new_size=new_size,
            delta=delta,
        ))

    diffs.sort(key=lambda d: abs(d.delta), reverse=True)

    return BuildDiff(
        old_source=old.source_file,
        new_source=new.source_file,
        flash_delta=new.total_flash - old.total_flash,
        ram_delta=new.total_ram - old.total_ram,
        symbol_diffs=diffs,
    )
