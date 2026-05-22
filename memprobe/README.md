# memprobe-viz

Firmware memory map visualizer for embedded systems engineers.

## Install

```bash
pip install memprobe-viz
```

## Usage

```bash
# Analyze a firmware build
memprobe analyze firmware.elf
memprobe analyze firmware.map

# Diff two builds
memprobe diff old.elf new.elf
memprobe diff old.map new.map --budget-flash 524288

# View build history
memprobe history list
```

## Features

- Parses GCC linker map files and ELF binaries
- Interactive HTML treemap report (click to zoom)
- Build diff with symbol-level change tracking
- SQLite build history
- Bloat detection heuristics
- GitHub Actions integration
