# Changelog

## Unreleased

- Per-database settings dialog with a master switch, component controls, Hvl opt-in and log levels. Plugin unload preserves the chosen enabled state.
- Pseudocode actions for syscall API overrides, explicit Windows snapshots and ntdll/win32u map imports.
- Named NTSTATUS return/comparison constants from IDA's Windows type library and printable pool tags in recognized allocation/free calls. Explicit number formats and arithmetic widths are preserved.

## 0.1.0 — 2026-11-14 · Preview

Initial public Rust port of [NtRays](https://github.com/can1357/NtRays), targeting IDA Pro 9.3, 9.4 and 9.5 on Windows x64.

- Rust core and lifters behind a C++ IDA SDK bridge.
- Corrections for RCL/RCR, XGETBV, syscall numbering/signatures, and XSAVES/XRSTORS request masks.
- A guarded `KiKernelExit` interrupt-frame ABI fix for the ordered `KiChainedDispatch` call-analysis failure.
- Named syscall maps and per-address overrides scoped to each IDB, with explicit legacy-table provenance checks.
- Modern syscall snapshots, automatic map capture from an open ntdll/win32u IDB, and recorded data provenance.
- Reproducible local IDA regression tools, three-version Windows build CI, release archives with hashes/notices, and a documentation site.

Runtime validation covers IDA **9.3**: two final candidate passes decompiled **63/63** selected kernel functions with zero repeat differences; targeted native lifter checks covered 51 cases. IDA **9.4/9.5** are compile-checked. Settings and preset-selection menus remain on the [roadmap](ROADMAP.md). The fixture instructions were analyzed by IDA, not executed on hardware.
