# Changelog

## 0.2.0 — 2026-11-14 · Preview

- Per-database settings dialog with a master switch, component controls, Hvl opt-in and log levels. Plugin unload preserves the chosen enabled state.
- Pseudocode actions for syscall API overrides, explicit Windows snapshots and ntdll/win32u map imports.
- Named NTSTATUS return/comparison constants from IDA's Windows type library and printable pool tags in recognized allocation/free calls. Explicit number formats and arithmetic widths are preserved.
- Byte decoding and opaque helpers for legacy ERETS/ERETU, LKGS, WRMSRNS and INVLPGB/TLBSYNC forms on x64. FRED returns are no longer misidentified as CLAC; decoding and helpers do not patch the binary.
- Versioned package manifests, changelog-driven release notes and remapped build paths in release DLLs. The README, roadmap and installation/feature guides cover the integrated release.

The published IDA 9.3 DLL passed a fresh four-process kernel regression: **63/63** functions, zero errors, zero repeat differences and zero changes from the reviewed literal-formatting reference. Focused checks cover 23 decoder functions, 12 LKGS addressing comparisons, 51 existing lifter cases, 12 settings phases, six syscall-menu phases and 15 literal-formatting functions; the Rust core has 29 tests. SDK 9.4/9.5 compile and PE checks pass; licensed runtime checks remain pending. Instructions are analyzed, not executed on hardware. See [validation](docs/src/validation.md) for exact DLL hashes, earlier GUI coverage and remaining limits.

## 0.1.0 — 2026-11-14 · Preview

Initial public Rust port of [NtRays](https://github.com/can1357/NtRays), targeting IDA Pro 9.3, 9.4 and 9.5 on Windows x64.

- Rust core and lifters behind a C++ IDA SDK bridge.
- Corrections for RCL/RCR, XGETBV, syscall numbering/signatures, and XSAVES/XRSTORS request masks.
- A guarded `KiKernelExit` interrupt-frame ABI fix for the ordered `KiChainedDispatch` call-analysis failure.
- Named syscall maps and per-address overrides scoped to each IDB, with explicit legacy-table provenance checks.
- Modern syscall snapshots, automatic map capture from an open ntdll/win32u IDB, and recorded data provenance.
- Reproducible local IDA regression tools, three-version Windows build CI, release archives with hashes/notices, and a documentation site.

Runtime validation covers IDA **9.3**: two final candidate passes decompiled **63/63** selected kernel functions with zero repeat differences; targeted native lifter checks covered 51 cases. IDA **9.4/9.5** are compile-checked. Settings and preset-selection menus were added in v0.2.0. The fixture instructions were analyzed by IDA, not executed on hardware.
