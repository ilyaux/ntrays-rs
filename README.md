<p align="center">
  <img src="docs/readme/mascot.png" width="280" alt="NtRays mascot: a grey cat in orange goggles and headphones, working on a Rust laptop.">
</p>

<h1 align="center">NtRays</h1>

<p align="center">
  <b>Windows internals, readable in Hex-Rays.</b><br>
  A Rust port of NtRays · IDA Pro 9.3 / 9.4 / 9.5 · Windows x64
</p>

<p align="center">
  <a href="https://github.com/ilyaux/ntrays-rs/releases"><img alt="Download preview" src="https://img.shields.io/badge/download-preview-B44A24"></a>
  <a href="https://github.com/ilyaux/ntrays-rs/actions/workflows/build.yml"><img alt="Windows builds" src="https://github.com/ilyaux/ntrays-rs/actions/workflows/build.yml/badge.svg"></a>
  <a href="https://ilyaux.github.io/ntrays-rs/"><img alt="Documentation" src="https://img.shields.io/badge/docs-online-1D4ED8"></a>
  <a href="LICENSE"><img alt="License: BSD-3-Clause" src="https://img.shields.io/badge/license-BSD--3--Clause-111113"></a>
  <img alt="Platform: Windows x64" src="https://img.shields.io/badge/platform-Windows%20x64-111113">
</p>

<p align="center">
  <b><a href="https://github.com/ilyaux/ntrays-rs/releases">Download</a></b>
  &nbsp;·&nbsp; <a href="https://ilyaux.github.io/ntrays-rs/">Documentation</a>
  &nbsp;·&nbsp; <a href="ROADMAP.md">Roadmap</a>
  &nbsp;·&nbsp; <a href="CHANGELOG.md">Changelog</a>
  &nbsp;·&nbsp; <a href="CONTRIBUTING.md">Contribute</a>
</p>

**NtRays** is a Rust port of [Can Bölük's NtRays](https://github.com/can1357/NtRays), a Hex-Rays microcode plugin for Windows internals. It turns low-level instructions into typed helpers, resolves syscall names and signatures, and simplifies patterns found in Windows kernels and drivers.

This is an early preview for **Windows x64**. It needs IDA Pro and the **x64 Hex-Rays decompiler**. Each IDA version has its own DLL.

## What changes in the decompiler

| Area | Behavior |
|---|---|
| **Hardware instructions** | Lift supported instructions into helpers with explicit inputs, outputs and flags. Includes CPUID, XGETBV, rotate-through-carry, VMX, XSTATE and selected newer instructions. |
| **Syscalls** | Resolve typed `Nt*` calls from a map belonging to the open database. Read syscall stubs from an open ntdll/win32u IDB; keep per-address overrides through save/reopen and rebase. |
| **Kernel structures** | Fix selected parent types, recognize paging bases and map `KUSER_SHARED_DATA`. Some GS and IRQL helpers are already supplied by Hex-Rays itself. |
| **Kernel patterns** | Simplify selected paging and scheduler expressions, and recognize the interrupt-frame ABI of `KiKernelExit`. Hvl branch folding is off by default. |
| **Database changes** | Use reversible IDA patches for RSB handling and preserve explicitly supplied types. Work on a copy of important databases. |

Compared with upstream, the port corrects RCL/RCR direction and immediate counts, XGETBV's high half, syscall numbering, and the full EDX:EAX mask for XSAVES/XRSTORS. The `KiChainedDispatch` call-analysis failure has a targeted ABI fix and an ordered reproducer.

## Checked, with limits

<img src="docs/readme/verification.svg" width="100%" alt="IDA 9.3: 63 of 63 selected kernel functions decompiled, zero differences between repeated candidate passes. 51 targeted native lifter cases. Three SDK build targets; runtime on IDA 9.4 and 9.5 is pending.">

The kernel sample uses Windows build **26100.9711**. The final integrated DLL decompiled all 63 selected functions in two fresh candidate processes with identical output. Four expected XSTATE changes were reviewed against the prior baseline; the no-plugin and original-plugin controls were reused after verifying their input fingerprints. This is a regression sample, not a claim of coverage for every Windows build or instruction.

| IDA Pro | Windows x64 build | Licensed runtime check |
|---|---|---|
| **9.3** | Yes | Kernel regression and targeted fixtures |
| **9.4** | Yes | Pending |
| **9.5** | Yes | Pending |

Hosted CI builds the DLLs and tests the Rust core. Licensed IDA/Hex-Rays checks run locally. See [validation scope](docs/src/validation.md) and [how to reproduce the regression](docs/src/regression.md).

## Install

1. [Download the preview](https://github.com/ilyaux/ntrays-rs/releases) and choose the ZIP for your **exact IDA version**: `ntrays-ida93`, `ntrays-ida94` or `ntrays-ida95`.
2. Close IDA. Extract the ZIP and copy `ntrays.dll` into `%APPDATA%\Hex-Rays\IDA Pro\plugins`.
3. Keep just one NtRays DLL in IDA's plugin search paths, then reopen IDA and your database.

Each archive includes installation notes, licenses, a source/DLL hash manifest and a `.sha256` companion for the ZIP. To uninstall, close IDA and remove the DLL. See [installation and troubleshooting](docs/src/installation.md).

## Build from source

Use Windows, PowerShell 7, Rust **1.93.1** and MSVC x64 Build Tools. The public [IDA SDK](https://github.com/HexRaysSA/ida-sdk) is sufficient to compile; IDA and Hex-Rays are required to use the plugin.

```powershell
git clone https://github.com/ilyaux/ntrays-rs.git
cd ntrays-rs
rustup toolchain install 1.93.1 --profile minimal
rustup override set 1.93.1

# Test the core without IDA or its SDK.
cargo test --locked

# Point to the src directory of the matching SDK release.
$env:IDASDK = 'C:\dev\ida-sdk\src'
cargo build --release --locked -p ntrays
```

The DLL is `target/release/ntrays.dll`. For checked, packaged builds, use [`tools/build_release.ps1`](tools/build_release.ps1); [the build guide](docs/src/build.md) lists the exact SDK commits and packaging commands.

## How it fits together

<img src="docs/readme/architecture.svg" width="100%" alt="IDA and Hex-Rays call a C++ SDK shim, which delegates to a Rust plugin and an IDA-independent core. The plugin supplies lifters, simplifications and per-database state.">

| Path | Responsibility |
|---|---|
| [`core/`](core/) | IDA-independent rules, PE syscall parser, versioned state codec and explicit syscall snapshots. |
| [`plugin/`](plugin/) | Rust lifters and database logic; a C++ shim owns SDK objects and dispatches callbacks. |
| [`tools/`](tools/) | Reproducible regression runners, fixture probes, generators and release packaging. |
| [`docs/`](docs/) | mdBook documentation and the SVGs used in this README. |

Syscall snapshots are selected explicitly; a Windows build family alone does not identify a servicing revision. The presets are available in the core API, while the selection menu is still planned. [Syscall maps](docs/src/syscalls.md) explains the distinction and the guarded migration of legacy IDBs.

## Next

The [roadmap](ROADMAP.md) tracks the remaining settings and syscall menus, runtime checks on IDA 9.4/9.5, and further kernel patterns. [Issues](https://github.com/ilyaux/ntrays-rs/issues) are welcome with the IDA version, DLL hash and a minimal reproducer. The [contribution guide](CONTRIBUTING.md) covers building, testing and what belongs in a public report.

## License and credits

[BSD-3-Clause](LICENSE). Original NtRays © 2021 **Can Bölük**; Rust port © 2026 **IK**. This project is an independent port and is not affiliated with Hex-Rays or Microsoft. Third-party data provenance is recorded in [NOTICE](NOTICE) and the [syscall data notice](data/syscall-presets-NOTICE.txt).
