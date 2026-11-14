# NtRays roadmap

The first public preview is **v0.1.0**. The aim is readable Windows kernel decompilation with explicit, reproducible behavior across supported IDA versions.

This public plan is a snapshot of the project board on **2026-11-14**. “Implemented / review” means code and checks exist; it does not mean every supported IDA version has been exercised at runtime. Milestones describe scope, not delivery dates.

| Stage | Goal | Status |
|---|---|---|
| **v0.1 · Preview** | Rust port, reproducible regression, versioned Windows packages and documentation | Implemented / review |
| **v0.2 · Daily workflow** | Settings and syscall selection in IDA; runtime checks on all three IDA versions | UI implemented / review; more runtimes pending |
| **Later · More kernel patterns** | Additional instructions and targeted simplifications | Planned |

## v0.1 · Implemented / review

| Work | Evidence / scope | Board reference |
|---|---|---|
| Rust workspace and C++ SDK bridge | Core tests without IDA; separate DLLs for SDK 9.3/9.4/9.5 | #378–382 |
| Upstream lifter corrections | RCL/RCR, XGETBV, syscall signatures, reversible RSB patches | #390–396 |
| Types and kernel simplifications | Paging bases, parent types, scheduler patterns, KUSER rebase | #395, #397–401 |
| Reproducible regression | Ordered 63-function kernel sample; fingerprinted inputs and repeat checks | #384 |
| `KiChainedDispatch` fix | Recognized `KiKernelExit` ABI, preserved explicit types, stale inferred caller types cleared | #460 |
| New decoder-supported instructions | Targeted native microcode probes; XSAVES/XRSTORS EDX:EAX mask retained | #404, #461 |
| Per-database syscall state | Named maps, overrides, reopen/rebase checks and guarded legacy migration | #387, #408 |
| Explicit modern syscall snapshots | Windows 11 24H2/25H2, Server 2025 and one exact captured revision | #407 |
| Public distribution | Three-SDK CI, preview release, SVG README and published documentation | #410, #411 |

See [validation](docs/src/validation.md) for what was actually run and what remains untested. GS/IRQL helpers already emitted correctly by Hex-Rays are kept rather than duplicated (#402, #403).

## v0.2 · Daily workflow

- [x] **Settings dialog and persistent toggles** (#383), implemented / review. Per-database component and log controls, cache refresh, and save/reopen/isolation checks; native Alt+F8 dialog checked on IDA 9.3.
- [x] **Set syscall API / Set Windows version menus** (#389), implemented / review. Explicit maps, API overrides, presets and DLL import; native selection and the non-call focus crash reproducer checked on IDA 9.3.
- [ ] **IDA 9.4 and 9.5 runtime checks** (#412). Repeat the licensed decompilation suites and inspect output on each exact version before extending the runtime support claim.

## Later · More kernel patterns

- [ ] **FRED, WRMSRNS, INVLPGB/TLBSYNC** (#405). Handle instructions missing from the decoder using narrowly recognized bytes and semantic fixtures.
- [ ] **Optional noise reduction** (#406). Investigate WIL feature flags, ETW/TraceLogging and Spectre/KVA patterns with a reviewed before/after corpus.
- [x] **NTSTATUS enums and pool-tag literals** (#409), implemented / review. Use the installed Windows status enum and known pool APIs; preserve 32-bit arithmetic and explicit user formats. See [constant formatting](docs/src/literals.md).

Requests and minimal reproducers belong in [GitHub issues](https://github.com/ilyaux/ntrays-rs/issues). The reference numbers above identify the existing project board; they are not GitHub issue numbers.
