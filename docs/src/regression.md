# Reproducible regression tests

The runner compares a fixed sequence of functions across isolated IDA processes and an explicitly reviewed baseline. It keeps input fixtures and generated pseudocode outside the repository. [Validation results](validation.md) record the observed runs separately from this procedure.

## Requirements

- Python 3.11+ compatible with your IDAPython installation.
- A licensed local IDA 9.3 installation with the x64 Hex-Rays decompiler.
- The original NtRays DLL and Rust DLL built for that same IDA target.
- A pristine, analyzed, unmodified IDB for each fixture.

The runner uses `idapro` from IDA's bundled `idalib/python`; no pip package is needed. Building with the public SDK alone is insufficient to run this suite.

## Kernel suite

`tools/regression-functions.json` contains an ordered list of 63 ntoskrnl functions selected on Windows build `10.0.26100.9711`. Prepare your own binary/IDB fixtures; the repository does not distribute those binaries, databases, or decompiled code.

Run from the repository root, substituting your paths:

```powershell
py -3.11 -I tools/regression.py `
  --ida 'C:\Program Files\IDA Professional 9.3' `
  --base "$env:USERPROFILE\ntrays-build\golden\base.i64" `
  --plugin "$env:USERPROFILE\ntrays-build\cargo-ida93\release\ntrays.dll" `
  --original-plugin 'C:\fixtures\NtRays64.dll' `
  --output "$env:USERPROFILE\ntrays-build\regression-new"
```

The standard runner opens four fresh copies of the same IDB in separate idalib processes: no NtRays, original NtRays, Rust, and Rust again. Each gets an empty `IDAUSR` and explicitly loads the selected DLL. Functions are decompiled in manifest order with `DECOMP_NO_CACHE`; databases are closed without saving. The source IDB is never modified.

Manifest order fixes within-run order dependence. It does not claim that another order would produce identical pseudocode. The runner also checks that original NtRays is enabled and the Rust plugin uses default `FOLD_HVL=0`.

## Review and compare

Each output directory must be new. Results include:

- `inputs.json`: SHA-256 fingerprints of the IDB, scripts, DLLs, and IDA configuration.
- Per-process logs, per-function statuses, and pseudocode.
- `original-vs-rust.diff`, `summary.json`, `report.txt`, and a candidate `baseline.json`.

The first run exits **2 / REVIEW**. Inspect its diff and every reported failure before retaining its candidate as a reviewed reference. Differences from upstream can be intentional, including corrected XGETBV behavior and default-disabled Hvl folding.

For a later build, use a new output directory and add:

```text
--baseline C:\path\to\reviewed\baseline.json
```

| Result | Meaning |
|---|---|
| **0 / PASS** | Both Rust runs and the reviewed per-function hashes/errors match exactly |
| **1 / FAIL** | Rust repeats differ or output differs from the reference; worker failure also exits nonzero |
| **2 / REVIEW** | A candidate needs review before it can be treated as a reference |

The runner never overwrites the reference. Known reference failures remain visible: PASS means no output regression against that reference, not necessarily successful decompilation of every function. Missing functions, decompiler errors, and crashed workers cannot count as successful decompilations.

A change to the IDB, manifest order, scripts, Python version, or fingerprinted IDA files requires a new reviewed reference. The candidate Rust DLL hash is recorded but is allowed to change when evaluating a new build.

## Smaller ordered manifests

| Manifest | Fixture | Cases |
|---|---|---:|
| `tools/regression-ntdll.json` | Analyzed ntdll without NtRays | 4 syscall-signature functions |
| `tools/regression-rcl.json` | Analyzed synthetic RCL/RCR fixture without NtRays | 6 |
| `tools/regression-chained.json` | The kernel IDB | 2, in the order below |
| `tools/lifters_xstate_kernel.json` | The kernel IDB | Selected XSAVES/XRSTORS callers |

Supply `--functions <manifest>` and the corresponding IDB with `--base`. Each fixture has a separate output directory and reviewed baseline; do not compare different fixture sets against one another.

### Kernel-exit order reproducer

`regression-chained.json` decompiles `KiRestoreSetContextState` before `KiChainedDispatch`. The recognized kernel-mode `KiKernelExit` consumes an interrupt frame at RSP, rather than ordinary Win64 stack arguments. Its type is:

```text
void __usercall __noreturn KiKernelExit(void *frame@<rsp>)
```

The name, function start, and `push rax; push rdx; lea rax,[rsp+38h]` prologue must match. Explicit types are preserved. When the ABI is first applied, stale Hex-Rays-inferred types of direct callers are invalidated. The check also runs before call analysis to handle symbols loaded later from PDB.

## Targeted instruction probe

`tools/lifters_native_probe.py` assembles a small synthetic fixture with MSVC, then decompiles it twice. It never executes the privileged instructions. It records IDA/Hex-Rays versions, kernel mode, PE metadata, decoded instructions, and pseudocode.

```powershell
py -3.11 -I tools/lifters_native_probe.py --extended `
  --ida 'C:\Program Files\IDA Professional 9.3' `
  --plugin "$env:USERPROFILE\ntrays-build\cargo-ida93\release\ntrays.dll" `
  --output "$env:USERPROFILE\ntrays-build\lifters-new"
```

The default MSVC Build Tools path can be changed with `--vcvars`. Omit `--plugin` to inspect the local IDA configuration without NtRays. The extended plugin check asserts selected implicit register/flag outputs, zero extension, address-size overrides, 64-bit XSTATE masks, and deliberate GS-prefixed UMONITOR fallback. The two result sets must match exactly.

## Syscall state and original lifecycle

`tools/test_syscall_state.py --ida <IDA-dir> --plugin <ntrays.dll> --base <ntdll-none.i64> --output <new-dir>` checks IDB export maps, legacy migration, reopening/rebasing, and same-process IDB isolation. Its additional fixture options are listed by `--help`.

`tools/test_syscall_ui.py` exercises the production menu setters against copied databases. It checks read-only chooser data, Automatic and named overrides, presets, map disabling, two-DLL number-space merging, rebase, and refusal to overwrite corrupt/future/unconfirmed legacy state:

```powershell
py -3.11 -I tools/test_syscall_ui.py `
  --ida 'C:\Program Files\IDA Professional 9.3' `
  --plugin 'C:\build\ntrays.dll' --base 'C:\fixtures\ntdll-none.i64' `
  --ntdll 'C:\fixtures\ntdll.dll' --win32u 'C:\fixtures\win32u.dll' `
  --output "$env:USERPROFILE\ntrays-build\syscall-ui-new"
```

`tools/test_settings.py` checks real plugmod settings, normal-cache refresh, persistence without destructor writes, protected records, log levels and IDB isolation. Include `--kernel-base` for the Hvl/optimizer cache and warm-cache rebase check:

```powershell
py -3.11 -I tools/test_settings.py `
  --ida 'C:\Program Files\IDA Professional 9.3' `
  --plugin 'C:\build\ntrays.dll' --base 'C:\fixtures\ntdll-none.i64' `
  --kernel-base "$env:USERPROFILE\ntrays-build\golden\base.i64" `
  --output "$env:USERPROFILE\ntrays-build\settings-new"
```

These scripts test production behavior under idalib. Separately check the native GUI: Alt+F8, Cancel/OK, the popup on a call and a non-call expression, API selection/refresh, preset confirmation/decline, and the DLL file picker. A native GUI crash cannot be ruled out by successful setter tests alone.

`tools/test_original_lifecycle.py --ida <IDA-dir> --base <base.i64> --plugin <original-NtRays64.dll> --output <new-dir>` opens a copied IDB in two separate processes and saves between openings. It records original NtRays's `$ ntrays` slot 0, plugin actions, and observed decompilation behavior. This tests saved idalib closure, not an interactive GUI shutdown.

## Windows literal formatting

`tools/test_literals.py` builds a synthetic PE with MSVC and decompiles it in two independent idalib processes:

```powershell
py -3.11 -I tools/test_literals.py `
  --ida 'C:\Program Files\IDA Professional 9.3' `
  --plugin 'C:\build\ntrays.dll' `
  --output "$env:USERPROFILE\ntrays-build\literals-new"
```

This check requires IDA and MSVC; `--vcvars` can select another MSVC environment script. Fifteen functions cover NTSTATUS returns/comparisons, pool tags, unknown values/call targets, wrong argument positions and explicit user number formats. The test compares ctree operations, arithmetic types and values before/after formatting, normalizing only the explicit enum-to-original-width casts. It also checks repeated output, master/component switches with the normal cache, unchanged saved number formats, and preservation of a conflicting local `MACRO_STATUS` type. Privileged or generated fixture code is not executed.

## Instruction decoder fixture

```powershell
py -3.11 -I tools/test_decoder.py `
  --ida 'C:\Program Files\IDA Professional 9.3' `
  --plugin 'C:\build\ntrays.dll' `
  --output "$env:USERPROFILE\ntrays-build\decoder-new"
```

This requires IDA/Hex-Rays and MSVC. The runner loads the plugin before autoanalysis, assembles raw opcode bytes into a synthetic PE and decompiles 23 functions twice. It checks exact helper input widths/values, preserved GPRs/flags, FRED no-return flow and frame stores, ordinary CLAC passthrough, LKGS word loads/addressing, INVLPGB/TLBSYNC ordering, normal-cache toggles and zero patched-byte records. Twelve LKGS operand cases are compared with native `MOV r16,r/m16` decoding; the comparison allows equivalent displacement display widths. No fixture instruction is executed.

## Checks without IDA

```powershell
$env:CARGO_TARGET_DIR = "$env:USERPROFILE\ntrays-build\core-tests"
cargo test --locked
python -I tools/gen_syscall_presets.py --check --self-test
py -3.11 -I -m unittest discover -s tools -p test_regression.py -v
```

## Retain evidence, remove working copies

After every worker has exited, remove disposable per-run IDBs, unpacked database sidecars, and intermediate Cargo/SDK build directories created for the run. Resolve cleanup paths first and keep them within your intended temporary directory. Preserve the pristine reusable IDB, required fixture binaries/reference DLLs, current deliverable DLLs, reviewed manifests/baselines, pseudocode, logs, and concise reports. Record which working databases were removed so retained report paths remain understandable.
