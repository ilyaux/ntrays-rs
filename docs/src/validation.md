# Validation results

This is the local validation record as of **2026-11-14**. It describes selected fixtures, not a universal compatibility claim. Licensed IDA databases, binaries, and pseudocode remain outside the repository; use the [regression procedure](regression.md) with your own authorized fixtures to reproduce the checks.

## Runtime environment

Runtime checks used IDA **9.3.260421** and Hex-Rays **9.3.0.260421** on Windows x64. The main kernel fixture comes from build `10.0.26100.9711`. The instruction fixture was analyzed as a 64-bit AMD64 PE in kernel mode. Privileged instructions were decompiled, never executed on the CPU.

| Check | Observed result | Scope |
|---|---|---|
| Kernel regression after settings/menu integration | 63/63 selected functions decompiled; 0 errors; 0 repeat differences; 0 reviewed-baseline changes | Four fresh processes: no NtRays, original, Rust, Rust repeat; fixed manifest order |
| Earlier kernel reference review | Four accepted changes, retained in the current reference | Corrected XSAVES/XRSTORS masks in `RtlXRestoreS`, `KxContextToKframes`, `RtlXSaveS`, `KeContextFromKframes` |
| Extended instruction probe | 51/51 cases decompiled; repeated JSON matched | One intentional assembly fallback: GS-prefixed UMONITOR |
| Ordered ntdll and RCL/RCR suites | 4/4 and 6/6; 0 errors, repeat differences or current-baseline changes | Four fresh modes per fixture |
| Per-database settings | 12/12 phases passed | Real plugmod settings, normal-cache invalidation, save/reopen, invalid records, log levels, isolation and kernel Hvl/rebase |
| Syscall menu state | 6/6 phases passed; previous state suite passed 12 checks in 10 processes | Production setters, overrides, map merging, corrupt/future/legacy guards and saved/rebased decompilation |
| Native IDA GUI | Listed popup, chooser, preset, import and settings checks passed | IDA 9.3; details below |
| SDK build/package targets | 9.3, 9.4, 9.5 passed local build checks | 9.4/9.5 runtime not tested |

These final checks use the IDA 9.3 DLL with SHA-256 `89a674572488e67f6b7cde01e9da89f952c903b3d8bc6c30f9e4e1041058aee2`. Package manifests fingerprint the compiled source files, including the settings and menu changes in the development checkout. The public `v0.1.0` preview does not contain these controls.

The kernel reference previously required review for four expected XSTATE changes; those changes were examined and accepted. The final four-mode run matches that reviewed reference. The older ntdll reference also reports four differences: typed `int 2e` and `syscall` branches now fold to the same helper. A separate `v0.1.0` control produced exactly the same four outputs as this candidate. The old raw comparison is retained as FAIL, while the final run matches the subsequently reviewed ntdll reference. REVIEW and an expected old-reference FAIL are not themselves test passes.

## Native interface checks

The fixed DLL was loaded into an isolated IDA 9.3 GUI process using its bundled Python 3.14.3; the idalib suites used Python 3.11.9. A syscall-call popup offered both actions, and selecting `NtTestAlert` in the API chooser immediately changed only the selected syscall. A non-call `KUSER_SHARED_DATA` expression offered the Windows-version action without the API action.

An initial GUI run exposed a null parent sentinel in the Hex-Rays call-selection visitor. The visitor now skips null items and parents. The former crash sequence (select a non-call expression, open the Windows chooser, select the last captured-snapshot row) reached confirmation successfully. Declining preserved the map bytes and active pointer; accepting committed the captured map. Importing `win32u.dll` through the native file picker succeeded and retained the NT number space. Alt+F8 opened the settings dialog, and Cancel preserved the settings record.

The native checks cover these interactions. Remaining preset rows, Automatic, invalid input and protected state were exercised through production setters under idalib; every native dialog path was not clicked manually.

## Instruction checks

The extended fixture includes meaningful uses of outputs after the target instruction, rather than only checking helper names. It covers selected VMRESUME status flags; WAITPKG and ENQCMD flags; RDPID/RDPKRU zero extension; opaque VMCALL and SGX register/flag dependencies; address-size overrides; and both halves of XSTATE masks, including the REX.W helper variants.

Fifty cases avoid assembly with the plugin. The remaining GS-prefixed UMONITOR case deliberately falls back because its segment-base address semantics are not modeled by that lifter. A local no-NtRays probe was also used to identify instructions already handled by IDA. That is evidence about the installed configuration, not an audit of a separately pristine IDA installation.

## Other focused checks

The development work also used the ordered ntdll syscall-signature, six-case RCL/RCR, and two-function KiChainedDispatch manifests, along with syscall-state persistence/isolation checks. These are separate fixture checks; their counts are not added to the 63-function kernel result.

The original plugin's save/reopen lifecycle was reproduced in separate idalib processes: after a saved close, `$ ntrays` slot 0 changed from enabled state `0` to disabled state `1`, with actions and decompilation behavior confirming the difference. This is an observation of the original DLL under idalib, not proof of every GUI-close or manual-unload path.

## Remaining limits

- IDA 9.4/9.5 have compile/package validation only.
- Scripted GUI exit saved and closed the test database, then stalled in Qt/IDAPython timer cleanup after NtRays had unloaded. A timer-related shutdown deadlock is suspected; no control run established the cause, and this is not a clean GUI-exit pass.
- Selected fixture outputs and repeated hashes do not prove every instruction encoding, Windows servicing revision, or architectural effect.
- Function-order changes require separate investigation; only the recorded manifest order was used for the reproducibility claim.
- Local build results do not prove a GitHub Actions run or a deployed Pages site. Inspect those external runs when available.

When reporting a new result, retain versions, hashes, manifest order, errors, repeat differences, and the reviewed baseline decision. Avoid describing an expected baseline delta as a clean match to the old reference.
