# Validation results

This is the local validation record as of **2026-11-14**. It describes selected fixtures, not a universal compatibility claim. Licensed IDA databases, binaries, and pseudocode remain outside the repository; use the [regression procedure](regression.md) with your own authorized fixtures to reproduce the checks.

## Runtime environment

Runtime checks used IDA **9.3.260421** and Hex-Rays **9.3.0.260421** on Windows x64. The main kernel fixture comes from build `10.0.26100.9711`. The instruction fixture was analyzed as a 64-bit AMD64 PE in kernel mode. Privileged instructions were decompiled, never executed on the CPU.

| Check | Observed result | Scope |
|---|---|---|
| Integrated kernel candidate | 63/63 selected functions decompiled; 0 errors; two candidate passes matched exactly | Final Rust DLL, fixed manifest order |
| Previous kernel reference comparison | Four reviewed changes | Corrected XSAVES/XRSTORS masks in `RtlXRestoreS`, `KxContextToKframes`, `RtlXSaveS`, `KeContextFromKframes` |
| Extended instruction probe | 51/51 cases decompiled; repeated JSON matched | One intentional assembly fallback: GS-prefixed UMONITOR |
| SDK build/package targets | 9.3, 9.4, 9.5 passed local build checks | 9.4/9.5 runtime not tested |

The final integrated check reran the two Rust candidate passes. Its no-NtRays/original comparison context was retained from earlier runs and its input context checked; it was **not** a new four-mode run of the final DLL. The candidate comparison initially reported REVIEW because of the four expected XSTATE changes; those changes were examined and accepted as a new reference. REVIEW itself is not a test pass.

## Instruction checks

The extended fixture includes meaningful uses of outputs after the target instruction, rather than only checking helper names. It covers selected VMRESUME status flags; WAITPKG and ENQCMD flags; RDPID/RDPKRU zero extension; opaque VMCALL and SGX register/flag dependencies; address-size overrides; and both halves of XSTATE masks, including the REX.W helper variants.

Fifty cases avoid assembly with the plugin. The remaining GS-prefixed UMONITOR case deliberately falls back because its segment-base address semantics are not modeled by that lifter. A local no-NtRays probe was also used to identify instructions already handled by IDA. That is evidence about the installed configuration, not an audit of a separately pristine IDA installation.

## Other focused checks

The development work also used the ordered ntdll syscall-signature, six-case RCL/RCR, and two-function KiChainedDispatch manifests, along with syscall-state persistence/isolation checks. These are separate fixture checks; their counts are not added to the 63-function kernel result.

The original plugin's save/reopen lifecycle was reproduced in separate idalib processes: after a saved close, `$ ntrays` slot 0 changed from enabled state `0` to disabled state `1`, with actions and decompilation behavior confirming the difference. This is an observation of the original DLL under idalib, not proof of every GUI-close or manual-unload path.

## Remaining limits

- IDA 9.4/9.5 have compile/package validation only.
- Selected fixture outputs and repeated hashes do not prove every instruction encoding, Windows servicing revision, or architectural effect.
- Function-order changes require separate investigation; only the recorded manifest order was used for the reproducibility claim.
- Local build results do not prove a GitHub Actions run or a deployed Pages site. Inspect those external runs when available.

When reporting a new result, retain versions, hashes, manifest order, errors, repeat differences, and the reviewed baseline decision. Avoid describing an expected baseline delta as a clean match to the old reference.
