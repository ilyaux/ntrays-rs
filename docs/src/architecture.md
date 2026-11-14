# Architecture

The project separates rules that can be checked without IDA from the runtime that owns IDA SDK objects.

| Area | Responsibility |
|---|---|
| `core/` | IDA-independent paging rules, folding decisions, syscall signatures, snapshot tables, and persisted syscall-state codecs |
| `plugin/src/lib.rs` | Plugin state, guarded Rust entry points, per-IDB syscall loading/resolution, and database setup |
| `plugin/src/lift.rs` | Instruction recognition and microcode emission |
| `plugin/src/mc.rs` | Rust emitter interface and declarations shared with the shim |
| `plugin/src/shim.cpp` | C++ SDK objects, hooks, database access, and the plugin export |
| `tools/` | Offline data checks, build/package recipe, isolated IDA workers, and regression comparison |
| `data/` | Syscall snapshot provenance and attribution |

## The Rust/C++ boundary

The C++ shim owns SDK classes such as microcode instructions, operands, types, and call descriptions. Rust refers to builder-owned objects through small handles rather than taking ownership of SDK pointers. The builder commits successful emission into the current block. Recognition checks must happen before operations such as effective-address generation that already emit microcode.

Rust entry points catch panics and report internal errors to IDA's Output window. The C++ side guards exceptions. On a rejected instruction or guarded failure, the hook falls back instead of allowing Rust unwinding across the C++ boundary.

Instruction and opcode tables must match Rust enum order exactly. The plugin compares table names at initialization and refuses a mismatch. When adding an opcode or instruction, update both declarations together.

## Runtime state

The plugin is an IDA `PLUGIN_MULTI` plugin: each database has its own Rust state. Syscall maps and per-callsite overrides are read from the active IDB, not from a process-wide selected Windows version. Names and analysis events can invalidate cached decisions.

Database operations include mode-specific KUSER mapping, parent-type adjustments, and recognized RSB patches. The shim also applies the constrained `KiKernelExit` type at initialization and before call analysis, so symbols arriving later from PDB can be recognized. The [regression guide](regression.md#kernel-exit-order-reproducer) describes this ABI and its order-sensitive reproducer.

## Validation layers

`core` tests exercise rules and codecs with no SDK. SDK builds check the Rust/C++ boundary for each target version. Licensed idalib workers then check actual decompilation on fixed fixtures, in separate processes with isolated user directories. Their output is compared by reviewed per-function hashes.

These layers answer different questions: successful compilation is not runtime proof, and matching a reviewed baseline is not proof that every function or architectural effect is correct. [Validation results](validation.md) retain those distinctions.
