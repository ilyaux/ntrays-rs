# Driver Intelligence (in development)

Driver Intelligence will open a WDM x64 driver in IDA and produce a **Driver Overview**: how the driver is entered, the routines it registers in its `DRIVER_OBJECT`, the IRP dispatch table, the I/O control codes its device-control routine accepts, and the devices and symbolic links it creates. Every item links back to the code that proves it.

**Status:** the result contract and the `CTL_CODE` decoder exist in the Rust core. Discovery inside IDA, the native Overview and the cache are not implemented yet. Nothing on this page describes the output of a real analysis.

## Result contract

`ntrays_core::wdi::DriverOverview` is the single structure the IDA adapter fills, the core normalizes, and the UI, cache and JSON export read. The JSON layout carries `"schema": 1`; readers refuse versions they do not know.

| Part | Content |
|---|---|
| `input` | SHA-256, file name, image base (hex string), machine, PDB name/GUID/age when present |
| `frameworks` | WDM / KMDF / minifilter / NDIS indicators; several may be present at once |
| `entry_roots` | PE entry point and the real `DriverEntry` behind a wrapper such as `GsDriverEntry` |
| `callbacks` | `DriverUnload`, `AddDevice` (through `DriverExtension`), `DriverStartIo` |
| `irp` | One entry per `MajorFunction[major] = target` fact |
| `ioctls` | Codes compared against `IoControlCode`, with the dispatch routine and, when resolved, the code that runs |
| `devices` | Device names, symbolic links, interface GUIDs |
| `coverage` | Functions analyzed, budget exhaustion, cancellation, diagnostics |

Addresses are RVAs relative to `input.image_base`, so results stay valid after a rebase. The image base is a `"0x..."` string because kernel addresses do not fit a JSON number exactly.

### Evidence and confidence

Every fact carries one or more evidence records: the instruction RVA and its function, the helper functions on the way from the analysis root, the path conditions, where the structure layout came from (PDB, IDA type library, user type, or a built-in WDK layout), and a one-sentence reason.

| Status | Meaning |
|---|---|
| `found_in_code` | The store, comparison or call exists on at least one path in the code. This is a static fact, **not** a claim that the routine is active at runtime. |
| `assumed` | Inferred from a convention or pattern, not from a direct store or comparison. |
| `unresolved` | Something was seen but could not be resolved: an indirect target, an unknown layout, or the analysis budget ran out. |

Rules the contract enforces:

- "Not found" is never reported as "does not exist". Partial results say so in `coverage`.
- The same fact found twice is merged with both evidence lists. Different targets for one slot are kept side by side and reported as a conflict, not resolved by guessing.
- One routine serving several IRP slots appears once per slot. The device-control routine is a role, not a name.
- An I/O control code is listed only with evidence that it is compared against `IoControlCode`. NTSTATUS values, flag masks and codes the driver sends to other drivers are not inbound IOCTLs. What a command does is unknown unless separately proven.
- The same facts always serialize to the same bytes, whatever order they were discovered in.

[`wdi-overview.demo.json`](wdi-overview.demo.json) shows the format. It is **hand-written demo data**, not the result of analyzing a driver; a core test keeps it valid and canonical.

## Control codes

`ntrays_core::ioctl::CtlCode` splits a 32-bit value into the fields of `CTL_CODE(DeviceType, Function, Method, Access)` and back. It names the device type from the Windows SDK's `FILE_DEVICE_*` constants (hex otherwise), shows the vendor bits of the device type and function, and refuses 64-bit values that are neither zero- nor sign-extended 32-bit rather than truncating them. Decoding a number only explains it; it does not make it an IOCTL of the driver.

## MVP scope

| Supported (target of the MVP) | Not supported yet: reported as partial or unresolved, never as absent |
|---|---|
| PE32+ AMD64 WDM drivers | x86, ARM64 |
| `DriverEntry` reached from the PE entry directly or through a wrapper call | Entry through exported or dynamically resolved routines |
| `MajorFunction`, `DriverUnload`, `DriverStartIo` stores through the `DRIVER_OBJECT` parameter, including loops that fill every slot | Dispatch tables copied from data or aliased through other structures (#494) |
| `AddDevice` through `DriverObject->DriverExtension` | Registrations deeper than the helper-call budget |
| `IoControlCode` comparisons in the device-control routine: `if` chains, `switch` statements, subtraction chains | IOCTL codes computed at runtime; packed or obfuscated drivers |
| `IoCreateDevice` / `IoCreateSymbolicLink` with constant names | KMDF, minifilter and NDIS registrations (indicators only, #495, #496) |
| | Buffer and access analysis of IOCTL handlers (#497) |

Compatibility is claimed only for target layouts that have been checked. The first runtime platform is IDA/Hex-Rays 9.3; SDK 9.4/9.5 builds are tracked separately.

## Fixtures and acceptance

- Fixtures are our own driver sources written for this project. The sources and an expected-result manifest per fixture are in Git; built `.sys`, `.pdb`, IDA databases and generated reports are not.
- A manifest lists the exact expected facts and the values that must **not** appear: NTSTATUS constants, codes sent with `IoBuildDeviceIoControlRequest`, unrelated DWORDs.
- Each fixture is checked with and without its PDB. For supported forms the normalized result must equal the manifest exactly; unsupported forms must produce partial or unresolved results with a diagnostic, never a wrong fact.
- Results must be identical across repeated runs, and analysis must not change user names, types, comments or settings.

## Licensing

Driver Intelligence is an independent BSD-3-Clause implementation based on the Windows Driver Kit headers and documentation ([`DRIVER_OBJECT`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_driver_object), [`CTL_CODE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes)) and on our own fixtures. [DriverBuddyReloaded](https://github.com/voidsec/DriverBuddyReloaded) is licensed under PolyForm Noncommercial 1.0.0; none of its code or tables are copied.
