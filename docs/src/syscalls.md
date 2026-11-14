# Syscall maps and presets

Syscall IDs depend on the Windows snapshot. NtRays keeps the number-to-API map and per-address overrides separately for each IDB, using API names in its new storage format. An open ntdll/win32u database can supply a map from its exported syscall stubs.

## Available snapshots

The core API exposes four stable x64 snapshot IDs:

| Stable ID | Scope | NT / GUI entries |
|---|---|---:|
| `win11-24h2-x64` | Windows 11 24H2 release snapshot, build family 26100 | 489 / 1477 |
| `win11-25h2-x64` | Windows 11 25H2 release snapshot, build family 26200 | 489 / 1485 |
| `server-2025-x64` | Windows Server 2025 release snapshot, build family 26100 | 489 / 1480 |
| `captured-26100.9711-x64` | Export stubs from the exact `10.0.26100.9711` ntdll/win32u fixtures | 489 / 1498 |

Use the stable ID explicitly. The host OS or build family alone does not select a map. Windows 11 24H2 and Server 2025 both use family 26100 here but have different GUI tables, and servicing revisions can differ from a release snapshot.

For Rust callers, `ntrays_core::syscall_presets::find(id)` returns a preset; its `map()` returns an independently owned name-based map.

The captured entry is an observed stub map, not a marketing-release preset or complete SSDT. Exports without a syscall stub are absent. The checked-in notice records the exact fixture versions, hashes, parser hash, source commit, and attribution. Do not substitute unrelated DLLs and keep the same captured label.

## Select a map or API in IDA

These actions are available in the development checkout; the original `v0.1.0` preview does not include them. Enable the syscall component in [settings](settings.md).

- Right-click in pseudocode and choose **Set Windows version...** to select a named snapshot, disable the number-to-name map, or import an exact local ntdll/win32u DLL. Snapshot selection requires confirmation because servicing revisions can differ. Importing the second DLL replaces its own NT or GUI number space and preserves the other space.
- Right-click the syscall helper call and choose **Set syscall API...** to assign a typed API at that instruction. **Automatic** clears the explicit API override and restores resolution from the available number/map/function information. The action is offered only for a selected syscall instruction, including `int 2Eh`.

Accepting a selection updates the current database and refreshes decompilation. Canceling the chooser, file picker or confirmation makes no change. Save the IDB to retain the result. Unsupported or damaged map/override records are protected; the UI reports a failed change instead of replacing unknown data.

## Validate the committed data

From the repository root, without IDA, local Windows fixtures, or network access:

```powershell
python -I tools/gen_syscall_presets.py --check --self-test
```

To compare a snapshot with explicit DLLs, with Cargo output directed outside the repository:

```powershell
$env:CARGO_TARGET_DIR = "$env:USERPROFILE\ntrays-build\preset-check"
cargo run --locked -p ntrays-core --example check_syscall_preset -- `
  win11-24h2-x64 C:\fixtures\ntdll.dll C:\fixtures\win32u.dll
```

Exit 0 means exact equality, 1 reports differences, and 2 indicates invalid input. Differences between servicing revisions should be reported, not hidden by relabeling or automatic selection.

## Regenerate with provenance

`python -I tools/gen_syscall_presets.py --refresh` fetches the selected factual pairs from the pinned source and preserves the separate captured entry. It requires network access. `--capture <ntdll.dll> <win32u.dll>` re-captures the specific fixtures only after checking both file hashes, both versions, and the parser hash; it rejects changing inputs.

The source is [j00ru's Windows System Call Tables](https://github.com/j00ru/windows-syscalls), pinned to commit `8a6806ac9148633e8afbbdb42e6002930b002741`. Only the selected API names and numeric assignments are retained. `data/syscall-presets-NOTICE.txt` preserves attribution and does not assign the project's BSD license to upstream data.

For original NtRays index-based storage, follow [legacy migration](migration.md). Never assume an old index identifies the same API in a different generated table.
