# Installation and compatibility

NtRays runs inside IDA Pro on Windows x64 and requires the x64 Hex-Rays decompiler. It is not a standalone decompiler. An IDA SDK and compiler are only needed to [build from source](build.md).

## Compatibility

Each DLL is built for one IDA SDK version. Select the package that matches your IDA version; do not reuse a DLL across these targets.

| IDA target | SDK release | Local build/package check | Runtime validation |
|---|---|---|---|
| 9.3 | `v9.3.1-release` | Passed | IDA 9.3.260421 / Hex-Rays 9.3.0.260421 |
| 9.4 | `v9.4.0-release` | Passed | Not run |
| 9.5 | `v9.5.0-release` | Passed | Not run |

The tested analysis target is Windows x64 PE code, including the selected kernel fixture from build `10.0.26100.9711`. Other Windows revisions need their own validation. [Validation results](validation.md) describe the exact scope.

## Install a package

Download [v0.2.0 Preview](https://github.com/ilyaux/ntrays-rs/releases/tag/v0.2.0) for your exact IDA version, or create packages with the [release build script](build.md#release-packages). The package names are `ntrays-ida93-windows-x64.zip`, `ntrays-ida94-windows-x64.zip`, and `ntrays-ida95-windows-x64.zip`; each has an adjacent `.zip.sha256` checksum. Compare the ZIP's `Get-FileHash -Algorithm SHA256` result with that checksum before installing.

1. Close IDA.
2. Extract the matching Windows x64 ZIP and retain its manifest and notices.
3. Copy its `ntrays.dll` to `%APPDATA%\Hex-Rays\IDA Pro\plugins`. Create the directory if needed. IDA's installation `plugins` directory is another supported location.
4. Keep older Rust and original NtRays DLLs outside all IDA plugin search paths, so only the selected version loads.
5. Reopen IDA and the database, then decompile a function. Check the Output window for initialization or internal-error messages.

Press **Alt+F8** (or **Edit → Plugins → NtRays**) for [per-database settings](settings.md). In pseudocode, use **Set Windows version** to select an explicit syscall snapshot or import DLL stubs, and **Set syscall API** on a recognized syscall call to override its API. See [maps and presets](syscalls.md).

Back up an IDB before first use. Some transformations create segments, adjust recognized types, or apply reversible patches; [features and limits](features.md#database-changes) explains these changes.

## Upgrade or uninstall

Close IDA before replacing or removing the DLL. To uninstall, remove `ntrays.dll` from its plugin directory. Removing the DLL does not revert changes already saved in an IDB. Revert RSB patches through IDA's patch interface, or return to your database backup when you need the original analysis state.

The Rust plugin has its own per-IDB syscall storage. Moving from original NtRays may require [explicit legacy migration](migration.md); loading the new DLL does not prove which original syscall table an IDB used.

When upgrading from v0.1.0, existing syscall maps remain in the IDB and settings use defaults until saved. The new instruction decoder does not rewrite already analyzed code automatically: reanalyze an affected function and refresh pseudocode to replace a previous CLAC/unknown decode. Keep NtRays installed while working with its custom instruction types. See [decoder extensions](decoder.md) for supported encodings and fallback behavior.

## If the plugin does not load

Check the IDA version, the selected package, availability of the x64 Hex-Rays decompiler, and duplicate DLLs in both plugin directories. A DLL built with the public SDK can pass export/import checks without having been tested in your licensed runtime. Include those versions and the relevant Output-window message in a bug report.
