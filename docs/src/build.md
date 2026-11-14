# Build from source

Build the plugin on Windows with the MSVC x64 toolchain. The IDA-independent `core` crate can be tested without an IDA SDK, installation, or license.

## Requirements

- Rust **1.93.1** for the release recipe, with the `x86_64-pc-windows-msvc` target.
- Visual Studio 2022 C++ Build Tools, including the x64 compiler/linker and Windows SDK.
- PowerShell 7 for `tools/build_release.ps1`.
- Git and a matching checkout of the public [IDA SDK](https://github.com/HexRaysSA/ida-sdk).

Point `IDASDK` at the SDK's **`src`** directory. The build needs `src/include`, `src/lib/x64_win_64`, and `src/lib/x64_win_64_s`. The static CRT setting in `.cargo/config.toml` is required because the SDK's `pro.lib` uses `/MT`.

## Development build

Run from the repository root in a shell configured for MSVC x64:

```powershell
$env:IDASDK = 'C:\ida-sdk\src'
$env:CARGO_TARGET_DIR = "$env:USERPROFILE\ntrays-build\cargo-ida93"
cargo +1.93.1 build --release --locked -p ntrays
```

The DLL is then `$env:CARGO_TARGET_DIR\release\ntrays.dll`. Use a separate target directory for each SDK version. [Install](installation.md) it only into the matching IDA version.

The workspace defaults to `core`, so this needs no SDK:

```powershell
$env:CARGO_TARGET_DIR = "$env:USERPROFILE\ntrays-build\core-tests"
cargo +1.93.1 test --locked
```

## Release packages

The release script requires these exact, unmodified SDK commits:

| IDA | SDK release | Commit |
|---|---|---|
| 9.3 | `v9.3.1-release` | `acacbbcc8fa349d919cc185d88b1ab3710ca252d` |
| 9.4 | `v9.4.0-release` | `2348615c25f90e357cd2cc72fcfede1ba14ad41a` |
| 9.5 | `v9.5.0-release` | `04c0a982c80fd08388e7a3c26ff711fc1c38344d` |

Install/select Rust 1.93.1, then run with your own SDK path:

```powershell
rustup toolchain install 1.93.1 --profile minimal
rustup default 1.93.1
./tools/build_release.ps1 -IdaVersion '9.3' `
  -IdaSdk 'C:\ida-sdk-9.3\src' `
  -OutputDirectory "$env:USERPROFILE\ntrays-build\release-new"
```

Repeat for 9.4/9.5 with the corresponding SDK. Existing package, archive, or log paths are rejected; choose a fresh output directory for another build of the same target.

The script builds in a private temporary target directory, checks the `PLUGIN` export, `ida.dll` import and static MSVC runtime, then packages the DLL with the license, third-party notices, installation notes, PE checks, and a versioned source/DLL hash manifest. It remaps Rust source paths and rejects a DLL containing the local profile, source, SDK or Cargo root. It also rejects changing source files and mismatched or modified SDK checkouts. Intermediate build files are removed after success or failure; packages and logs remain.

These recorded inputs make the build inspectable. The MSVC tools and OS image can affect binary bytes, so the recipe does not promise identical DLL hashes across machines.

## Continuous integration

`.github/workflows/build.yml` builds the three targets on `windows-2022` for `main`, pull requests, manual runs, or a reusable-workflow call. Actions and SDK commits are pinned. The workflow validates committed syscall data offline, tests `core`, and uploads separate ZIP/checksum artifacts with 14-day retention. Local build logs are retained locally; they are excluded from uploaded artifacts and public release assets.

`.github/workflows/release.yml` handles pushed `v*` tags. The tag must equal `v` plus the workspace version in `Cargo.toml`. It reuses the build matrix and verifies ZIP/DLL hashes, tagged source revision, and matching source manifests before publishing exactly three SDK ZIPs and their three `.zip.sha256` files. All `0.x` versions and versions with a prerelease suffix are published as prereleases, without becoming the latest stable release. Release notes include the matching version section from `CHANGELOG.md`; a missing section stops publication.

Neither workflow runs the licensed IDA regression suite. A local build or workflow configuration does not demonstrate that GitHub Actions has run successfully or a release exists; inspect an actual run before making that claim.

For runtime checks, continue with [reproducible regression tests](regression.md).
