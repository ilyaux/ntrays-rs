# NtRays

NtRays is a Rust rewrite of [Can Bölük's NtRays](https://github.com/can1357/NtRays), a Hex-Rays microcode plugin for Windows kernel analysis. It turns selected instructions and kernel patterns into readable helpers, corrects recognized calling conventions, and keeps syscall information with the IDA database.

The current release is [**v0.2.0 Preview**](https://github.com/ilyaux/ntrays-rs/releases/tag/v0.2.0), with per-database settings, syscall selection menus, Windows constant formatting and legacy instruction decoder extensions. It targets Windows x64 IDA Pro 9.3, 9.4 and 9.5. Runtime regression testing currently covers **IDA 9.3**; the other two targets have been compiled and packaged. See the [compatibility table](installation.md#compatibility) before choosing a DLL.

Start with [installation](installation.md), or [build from source](build.md) if you have an IDA SDK checkout. The [features and limits](features.md) describe which transformations change your database and which instruction forms deliberately fall back to Hex-Rays.

For development, the [architecture](architecture.md) explains the Rust/C++ boundary. The [regression guide](regression.md) describes how to reproduce a result, while the [validation record](validation.md) separates observed results from untested configurations.

NtRays is a work in progress. A successful build or a readable helper does not establish correctness for every Windows build, instruction form, or database. Planned work belongs in the repository roadmap; it is not implied by a release package.

The code uses the BSD-3-Clause license, as does the original project. Original code is © 2021 Can Bölük. Syscall-data provenance and third-party notices are recorded separately in `data/syscall-presets-NOTICE.txt` and in release packages.
