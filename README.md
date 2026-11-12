# ntrays-rs

A Rust rewrite of [NtRays](https://github.com/can1357/NtRays) by Can Bölük: a Hex-Rays microcode plugin that cleans up
Windows kernel decompilation. Targets IDA Pro 9.3, 9.4 and 9.5.

Work in progress. The original C++ plugin is the reference; the plan and the bug list are in the NtRays checkout's `PLAN.md`.

## Layout

- `core/` — IDA-independent rules and tables (paging bases, syscall tables, lifter rules). `cargo test` needs no IDA.
- `plugin/` — the plugin DLL: Rust plus a thin C++ shim (`src/shim.cpp`) for the IDA SDK classes.
- `tools/golden.py` — IDAPython batch script that decompiles a fixed set of ntoskrnl functions for diffing.

## Build (Windows, MSVC)

The DLL is built for one IDA version at a time, picked by the SDK you point `IDASDK` at: the `src` folder of
[HexRaysSA/ida-sdk](https://github.com/HexRaysSA/ida-sdk) at a release tag (`v9.3.1-release`, `v9.4.0-release`,
`v9.5.0-release`). Only `src/include`, `src/lib/x64_win_64` and `src/lib/x64_win_64_s` are needed.

```
set IDASDK=C:\path\to\ida-sdk\src
cargo build --release -p ntrays
```

Copy `target/release/ntrays.dll` into IDA's `plugins` folder (or `%APPDATA%\Hex-Rays\IDA Pro\plugins`).
The static CRT is required (`.cargo/config.toml`), because the SDK's `pro.lib` is built with `/MT`.

## License

BSD-3-Clause, same as upstream. Original code © 2021 Can Bölük; see [LICENSE](LICENSE).
