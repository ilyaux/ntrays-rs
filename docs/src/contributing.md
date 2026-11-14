# Contributing

Start by identifying the affected rule and its validation layer. A reproducible bug report should include the IDA/Hex-Rays version, matching plugin build, Windows fixture version or hash, function/instruction, relevant Output-window error, and the order needed to reproduce it. Share the smallest permitted reproducer; do not commit licensed binaries, IDBs, or decompiled code dumps.

## Choose the smallest useful check

Use `core` tests for IDA-independent rules, table parsing, and stored-state codecs. For changes to lifters, build the matching SDK target and add a focused case whose output is used after the instruction. Implicit registers, flags, operand width, and memory/address inputs need meaningful assertions. Preserve fallback when a form is not modeled.

For a cross-function analysis issue, add the required order to a regression manifest and use a pristine IDB copy. Review pseudocode differences before accepting a new baseline. See [reproducible regression tests](regression.md) for commands and failure semantics.

Keep C++/Rust instruction and opcode tables in the same order. Avoid unwinding across FFI. Separate observed instruction behavior from guessed operating-system or hypervisor ABIs. Build checks and licensed runtime checks should be reported separately.

## Source and artifacts

Keep fixture binaries, IDBs, generated pseudocode, and build directories outside the source tree, for example under `%USERPROFILE%\ntrays-build`. Preserve unrelated or pre-existing work in a shared checkout. After workers stop, clean disposable working copies and intermediate builds while retaining reviewed results and reusable inputs.

The code is BSD-3-Clause. Retain upstream attribution and third-party notices. Changes to syscall snapshots must update their pinned provenance and pass the offline generator check; see [maps and presets](syscalls.md).

## Documentation

The site uses **mdBook 0.4.52**, with the built-in light/navy themes and search. No extra preprocessor is required. Install that version from the [official release](https://github.com/rust-lang/mdBook/releases/tag/v0.4.52), or use:

```powershell
cargo install mdbook --version 0.4.52 --locked
mdbook build docs --dest-dir "$env:USERPROFILE\ntrays-build\docs-preview"
```

For a local preview:

```powershell
mdbook serve docs --dest-dir "$env:USERPROFILE\ntrays-build\docs-preview" --open
```

Add chapters to `docs/src/SUMMARY.md` and use relative links to other chapters. Review generated pages and resolve local links before submitting changes. The generated site is disposable; do not commit it.

`.github/workflows/docs.yml` checks documentation on pull requests and builds/deploys on documentation changes to `main` or a manual run on `main`. It downloads a checksum-verified mdBook 0.4.52 binary and uses commit-pinned official GitHub Pages actions. It does not need IDA or Rust compilation.

The planned site is `https://ilyaux.github.io/ntrays-rs/`. Repository maintainers must enable **Settings → Pages → Build and deployment → Source: GitHub Actions** and allow the `github-pages` environment before the first deployment. The workflow file and a local build do not establish that publication has happened.
