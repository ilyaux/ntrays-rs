# Contributing

Start with the [architecture](docs/src/architecture.md), [build guide](docs/src/build.md) and [roadmap](ROADMAP.md). Changes to the Rust core can be developed without an IDA license or SDK.

```powershell
cargo test --locked
python -I tools/gen_syscall_presets.py --check --self-test
python -I -m unittest discover -s tools -p test_regression.py -v
```

For lifter or database changes, include a focused reproducer and run the relevant [local IDA regression](docs/src/regression.md). Record the exact IDA/Hex-Rays version, SDK, source revision and DLL hash. Explain any intentional output changes; a successful build alone does not validate decompiler behavior.

Keep reports small: describe the trigger, expected behavior, actual behavior and minimal steps. Share source for a synthetic fixture when possible. Check that attached logs contain no private paths or customer data. Microsoft binaries, IDA databases, SDK installations, license files and decompiled third-party source belong outside the repository.

Keep changes focused and preserve upstream attribution. Generated syscall data must pass the offline generator check and retain its provenance notice. Build outputs go outside the checkout; clean disposable databases and intermediate builds after their processes finish, keeping the inputs and concise reports needed to reproduce results.

See the [full contribution guide](docs/src/contributing.md) for local documentation builds and release checks.
