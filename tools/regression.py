"""Run isolated idalib processes on fresh IDBs; keep pseudocode outside the repo."""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def worker(config_path):
    cfg = read_json(config_path)
    sys.path.insert(0, str(Path(cfg["ida"]) / "idalib/python"))
    import idapro
    idapro.enable_console_messages(True)
    rc = idapro.open_database(cfg["database"], False)
    if rc:
        raise RuntimeError("open_database failed: " + str(rc))
    try:
        import ida_auto
        import ida_hexrays
        import ida_loader
        import ida_nalt
        import ida_netnode
        if not ida_hexrays.init_hexrays_plugin():
            if not ida_loader.load_plugin("hexx64") or not ida_hexrays.init_hexrays_plugin():
                raise RuntimeError("cannot load x64 Hex-Rays")
        if cfg["plugin"] and not ida_loader.load_plugin(cfg["plugin"]):
            raise RuntimeError("cannot load plugin: " + cfg["plugin"])
        ida_auto.auto_wait()
        if cfg["mode"] == "original" and ida_netnode.netnode("$ ntrays").altval(0) != 0:
            raise RuntimeError("original NtRays is disabled in the base IDB")
        if cfg["mode"] == "rust" and ida_netnode.netnode("$ ntrays-rs").altval(2) != 0:
            raise RuntimeError("expected default FOLD_HVL=0")
        import golden
        rows = golden.export_functions(cfg["functions"], Path(config_path).parent / "pseudocode")
        for row in rows:
            row["sha256"] = sha256(Path(config_path).parent / "pseudocode" / row["file"])
        write_json(Path(config_path).parent / "result.json", {
            "ida_version": list(idapro.get_library_version()),
            "hexrays_version": ida_hexrays.get_hexrays_version(),
            "input_sha256": ida_nalt.retrieve_input_file_sha256().hex(),
            "functions": rows,
        })
    finally:
        idapro.close_database(False)


def compare(left, right):
    """Names/order are part of the contract, including failures and their exact error."""
    if [r["name"] for r in left] != [r["name"] for r in right]:
        raise ValueError("function names/order differ")
    return [a["name"] for a, b in zip(left, right)
            if (a["sha256"], a["error"]) != (b["sha256"], b["error"])]


def run_pass(root, label, mode, args, functions, plugin):
    work = root / label
    work.mkdir()
    database = work / "input.i64"
    shutil.copyfile(args.base, database)
    user = work / "idausr"
    user.mkdir()
    cfg = {"ida": str(args.ida), "database": str(database), "mode": mode,
           "plugin": str(plugin) if plugin else None, "functions": functions}
    write_json(work / "config.json", cfg)
    env = dict(os.environ, IDADIR=str(args.ida), IDAUSR=str(user), PYTHONHASHSEED="0")
    env.pop("IDA_IS_INTERACTIVE", None)
    print("Running " + label, flush=True)
    started = time.monotonic()
    with (work / "process.log").open("w", encoding="utf-8") as log:
        completed = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()),
                                    "--worker", str(work / "config.json")],
                                   cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT,
                                   timeout=args.timeout)
    if completed.returncode or not (work / "result.json").is_file():
        raise RuntimeError(f"{label} failed (exit {completed.returncode}); see {work / 'process.log'}")
    result = read_json(work / "result.json")
    if [r["name"] for r in result["functions"]] != [f["name"] for f in functions]:
        raise ValueError(label + ": incomplete function list")
    result["seconds"] = round(time.monotonic() - started, 2)
    print(f"{label}: {len(functions)} functions in {result['seconds']} s", flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida", type=Path, required=True, help="IDA installation directory")
    parser.add_argument("--base", type=Path, required=True, help="pristine, analyzed .i64 without NtRays")
    parser.add_argument("--functions", type=Path, default=Path(__file__).with_name("regression-functions.json"))
    parser.add_argument("--plugin", type=Path, required=True, help="Rust DLL built for this IDA")
    parser.add_argument("--original-plugin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new directory outside the repository")
    parser.add_argument("--baseline", type=Path, help="previous reviewed baseline.json; never updated automatically")
    parser.add_argument("--timeout", type=int, default=1800, help="seconds per process")
    args = parser.parse_args()
    for key in ("ida", "base", "functions", "plugin", "original_plugin", "output", "baseline"):
        value = getattr(args, key)
        if value:
            setattr(args, key, value.resolve())
    repo = Path(__file__).resolve().parent.parent
    if args.output == repo or repo in args.output.parents:
        parser.error("keep proprietary IDBs and pseudocode outside the repository")
    if args.output.exists():
        parser.error("output already exists; use a new directory (nothing is deleted)")
    functions = read_json(args.functions)
    if not functions or len({f["name"] for f in functions}) != len(functions):
        parser.error("function manifest must be nonempty with unique names")
    context = {
        "base_sha256": sha256(args.base), "functions_sha256": sha256(args.functions),
        "golden_script_sha256": sha256(Path(__file__).with_name("golden.py")),
        "runner_sha256": sha256(__file__), "python": platform.python_version(),
        "ida_files": {str(p.relative_to(args.ida)): sha256(p) for p in sorted(set(
            [args.ida / "ida.dll", args.ida / "idalib.dll"]
            + list((args.ida / "plugins").glob("*.dll"))
            + list((args.ida / "cfg").glob("*.cfg"))))},
        "settings": {"fold_hvl": False, "decomp_no_cache": True, "fresh_idb_per_pass": True},
    }
    baseline = read_json(args.baseline) if args.baseline else None
    if baseline and baseline["context"] != context:
        parser.error("baseline environment differs (base, order, scripts, Python, IDA or settings)")
    args.output.mkdir(parents=True)
    write_json(args.output / "inputs.json", {"context": context, "functions": functions,
        "plugins": {"rust_sha256": sha256(args.plugin), "original_sha256": sha256(args.original_plugin)},
        "arguments": {k: str(v) for k, v in vars(args).items()}})
    passes = {}
    for label, mode, plugin in [("none", "none", None), ("original", "original", args.original_plugin),
                                ("rust", "rust", args.plugin), ("rust-repeat", "rust", args.plugin)]:
        passes[label] = run_pass(args.output, label, mode, args, functions, plugin)
    rows = passes["rust"]["functions"]
    unstable = compare(rows, passes["rust-repeat"]["functions"])
    changed = compare(passes["original"]["functions"], rows)
    baseline_changes = compare(baseline["functions"], rows) if baseline else []
    failures = {r["name"]: r["error"] for r in rows if r["error"] is not None}
    original_failures = {r["name"] for r in passes["original"]["functions"] if r["error"] is not None}
    new_failures = [n for n in failures if n not in original_failures]
    status = "PASS" if baseline and not unstable and not baseline_changes else "REVIEW"
    if unstable or (baseline and baseline_changes):
        status = "FAIL"
    summary = {"status": status, "functions": len(rows), "unstable": unstable,
               "different_from_original": changed, "baseline_changes": baseline_changes,
               "rust_failures": failures, "new_failures_vs_original": new_failures,
               "passes": {label: {k: v for k, v in result.items() if k != "functions"}
                          for label, result in passes.items()}}
    write_json(args.output / "summary.json", summary)
    write_json(args.output / "baseline.json", {"context": context, "functions": rows})
    with (args.output / "original-vs-rust.diff").open("w", encoding="utf-8") as diff:
        for row in rows:
            if row["name"] in changed:
                name = row["file"]
                old = (args.output / "original/pseudocode" / name).read_text(encoding="utf-8").splitlines(True)
                new = (args.output / "rust/pseudocode" / name).read_text(encoding="utf-8").splitlines(True)
                diff.writelines(difflib.unified_diff(old, new, fromfile="original/" + name, tofile="rust/" + name))
    report = [f"NtRays regression: {status}", f"Functions: {len(rows)}",
              f"Rust repeat differences: {len(unstable)}", f"Different from original: {len(changed)}",
              f"Baseline changes: {len(baseline_changes)}", f"Rust failures: {len(failures)}",
              f"New failures vs original: {len(new_failures)}", "", json.dumps(summary, indent=2)]
    (args.output / "report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report[:7]), flush=True)
    return 1 if status == "FAIL" else (2 if status == "REVIEW" else 0)


if __name__ == "__main__":
    # -I excludes the script directory; add only our own helpers, never cwd.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        worker(sys.argv[2])
    else:
        sys.exit(main())
