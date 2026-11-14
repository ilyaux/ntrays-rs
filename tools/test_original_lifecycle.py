"""Check original NtRays state across a saved IDB and a second idalib process.

Run with Python 3.11+ compatible with the local IDAPython installation. The input
IDB is copied once; all plugin changes and saves affect only the output copy.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def worker(config_path):
    cfg = json.loads(Path(config_path).read_text(encoding="utf-8"))
    sys.path.insert(0, str(Path(cfg["ida"]) / "idalib/python"))
    import idapro
    idapro.enable_console_messages(True)
    if idapro.open_database(cfg["database"], False):
        raise RuntimeError("could not open the private database copy")
    try:
        import ida_auto
        import ida_hexrays
        import ida_idaapi
        import ida_kernwin
        import ida_loader
        import ida_name
        import ida_netnode

        def snapshot():
            exists = ida_netnode.netnode.exist("$ ntrays")
            return {"node_exists": exists,
                    "slot0": int(ida_netnode.netnode("$ ntrays").altval(0)) if exists else None,
                    "actions": sorted(a for a in ida_kernwin.get_registered_actions() if a.startswith("ntrays:"))}

        result = {"phase": cfg["phase"], "ida_version": list(idapro.get_library_version()),
                  "before_plugin": snapshot()}
        if not ida_hexrays.init_hexrays_plugin():
            if not ida_loader.load_plugin("hexx64") or not ida_hexrays.init_hexrays_plugin():
                raise RuntimeError("x64 Hex-Rays unavailable")
        if not ida_loader.load_plugin(cfg["plugin"]):
            raise RuntimeError("original NtRays did not load")
        ida_auto.auto_wait()
        result["after_plugin"] = snapshot()
        addr = ida_name.get_name_ea(ida_idaapi.BADADDR, "KeYieldProcessorEx")
        if addr == ida_idaapi.BADADDR:
            raise RuntimeError("KeYieldProcessorEx is missing from the fixture")
        failure = ida_hexrays.hexrays_failure_t()
        cfunc = ida_hexrays.decompile(addr, failure, ida_hexrays.DECOMP_NO_CACHE)
        if not cfunc:
            raise RuntimeError(f"decompilation failed: {failure.desc()} at {failure.errea:X}")
        pseudocode = str(cfunc)
        Path(cfg["pseudocode"]).write_text(pseudocode + "\n", encoding="utf-8")
        result["hvl_call_present"] = "HvlNotifyLongSpinWait" in pseudocode
        result["hexrays_version"] = ida_hexrays.get_hexrays_version()
        # Release the cfunc before plugin/database teardown.
        del cfunc
    finally:
        idapro.close_database(True)
    result["close_database_save_completed"] = True
    write_json(cfg["result"], result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida", type=Path, required=True)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True, help="original NtRays DLL for this IDA")
    parser.add_argument("--output", type=Path, required=True, help="new directory outside the repository")
    args = parser.parse_args()
    args.ida, args.base, args.plugin, args.output = (p.resolve() for p in (args.ida, args.base, args.plugin, args.output))
    repo = Path(__file__).resolve().parent.parent
    if args.output == repo or repo in args.output.parents or args.output.exists():
        parser.error("use a new output directory outside the repository")
    source_hash = sha256(args.base)
    args.output.mkdir(parents=True)
    database = args.output / "database.i64"
    shutil.copyfile(args.base, database)
    write_json(args.output / "inputs.json", {"base": str(args.base), "base_sha256": source_hash,
        "plugin": str(args.plugin), "plugin_sha256": sha256(args.plugin), "script_sha256": sha256(__file__),
        "python": sys.version, "database_copy": str(database)})
    results = []
    for phase in (1, 2):
        user = args.output / f"idausr-{phase}"
        user.mkdir()
        cfg = {"phase": phase, "ida": str(args.ida), "database": str(database), "plugin": str(args.plugin),
               "result": str(args.output / f"phase-{phase}.json"),
               "pseudocode": str(args.output / f"phase-{phase}.c")}
        config_path = args.output / f"phase-{phase}-config.json"
        write_json(config_path, cfg)
        env = dict(os.environ, IDADIR=str(args.ida), IDAUSR=str(user))
        env.pop("IDA_IS_INTERACTIVE", None)
        with (args.output / f"phase-{phase}.log").open("w", encoding="utf-8") as log:
            subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--worker", str(config_path)],
                           cwd=args.output, env=env, stdout=log, stderr=subprocess.STDOUT,
                           timeout=180, check=True)
        results.append(json.loads(Path(cfg["result"]).read_text(encoding="utf-8")))
    assert sha256(args.base) == source_hash, "source fixture was modified"
    first, second = results
    assert first["after_plugin"]["slot0"] == 0 and not first["hvl_call_present"], "first open did not enable NtRays"
    persisted = second["before_plugin"]["slot0"]
    summary = {"self_disable_reproduced": persisted == 1 and second["after_plugin"]["slot0"] == 1 and second["hvl_call_present"],
               "enabled_state_preserved": persisted == 0 and second["after_plugin"]["slot0"] == 0 and not second["hvl_call_present"],
               "source_unchanged": True, "phases": results,
               "limit": "idalib close_database(save=True), not an interactive GUI close or explicit plugin unload"}
    write_json(args.output / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    if not (summary["self_disable_reproduced"] or summary["enabled_state_preserved"]):
        raise RuntimeError("lifecycle result is inconclusive; inspect the logs")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        worker(sys.argv[2])
    else:
        main()
