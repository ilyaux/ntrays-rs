"""Live IDA 9.3 checks: IDB export map, legacy migration, reopen/rebase and same-process IDB isolation.

py -3.11 -I tools/test_syscall_state.py --ida <IDA-dir> --plugin <ntrays.dll> --base <ntdll-none.i64> --output <new-dir>
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

TEST_SCRIPT_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def map_blob(name):
    encoded = name.encode("ascii")
    return b"NTRSCM\x01\0" + struct.pack("<IIH", 1, 15, len(encoded)) + encoded


def read_map(blob):
    assert blob[:8] == b"NTRSCM\x01\0"
    count, = struct.unpack_from("<I", blob, 8)
    result, pos = {}, 12
    for _ in range(count):
        number, size = struct.unpack_from("<IH", blob, pos)
        pos += 6
        result[number] = blob[pos:pos + size].decode("ascii")
        pos += size
    assert pos == len(blob)
    return result


def worker(cfg):
    sys.path.insert(0, str(Path(cfg["ida"]) / "idalib/python"))
    import idapro
    import ida_auto, ida_bytes, ida_hexrays, ida_idaapi, ida_loader, ida_name, ida_netnode, ida_segment
    results = []
    names = re.findall(r'"(Nt\w+)"', (Path(__file__).resolve().parents[1] / "core/src/legacy_syscalls.rs").read_text().split("];", 1)[0])
    close_index, alert_index = names.index("NtClose") + 1, names.index("NtTestAlert") + 1
    profile = b"c7929397db55812e0307845e700169a0b36ff2687e992156c0207c16f054bc26"
    for database, expected in cfg["databases"]:
        assert idapro.open_database(database, False) == 0
        case = cfg["case"]
        try:
            if case == "win32u":
                if not ida_hexrays.init_hexrays_plugin():
                    assert ida_loader.load_plugin("hexx64")
                assert ida_loader.load_plugin(cfg["plugin"])
                ida_auto.auto_wait()
                node = ida_netnode.netnode("$ ntrays-rs syscall")
                active = node.altval(0)
                assert active in (1, 2)
                loaded = read_map(node.getblob(active - 1, ord("B")))
                assert len(loaded) > 1000 and all(0x1000 <= n < 0x2000 for n in loaded)
                assert "NtGdiGetPixel" in loaded.values()
                results.append({"case": case, "success": True, "map_size": len(loaded)})
                continue
            close = ida_name.get_name_ea(ida_idaapi.BADADDR, "NtClose")
            if close == ida_idaapi.BADADDR:
                close = ida_name.get_name_ea(ida_idaapi.BADADDR, "OpaqueClose")
            assert close != ida_idaapi.BADADDR
            call = close + ida_bytes.get_bytes(close, 32).index(b"\x0f\x05")
            legacy = ida_netnode.netnode("$ ntrays syscall", 0, True)
            old_blob = struct.pack("<HH", 16, 0) + struct.pack("<16H", *([0] * 15 + [close_index]))
            old_override = (alert_index << 16) | 16
            if case in ("legacy", "no-provenance", "wrong-provenance"):
                assert legacy.altset(0, 1)
                assert legacy.setblob(old_blob, 0, ord("B"))
                assert legacy.altset_ea(call, old_override)
                if case != "no-provenance":
                    node = ida_netnode.netnode("$ ntrays-rs syscall", 0, True)
                    assert node.supset(0, profile if case == "legacy" else b"0" * 64, ord("M"))
            if case == "unknown-legacy":
                old_blob = struct.pack("<HH", 16, 0) + struct.pack("<16H", *([0] * 15 + [65535]))
                assert legacy.altset(0, 1)
                assert legacy.setblob(old_blob, 0, ord("B"))
                assert ida_netnode.netnode("$ ntrays-rs syscall", 0, True).supset(0, profile, ord("M"))
            if case in ("prepare", "future"):
                node = ida_netnode.netnode("$ ntrays-rs syscall", 0, True)
                payload = map_blob("NtClose" if case == "future" else expected)
                if case == "future":
                    assert read_map(payload) == {15: "NtClose"}
                    valid_payload = payload
                    payload = payload[:6] + b"\x02" + payload[7:]
                    assert sum(a != b for a, b in zip(valid_payload, payload)) == 1
                assert node.setblob(payload, 0, ord("B"))
                assert node.altset(0, 1)
                initial_active = node.altval(0)
            if case == "reopen":
                assert legacy.setblob(b"broken old table", 0, ord("B"))
                assert legacy.altset_ea(call, 65535 << 16)
                ida_netnode.netnode("$ ntrays-rs syscall").supdel(0, ord("M"))
            assert ida_name.set_name(close, "OpaqueClose")
            if case in ("no-provenance", "wrong-provenance"):
                alert = ida_name.get_name_ea(ida_idaapi.BADADDR, "NtTestAlert")
                if alert == ida_idaapi.BADADDR:
                    alert = ida_name.get_name_ea(ida_idaapi.BADADDR, "ZwTestAlert")
                assert alert != ida_idaapi.BADADDR
                alert_call = alert + ida_bytes.get_bytes(alert, 32).index(b"\x0f\x05")
                assert legacy.altval_ea(alert_call) == 0
                assert ida_name.set_name(alert, "OpaqueAlert")
            if case != "prepare":
                if not ida_hexrays.init_hexrays_plugin():
                    assert ida_loader.load_plugin("hexx64")
                assert ida_loader.load_plugin(cfg["plugin"])
                ida_auto.auto_wait()
                node = ida_netnode.netnode("$ ntrays-rs syscall")
                hf = ida_hexrays.hexrays_failure_t()
                cf = ida_hexrays.decompile(close, hf, ida_hexrays.DECOMP_NO_CACHE)
                assert cf, hf.desc()
                text = str(cf)
                (Path(cfg["output"]) / (Path(database).parent.name + ".c")).write_text(text, encoding="utf-8")
                assert expected + "(" in text, text
                nt_helpers = sorted(set(re.findall(r"\b(Nt[A-Z]\w*)\s*\(", text)))
                if expected == "__syscall":
                    assert not nt_helpers, f"untrusted typed helper accepted: {nt_helpers}\n{text}"
                if case == "future":
                    assert node.altval(0) == initial_active, "future active pointer changed"
                    assert node.getblob(0, ord("B")) == payload, "future data overwritten"
                elif case == "unknown-legacy":
                    assert not node.altval(0), "unrecognized legacy map committed"
                    assert legacy.getblob(0, ord("B")) == old_blob
                elif case in ("no-provenance", "wrong-provenance"):
                    assert not node.altval(0), "unconfirmed legacy state committed"
                    assert legacy.getblob(0, ord("B")) == old_blob
                    assert legacy.altval_ea(call) == old_override
                    assert node.supval_ea(call, ord("S")) is None
                    alert_cf = ida_hexrays.decompile(alert, hf, ida_hexrays.DECOMP_NO_CACHE)
                    assert alert_cf, hf.desc()
                    alert_text = str(alert_cf)
                    alert_helpers = sorted(set(re.findall(r"\b(Nt[A-Z]\w*)\s*\(", alert_text)))
                    assert alert_helpers == ["NtTestAlert"], alert_text
                    assert node.altval(0) == 0, "in-memory auto-map was committed"
                    assert legacy.getblob(0, ord("B")) == old_blob
                    assert legacy.altval_ea(call) == old_override
                    assert legacy.altval_ea(alert_call) == 0
                    assert node.supval_ea(alert_call, ord("S")) is None
                    (Path(cfg["output"]) / "OpaqueAlert.c").write_text(alert_text, encoding="utf-8")
                    results.append({"case": case, "function": "OpaqueAlert", "helper": "NtTestAlert",
                                    "nt_helpers": alert_helpers, "active_pointer": 0, "in_memory_uncommitted": True,
                                    "success": True})
                else:
                    active = node.altval(0)
                    assert active in (1, 2)
                    loaded = read_map(node.getblob(active - 1, ord("B")))
                    assert loaded[15] == ("NtClose" if case in ("legacy", "reopen", "no-provenance", "wrong-provenance") else expected)
                    if case == "auto":
                        assert len(loaded) > 300, len(loaded)
                    if case == "legacy":
                        assert legacy.getblob(0, ord("B")) == old_blob
                        assert legacy.altval_ea(call) == old_override
                        assert b"NtTestAlert" in node.supval_ea(call, ord("S"))
                    if case == "reopen":
                        assert ida_segment.rebase_program(0x100000, ida_segment.MSF_FIXONCE) == 0
                        close = ida_name.get_name_ea(ida_idaapi.BADADDR, "OpaqueClose")
                        cf = ida_hexrays.decompile(close, hf, ida_hexrays.DECOMP_NO_CACHE)
                        assert cf and expected + "(" in str(cf), hf.desc()
                results.append({"case": case, "database": Path(database).parent.name, "function": "OpaqueClose",
                                "helper": expected, "nt_helpers": nt_helpers, "active_pointer": node.altval(0),
                                "success": True})
        finally:
            idapro.close_database(case in ("prepare", "legacy"))
    for row in results:
        row["test_script_sha256"] = TEST_SCRIPT_SHA256
    Path(cfg["result"]).write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("ida", "plugin", "base", "output"):
        p.add_argument("--" + key, type=Path, required=True)
    p.add_argument("--win32u", type=Path, help="optional raw local win32u.dll fixture")
    a = p.parse_args()
    a.ida, a.plugin, a.base, a.output = (value.resolve() for value in (a.ida, a.plugin, a.base, a.output))
    repo = Path(__file__).resolve().parents[1]
    if a.output == repo or repo in a.output.parents:
        p.error("keep IDBs and generated pseudocode outside the repository")
    if a.output.exists():
        p.error("output must be a new directory")
    a.output.mkdir(parents=True)
    for case in ("auto", "legacy", "isolation-a", "isolation-b", "future", "unknown-legacy", "no-provenance", "wrong-provenance"):
        work = a.output / case
        work.mkdir()
        shutil.copyfile(a.base, work / "input.i64")
    if a.win32u:
        (a.output / "win32u").mkdir()
        shutil.copyfile(a.win32u.resolve(), a.output / "win32u/win32u.dll")
    def run(case, databases):
        work = a.output / ("run-" + case)
        work.mkdir()
        cfg = {"ida": str(a.ida), "plugin": str(a.plugin), "case": case,
               "databases": [(str(a.output / d / ("win32u.dll" if d == "win32u" else "input.i64")), expected) for d, expected in databases],
               "output": str(work), "result": str(work / "result.json")}
        config = work / "config.json"
        config.write_text(json.dumps(cfg), encoding="utf-8")
        env = dict(os.environ, IDADIR=str(a.ida), IDAUSR=str(work))
        with (work / "process.log").open("w", encoding="utf-8") as log:
            process = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--worker", str(config)],
                                     env=env, stdout=log, stderr=subprocess.STDOUT, timeout=180)
        if process.returncode:
            raise RuntimeError(f"{case} failed: {work / 'process.log'}")
        print(case + ": PASS", flush=True)
    run("auto", [("auto", "NtClose")])
    run("legacy", [("legacy", "NtTestAlert")])
    run("reopen", [("legacy", "NtTestAlert")])
    run("prepare", [("isolation-a", "NtClose"), ("isolation-b", "NtTestAlert")])
    run("isolation", [("isolation-a", "NtClose"), ("isolation-b", "NtTestAlert")])
    run("future", [("future", "__syscall")])
    run("unknown-legacy", [("unknown-legacy", "__syscall")])
    run("no-provenance", [("no-provenance", "__syscall")])
    run("wrong-provenance", [("wrong-provenance", "__syscall")])
    if a.win32u:
        run("win32u", [("win32u", "")])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        worker(json.loads(Path(sys.argv[2]).read_text(encoding="utf-8")))
    else:
        main()
