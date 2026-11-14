"""Exercise the production syscall UI setters in isolated idalib processes.

Native popup/chooser interactions are a separate GUI check. This runner uses the
same exported setters with a temporary Rust state, then verifies the saved IDB
in a fresh process with the actual plugin loaded.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys


def map_blob(name="NtClose"):
    data = name.encode("ascii")
    return b"NTRSCM\x01\0" + struct.pack("<IIH", 1, 15, len(data)) + data


def read_map(blob):
    assert blob[:8] == b"NTRSCM\x01\0"
    count, = struct.unpack_from("<I", blob, 8)
    result, pos = {}, 12
    for _ in range(count):
        number, length = struct.unpack_from("<IH", blob, pos)
        pos += 6
        result[number] = blob[pos:pos + length].decode("ascii")
        pos += length
    assert pos == len(blob)
    return result


def worker(cfg):
    sys.path.insert(0, str(Path(cfg["ida"]) / "idalib/python"))
    import idapro
    idapro.enable_console_messages(True)
    assert idapro.open_database(cfg["database"], False) == 0
    save, checks = False, []
    try:
        import ida_auto
        import ida_bytes
        import ida_hexrays
        import ida_idaapi
        import ida_loader
        import ida_name
        import ida_netnode
        import ida_segment
        assert ida_hexrays.init_hexrays_plugin() or (ida_loader.load_plugin("hexx64") and ida_hexrays.init_hexrays_plugin())
        ida_auto.auto_wait()
        close = ida_name.get_name_ea(ida_idaapi.BADADDR, "NtClose")
        if close == ida_idaapi.BADADDR:
            close = ida_name.get_name_ea(ida_idaapi.BADADDR, "OpaqueClose")
        assert close != ida_idaapi.BADADDR
        call = close + ida_bytes.get_bytes(close, 32).index(b"\x0f\x05")
        node = ida_netnode.netnode("$ ntrays-rs syscall", 0, True)
        case = cfg["case"]
        if case == "reopen":
            assert ida_loader.load_plugin(cfg["plugin"])
            def verify(ea):
                hf = ida_hexrays.hexrays_failure_t()
                cf = ida_hexrays.decompile(ea, hf, ida_hexrays.DECOMP_NO_CACHE)
                assert cf, hf.desc()
                calls = re.findall(r"\b(Nt[A-Za-z0-9_]+)\s*\(", str(cf))
                # The alternate INT 2E site can legitimately retain its own automatic NtClose mapping.
                assert "NtTestAlert" in calls, calls
                return hashlib.sha256(str(cf).encode()).hexdigest()
            assert verify(close) == verify(close)
            before = node.supval_ea(call, ord("S"))
            assert before and before.endswith(b"NtTestAlert")
            assert ida_segment.rebase_program(0x100000, ida_segment.MSF_FIXONCE) == 0
            assert node.supval_ea(call + 0x100000, ord("S")) == before
            verify(close + 0x100000)
            checks.append("saved override affects real decompilation and follows rebase")
        else:
            assert ida_name.set_name(close, "OpaqueClose")
            legacy = ida_netnode.netnode("$ ntrays syscall", 0, True)
            if case in ("future", "corrupt"):
                payload = map_blob()
                payload = payload[:6] + b"\x02" + payload[7:] if case == "future" else b"corrupt"
                assert node.setblob(payload, 0, ord("B")) and node.altset(0, 1)
            elif case == "legacy":
                assert legacy.altset(0, 2)
                assert legacy.altset_ea(call, (437 << 16) | 16)
            elif case == "site-corrupt":
                assert node.supset_ea(call, b"\x02\0\0\0\0\0\0\0", ord("S"))
            else:
                # Automatic must clear only the API, retaining this explicitly stored number.
                name = b"NtClose"
                assert node.supset_ea(call, struct.pack("<BBIH", 1, 1, 0x1234, len(name)) + name, ord("S"))

            dll = ctypes.CDLL(cfg["plugin"])
            p, u32, u64 = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint64
            signatures = {
                "ntrays_init": (p, []), "ntrays_term": (None, [p]),
                "ntrays_ui_api_count": (u32, []),
                "ntrays_ui_api_row": (ctypes.c_bool, [u32, u32, p, ctypes.c_size_t]),
                "ntrays_ui_api_selection": (ctypes.c_int64, [p, u64]),
                "ntrays_ui_preset_selection": (ctypes.c_int64, [p]),
                "ntrays_ui_set_api": (ctypes.c_bool, [p, u64, u32]),
                "ntrays_ui_set_preset": (ctypes.c_bool, [p, u32]),
                "ntrays_ui_import_map": (ctypes.c_bool, [p, ctypes.c_char_p]),
            }
            for name, (result, args) in signatures.items():
                fn = getattr(dll, name)
                fn.restype, fn.argtypes = result, args
            state = dll.ntrays_init()
            assert state
            try:
                def snapshot():
                    return (node.altval(0), node.getblob(0, ord("B")), node.getblob(1, ord("B")),
                            node.supval_ea(call, ord("S")), legacy.altval(0), legacy.altval_ea(call))
                initial = snapshot()
                names = []
                for index in range(dll.ntrays_ui_api_count()):
                    text = ctypes.create_string_buffer(4096)
                    assert dll.ntrays_ui_api_row(index, 0, text, len(text))
                    names.append(text.value.decode())
                alert_index = names.index("NtTestAlert")
                assert names[0] == "Automatic" and len(names) == len(set(names)) == 927
                dll.ntrays_ui_api_selection(state, call)
                dll.ntrays_ui_preset_selection(state)
                assert snapshot() == initial
                checks.append("chooser data and current selection are read-only")
                if case in ("future", "corrupt", "legacy"):
                    assert not dll.ntrays_ui_set_api(state, call, alert_index)
                    assert not dll.ntrays_ui_set_preset(state, 2)
                    assert not dll.ntrays_ui_import_map(state, cfg["ntdll"].encode())
                    assert snapshot() == initial
                    checks.append("protected map/legacy state refuses all UI writes")
                elif case == "site-corrupt":
                    assert not dll.ntrays_ui_set_api(state, call, alert_index)
                    assert not dll.ntrays_ui_set_api(state, call, 0)
                    assert snapshot() == initial
                    checks.append("corrupt per-EA override remains unchanged")
                else:
                    assert not dll.ntrays_ui_set_api(state, close, alert_index)
                    assert not dll.ntrays_ui_set_api(state, call, 0xFFFFFFFF)
                    assert not dll.ntrays_ui_set_preset(state, 1)
                    assert not dll.ntrays_ui_set_preset(state, 0xFFFFFFFF)
                    assert not dll.ntrays_ui_import_map(state, cfg["empty"].encode())
                    assert not dll.ntrays_ui_import_map(state, (cfg["empty"] + ".missing").encode())
                    assert snapshot() == initial
                    checks.append("invalid address, rows and empty/missing files do not mutate state")
                    assert dll.ntrays_ui_set_api(state, call, 0)
                    assert node.supval_ea(call, ord("S")) == struct.pack("<BBIH", 1, 1, 0x1234, 0)
                    assert dll.ntrays_ui_set_api(state, call, alert_index)
                    assert dll.ntrays_ui_api_selection(state, call) == alert_index
                    checks.append("Automatic keeps number; explicit API persists by name")
                    assert dll.ntrays_ui_set_preset(state, 2)
                    assert dll.ntrays_ui_preset_selection(state) == 2
                    assert len(read_map(node.getblob(node.altval(0) - 1, ord("B")))) == 1966
                    assert dll.ntrays_ui_set_preset(state, 0)
                    assert read_map(node.getblob(node.altval(0) - 1, ord("B"))) == {}
                    assert dll.ntrays_ui_import_map(state, cfg["ntdll"].encode())
                    nt = read_map(node.getblob(node.altval(0) - 1, ord("B")))
                    assert len(nt) > 300 and all(n < 0x1000 for n in nt)
                    assert dll.ntrays_ui_import_map(state, cfg["win32u"].encode())
                    merged = read_map(node.getblob(node.altval(0) - 1, ord("B")))
                    assert {n: v for n, v in merged.items() if n < 0x1000} == nt
                    assert sum(0x1000 <= n < 0x2000 for n in merged) > 1000
                    checks.append("explicit snapshot, disable and two-DLL space merge persist")
                    save = True
            finally:
                dll.ntrays_term(state)
        Path(cfg["result"]).write_text(json.dumps({"case": case, "status": "PASS", "checks": checks}, indent=2) + "\n")
    finally:
        idapro.close_database(save)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("ida", "plugin", "base", "ntdll", "win32u", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    values = {name: str(value.resolve()) for name, value in vars(args).items()}
    output = Path(values["output"])
    repo = Path(__file__).resolve().parents[1]
    if output.exists() or output == repo or repo in output.parents:
        parser.error("use a fresh output directory outside the repository")
    output.mkdir(parents=True)
    empty = output / "empty.dll"
    empty.write_bytes(b"")
    rows = []
    for case in ("edit", "reopen", "site-corrupt", "future", "corrupt", "legacy"):
        work = output / case
        work.mkdir()
        database = output / ("edit" if case == "reopen" else case) / "input.i64"
        if case != "reopen":
            shutil.copyfile(values["base"], database)
        cfg = dict(values, case=case, database=str(database), empty=str(empty), result=str(work / "result.json"))
        config = work / "config.json"
        config.write_text(json.dumps(cfg))
        with (work / "process.log").open("w", encoding="utf-8") as log:
            result = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--worker", str(config)],
                                    env=dict(os.environ, IDADIR=values["ida"], IDAUSR=str(work)),
                                    stdout=log, stderr=subprocess.STDOUT, timeout=180)
        if result.returncode:
            raise RuntimeError(f"{case} failed: {work / 'process.log'}")
        rows.append(json.loads(Path(cfg["result"]).read_text()))
        print(f"{case}: PASS", flush=True)
    summary = dict(status="PASS", plugin_sha256=hashlib.sha256(Path(values["plugin"]).read_bytes()).hexdigest(),
                   test_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), phases=rows,
                   scope="Production UI setters and saved state; native popup/chooser interaction is separate")
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        worker(json.loads(Path(sys.argv[2]).read_text()))
    else:
        main()
