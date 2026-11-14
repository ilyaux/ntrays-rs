"""Generate x64 syscall release snapshots and an exact observed fixture snapshot.

Normal use is offline: python -I tools/gen_syscall_presets.py [--check]
--refresh re-extracts the three selected releases from the pinned j00ru files.
--capture NTDLL WIN32U reuses the core PE parser for the pinned local fixtures.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data/syscall-presets-x64.json"
OUTPUT = ROOT / "core/src/syscall_presets_data.rs"
REPOSITORY = "https://github.com/j00ru/windows-syscalls"
COMMIT = "8a6806ac9148633e8afbbdb42e6002930b002741"
FILES = {
    "nt-per-system.json": "a1998f5973cdff5fd2a28474e413a5074d66f65ab4555efc4b1911bf9f00e6ff",
    "win32k-per-system.json": "be333b3fc581f95463750f5a2b354c99ad4165198bcf7f0811e08cca33959043",
}
PRESETS = [
    {"id": "win11-24h2-x64", "label": "Windows 11 24H2 (x64)", "build": 26100,
     "source_release": "11 24H2", "nt": "nt_common", "win32k": "win32k_24h2"},
    {"id": "win11-25h2-x64", "label": "Windows 11 25H2 (x64)", "build": 26200,
     "source_release": "11 25H2", "nt": "nt_common", "win32k": "win32k_25h2"},
    {"id": "server-2025-x64", "label": "Windows Server 2025 (x64)", "build": 26100,
     "source_release": "Server 2025", "nt": "nt_common", "win32k": "win32k_server2025"},
    {"id": "captured-26100.9711-x64", "label": "Captured DLL stubs 10.0.26100.9711 (x64)", "build": 26100,
     "nt": "nt_captured_26100_9711", "win32k": "win32k_captured_26100_9711"},
]
CAPTURE = {
    "preset_id": "captured-26100.9711-x64", "file_version": "10.0.26100.9711",
    "ntdll_sha256": "651ac9041af8e6b5ebd331d53163244c0a27d36d1433f0f15cac1f28c5f2e82c",
    "win32u_sha256": "d46a695db805e808efa63d1095ce3e1b6be9c0155dad405d444530efc1ed0362",
    "parser_sha256": "7343f25d1d80e5751e36e8046e299da88313f5a4d5156a05d945ff38236ed53c",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def load(text):
    return json.loads(text, object_pairs_hook=unique_object)


def validate(data):
    if set(data) != {"source", "capture", "presets", "tables"}:
        raise ValueError("unexpected source schema")
    if data["source"] != {"repository": REPOSITORY, "commit": COMMIT, "files": FILES}:
        raise ValueError("source provenance differs from pinned commit/hashes")
    if data["presets"] != PRESETS:
        raise ValueError("unexpected release, label, build or table reference")
    if data["capture"] != CAPTURE:
        raise ValueError("captured fixture provenance differs")
    expected_tables = {p[k] for p in PRESETS for k in ("nt", "win32k")}
    if set(data["tables"]) != expected_tables:
        raise ValueError("unexpected or missing tables")
    for table_name, entries in data["tables"].items():
        if not isinstance(entries, dict) or not entries:
            raise ValueError("empty or invalid table: " + table_name)
        low = 0 if table_name.startswith("nt_") else 0x1000
        seen = set()
        for name, number in entries.items():
            if not re.fullmatch(r"Nt[A-Z][A-Za-z0-9_]*", name):
                raise ValueError("invalid Nt API name: " + name)
            if type(number) is not int or not low <= number < low + 0x1000:
                raise ValueError(f"invalid syscall number for {name}: {number!r}")
            if number in seen:
                raise ValueError(f"duplicate syscall number in {table_name}: {number}")
            seen.add(number)
    return data


def extract(upstream):
    tables = {}
    for preset in PRESETS[:3]:
        for kind, filename in (("nt", "nt-per-system.json"), ("win32k", "win32k-per-system.json")):
            entries = upstream[filename]["Windows 11 and Server"][preset["source_release"]]
            key = preset[kind]
            if key in tables and tables[key] != entries:
                raise ValueError("source tables no longer identical: " + key)
            tables[key] = entries
    return {"source": {"repository": REPOSITORY, "commit": COMMIT, "files": FILES},
            "presets": PRESETS, "tables": tables}


def refresh():
    upstream = {}
    for filename, expected_sha in FILES.items():
        url = f"https://raw.githubusercontent.com/j00ru/windows-syscalls/{COMMIT}/x64/json/{filename}"
        with urllib.request.urlopen(url, timeout=30) as response:
            raw = response.read()
        if hashlib.sha256(raw).hexdigest() != expected_sha:
            raise ValueError("upstream hash mismatch: " + filename)
        upstream[filename] = load(raw)
    return extract(upstream)


def file_version(path):
    """Read VS_FIXEDFILEINFO through Windows, without a second PE parser dependency."""
    import ctypes
    from ctypes import wintypes
    version = ctypes.WinDLL("version", use_last_error=True)
    version.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    version.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    version.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    version.GetFileVersionInfoW.restype = wintypes.BOOL
    version.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT)]
    version.VerQueryValueW.restype = wintypes.BOOL
    size = version.GetFileVersionInfoSizeW(str(path), None)
    if not size:
        raise ValueError("file has no version resource: " + str(path))
    buffer = ctypes.create_string_buffer(size)
    pointer, length = ctypes.c_void_p(), wintypes.UINT()
    if not version.GetFileVersionInfoW(str(path), 0, size, buffer) or not version.VerQueryValueW(buffer, "\\", ctypes.byref(pointer), ctypes.byref(length)):
        raise ctypes.WinError(ctypes.get_last_error())
    if length.value < 13 * ctypes.sizeof(wintypes.DWORD):
        raise ValueError("truncated VS_FIXEDFILEINFO")
    fields = ctypes.cast(pointer, ctypes.POINTER(wintypes.DWORD))
    if fields[0] != 0xFEEF04BD:
        raise ValueError("invalid VS_FIXEDFILEINFO signature")
    return ".".join(map(str, (fields[2] >> 16, fields[2] & 0xFFFF, fields[3] >> 16, fields[3] & 0xFFFF)))


def capture(paths):
    paths = [path.resolve() for path in paths]
    expected_hashes = [CAPTURE["ntdll_sha256"], CAPTURE["win32u_sha256"]]
    before = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
    if before != expected_hashes or any(file_version(path) != CAPTURE["file_version"] for path in paths):
        raise ValueError("capture DLL version/hash differs from the explicitly pinned fixture")
    parser_source = (ROOT / "core/src/syscall.rs").read_text(encoding="utf-8")
    if hashlib.sha256(parser_source.encode("utf-8")).hexdigest() != CAPTURE["parser_sha256"]:
        raise ValueError("core PE parser source differs; review before refreshing the capture")
    result = subprocess.run(["cargo", "run", "--locked", "--quiet", "-p", "ntrays-core", "--example",
                             "capture_syscall_stubs", "--", *map(str, paths)], cwd=ROOT,
                            check=True, capture_output=True, text=True)
    tables = {"nt_captured_26100_9711": {}, "win32k_captured_26100_9711": {}}
    for line in result.stdout.splitlines():
        kind, raw_id, name = line.split("\t")
        if kind not in ("nt", "win32k"):
            raise ValueError("unexpected capture domain: " + kind)
        table = tables[kind + "_captured_26100_9711"]
        if name in table:
            raise ValueError("duplicate captured API: " + name)
        table[name] = int(raw_id)
    if [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths] != before:
        raise ValueError("DLL changed during capture")
    return tables


def generate(data):
    validate(data)
    lines = ["// Generated by tools/gen_syscall_presets.py. Do not edit.",
             "// Factual syscall identifiers from j00ru/windows-syscalls; see data/syscall-presets-NOTICE.txt.",
             f"// Source commit: {COMMIT}", "", "use super::Preset;", ""]
    lines += ["pub const CAPTURE_SOURCE: super::CaptureSource = super::CaptureSource {"]
    lines += [f'    {key}: "{value}",' for key, value in sorted(data["capture"].items())]
    lines += ["};", ""]
    for key, entries in sorted(data["tables"].items()):
        lines += ["#[rustfmt::skip]", f"static {key.upper()}: &[(u32, &str)] = &["]
        lines += [f'    (0x{number:04X}, "{name}"),' for name, number in sorted(entries.items(), key=lambda e: e[1])]
        lines += ["];", ""]
    lines += ["pub static PRESETS: &[Preset] = &["]
    for preset in data["presets"]:
        lines += ["    Preset {", f'        id: "{preset["id"]}",',
                  f'        label: "{preset["label"]}",', f'        build: {preset["build"]},',
                  f'        nt: {preset["nt"].upper()}, win32k: {preset["win32k"].upper()},', "    },"]
    return "\n".join(lines + ["];", ""])


def self_test():
    import copy
    good = validate(load(DATA.read_text(encoding="utf-8")))
    for mutate in (
        lambda d: d["tables"]["nt_common"].update({"NtInvalid": 0x1000}),
        lambda d: d["tables"]["nt_common"].update({"NtInvalid": True}),
        lambda d: d["tables"]["nt_common"].update({"NtDuplicate": 0}),
        lambda d: d["presets"][0].update({"source_release": "11 26H2"}),
        lambda d: d["tables"].pop("win32k_24h2"),
        lambda d: d["capture"].update({"ntdll_sha256": "0" * 64}),
    ):
        bad = copy.deepcopy(good)
        mutate(bad)
        try:
            validate(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid data accepted")
    try:
        load('{"NtClose": 1, "NtClose": 2}')
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate JSON key accepted")
    print("generator validation self-test: OK")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify generated Rust without writing")
    parser.add_argument("--refresh", action="store_true", help="download only the pinned source files")
    parser.add_argument("--capture", nargs=2, type=Path, metavar=("NTDLL", "WIN32U"), help="Windows: capture the pinned fixture via the core PE parser")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.check and (args.refresh or args.capture):
        parser.error("--check is read-only; run --refresh/--capture separately")
    if args.self_test:
        self_test()
    data = load(DATA.read_text(encoding="utf-8"))
    if args.refresh:
        fresh = refresh()
        data["source"] = fresh["source"]
        data["tables"].update(fresh["tables"])
    if args.capture:
        data["capture"] = CAPTURE
        data["tables"].update(capture(args.capture))
    if args.refresh or args.capture:
        data["presets"] = PRESETS
    validate(data)
    rendered = generate(data)
    if args.refresh or args.capture:
        DATA.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.check:
        if OUTPUT.read_text(encoding="utf-8") != rendered:
            raise SystemExit("generated syscall_presets_data.rs differs")
        print("generated syscall presets: up to date")
    else:
        OUTPUT.write_text(rendered, encoding="utf-8", newline="\n")
        print("generated", OUTPUT)


if __name__ == "__main__":
    main()
