"""Build and decompile synthetic privileged instructions; the fixture is never executed."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ASM = """.code
gs_thread PROC
 mov rax, gs:[188h]
 ret
gs_thread ENDP
gs_prcb PROC
 mov rax, gs:[20h]
 ret
gs_prcb ENDP
gs_pcr PROC
 mov rax, gs:[18h]
 ret
gs_pcr ENDP
cr8_read PROC
 mov rax, cr8
 ret
cr8_read ENDP
cr8_write PROC
 mov cr8, rcx
 ret
cr8_write ENDP
END
"""
NAMES = ["gs_thread", "gs_prcb", "gs_pcr", "cr8_read", "cr8_write"]
EXTENDED = {
    "vmfunc_case": "xor eax,eax\n xor ecx,ecx\n vmfunc",
    "vmresume_case": "vmresume",
    "vmcall_case": "mov rax,rcx\n vmcall",
    "vmrun_case": "mov rax,rcx\n vmrun rax",
    "vmload_case": "mov rax,rcx\n vmload rax",
    "vmsave_case": "mov rax,rcx\n vmsave rax",
    "clgi_case": "clgi",
    "stgi_case": "stgi",
    "rdpid_case": "rdpid rax",
    "rdpkru_case": "xor ecx,ecx\n rdpkru",
    "wrpkru_case": "mov eax,ecx\n xor ecx,ecx\n xor edx,edx\n wrpkru",
    "xsavec_case": "mov eax,edx\n mov edx,r8d\n xsavec [rcx]",
    "xsaveopt_case": "mov eax,edx\n mov edx,r8d\n xsaveopt [rcx]",
    "serialize_case": "serialize",
    "umonitor_case": "umonitor rcx",
    "umwait_case": "mov eax,edx\n mov edx,r8d\n umwait ecx\n setc al",
    "tpause_case": "mov eax,edx\n mov edx,r8d\n tpause ecx\n setc al",
    "enqcmd_case": "enqcmd rcx,zmmword ptr [rdx]\n setnz al",
    "uiret_case": "uiret",
    "senduipi_case": "senduipi rcx",
    "encls_case": "mov eax,ecx\n encls",
    "enclu_case": "mov eax,ecx\n enclu",
    "int2e_case": "mov eax,ecx\n int 2eh",
    "vmresume_cf": "vmresume\n setc al",
    "vmresume_zf": "vmresume\n setz al",
    "vmresume_of": "vmresume\n seto al",
    "umwait_zf": "mov eax,edx\n mov edx,r8d\n umwait ecx\n setz al",
    "enqcmd_cf": "enqcmd rcx,zmmword ptr [rdx]\n setc al",
    "rdpid_high": "rdpid rax\n shr rax,32",
    "rdpkru_edx": "xor ecx,ecx\n rdpkru\n shl rdx,32\n or rax,rdx",
    "xsavec64_case": "mov eax,edx\n mov edx,r8d\n xsavec64 [rcx]",
    "vmcall_rbx": "mov rbx,rdx\n mov rax,rcx\n vmcall\n mov rax,rbx",
    "encls_rbx": "mov rbx,rdx\n mov eax,ecx\n encls\n mov rax,rbx",
    "encls_zf": "mov eax,ecx\n encls\n setz al",
    "vmcall_cf_input": "stc\n vmcall\n setc al",
    "enclu_rdi": "mov rdi,rcx\n mov eax,2\n enclu\n mov rax,rdi",
    "enclu_rsi": "mov rsi,rcx\n mov eax,3\n enclu\n mov rax,rsi",
    "umonitor32_case": "mov rcx,1234567800000040h\n umonitor ecx",
    "umonitor_gs_case": "db 65h\n umonitor rcx",
    "xsaveopt64_case": "mov eax,edx\n mov edx,r8d\n xsaveopt64 [rcx]",
    "enqcmd32_case": "mov rcx,1234567800000040h\n mov rdx,1234567800000080h\n enqcmd ecx,zmmword ptr [edx]\n setz al",
    "xsaves_case": "mov eax,edx\n mov edx,r8d\n xsaves [rcx]",
    "xsaves64_case": "mov eax,edx\n mov edx,r8d\n xsaves64 [rcx]",
    "xrstors_case": "mov eax,edx\n mov edx,r8d\n xrstors [rcx]",
    "xrstors64_case": "mov eax,edx\n mov edx,r8d\n xrstors64 [rcx]",
    "xsavec32_area": "mov rcx,1234567800000040h\n mov eax,3\n mov edx,1\n xsavec [ecx]",
}


def worker(config):
    cfg = json.loads(Path(config).read_text())
    os.environ["IDADIR"] = cfg["ida"]
    os.environ["IDAUSR"] = cfg["user"]
    sys.path.insert(0, str(Path(cfg["ida"]) / "idalib/python"))
    import idapro
    assert idapro.open_database(cfg["binary"], True) == 0
    try:
        import ida_auto, ida_bytes, ida_funcs, ida_hexrays, ida_ida, ida_idaapi, ida_loader, ida_name, ida_typeinf, ida_ua, idautils
        ida_ida.inf_set_kernel_mode(True)
        if not ida_hexrays.init_hexrays_plugin():
            assert ida_loader.load_plugin("hexx64")
        assert ida_hexrays.init_hexrays_plugin()
        if cfg.get("plugin"):
            assert ida_loader.load_plugin(cfg["plugin"])
        ida_auto.auto_wait()
        Path(cfg["result"]).with_name("metadata.json").write_text(json.dumps({
            "ida_version": list(idapro.get_library_version()), "hexrays_version": ida_hexrays.get_hexrays_version(),
            "kernel_mode": ida_ida.inf_is_kernel_mode(), "bitness": 64 if ida_ida.inf_is_64bit() else 32,
            "filetype": ida_ida.inf_get_filetype(), "filetype_name": ida_loader.get_file_type_name(),
        }, indent=2), encoding="utf-8")
        rows = []
        for name in cfg["names"]:
            ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
            assert ea != ida_idaapi.BADADDR, name
            instructions = []
            for address in idautils.FuncItems(ea):
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, address):
                    instructions.append({"ea": hex(address), "itype": insn.itype,
                        "mnemonic": insn.get_canon_mnem(),
                        "bytes": ida_bytes.get_bytes(address, insn.size).hex(),
                        "operands": [{"type": insn.ops[i].type, "reg": insn.ops[i].reg, "dtype": insn.ops[i].dtype} for i in range(2)]})
            hf = ida_hexrays.hexrays_failure_t()
            cf = ida_hexrays.decompile(ea, hf, ida_hexrays.DECOMP_NO_CACHE)
            ti = ida_typeinf.tinfo_t()
            if cf:
                cf.get_func_type(ti)
            row = {"name": name, "text": str(cf) if cf else None,
                   "error": None if cf else hf.desc(), "type": str(ti),
                   "instructions": instructions}
            rows.append(row)
            print(json.dumps(row), flush=True)
        Path(cfg["result"]).write_text(json.dumps(rows, indent=2), encoding="utf-8")
    finally:
        idapro.close_database(False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--ida", type=Path, default=Path(r"C:\Program Files\IDA Professional 9.3"))
    p.add_argument("--vcvars", type=Path, default=Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"))
    p.add_argument("--plugin", type=Path)
    p.add_argument("--extended", action="store_true")
    a = p.parse_args()
    out = a.output.resolve()
    out.mkdir(parents=True)
    names = NAMES + (list(EXTENDED) if a.extended else [])
    extra = "".join(f"{n} PROC\n {body}\n ret\n{n} ENDP\n" for n, body in EXTENDED.items()) if a.extended else ""
    (out / "fixture.asm").write_text(ASM.removesuffix("END\n") + extra + "END\n")
    exports = " ".join("/export:" + n for n in names)
    build = f'@call "{a.vcvars}" >nul 2>&1\n@cd /d "{out}"\n@ml64 /nologo /c fixture.asm && link /nologo /dll /noentry /subsystem:native /out:fixture.dll fixture.obj {exports}\n'
    (out / "build.bat").write_text(build)
    subprocess.run(["cmd", "/c", str(out / "build.bat")], check=True, cwd=out)
    for mode in ("first", "repeat"):
        work = out / mode
        work.mkdir()
        shutil.copyfile(out / "fixture.dll", work / "fixture.dll")
        user = work / "idausr"
        user.mkdir()
        cfg = {"ida": str(a.ida.resolve()), "user": str(user), "binary": str(work / "fixture.dll"),
               "result": str(work / "result.json"), "plugin": str(a.plugin.resolve()) if a.plugin else None,
               "names": names}
        (work / "config.json").write_text(json.dumps(cfg))
        with (work / "process.log").open("w", encoding="utf-8") as log:
            subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--worker", str(work / "config.json")],
                           check=True, cwd=work, stdout=log, stderr=subprocess.STDOUT, timeout=120)
    first = json.loads((out / "first/result.json").read_text())
    repeat = json.loads((out / "repeat/result.json").read_text())
    assert first == repeat, "native outputs are not reproducible"
    native = {row["name"]: row for row in first}
    if not a.plugin:
        for name, helper in [("gs_thread", "KeGetCurrentThread"), ("gs_prcb", "KeGetCurrentPrcb"),
                             ("gs_pcr", "KeGetPcr"), ("cr8_read", "KeGetCurrentIrql"), ("cr8_write", "__writecr8")]:
            assert helper in (native[name]["text"] or ""), name
        for name, ty in [("gs_thread", "_KTHREAD"), ("gs_prcb", "_KPRCB"), ("gs_pcr", "KPCR")]:
            assert ty in native[name]["type"], name
    elif a.extended:
        assert all(r["error"] is None for r in first)
        assert all("__asm" not in r["text"] for r in first if r["name"] != "umonitor_gs_case")
        assert "__asm" in native["umonitor_gs_case"]["text"]
        for name, marker in [("vmresume_cf", "== 2"), ("vmresume_zf", "== 1"),
                             ("vmresume_of", "return 0;"), ("umwait_zf", "return 0;"),
                             ("enqcmd_cf", "return 0;"), ("rdpid_high", "return 0;"),
                             ("rdpkru_edx", "__rdpkru(0)"), ("xsavec64_case", "_xsavec64("),
                             ("xsaveopt_case", "__SPAIR64__"), ("xsaveopt64_case", "_xsaveopt64("),
                             ("xsaves_case", "_xsaves("), ("xsaves64_case", "_xsaves64("),
                             ("xrstors_case", "_xrstors("), ("xrstors64_case", "_xrstors64("),
                             ("umonitor32_case", "_umonitor("),
                             ("enqcmd32_case", "_enqcmd("),
                             ("xsavec32_area", "_xsavec("),
                             ("vmcall_rbx", "RBX(__vmcall_regs("), ("encls_rbx", "RBX(__encls_regs("),
                             ("enclu_rdi", "RDI(__enclu_regs("), ("enclu_rsi", "RSI(__enclu_regs("),
                             ("encls_zf", "ZF(__encls_regs("), ("int2e_case", "__syscall(")]:
            assert "".join(marker.split()) in "".join(native[name]["text"].split()), name
        assert "LODWORD" not in native["rdpkru_edx"]["text"] and "<<" not in native["rdpkru_edx"]["text"]
        flags = "".join(native["vmcall_cf_input"]["text"].split())
        assert "CF(__vmcall_regs(" in flags and ",1," in flags
        assert "12345678" not in native["umonitor32_case"]["text"]
        assert "12345678" not in native["enqcmd32_case"]["text"]
        area32 = native["xsavec32_area"]["text"]
        assert "12345678" not in area32 and ("0x100000003" in area32 or "4294967299" in area32)
        for name in ["xsavec_case", "xsavec64_case", "xsaveopt_case", "xsaveopt64_case",
                     "xsaves_case", "xsaves64_case", "xrstors_case", "xrstors64_case"]:
            assert "__SPAIR64__" in native[name]["text"], name
    print(json.dumps(first, indent=2))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        worker(sys.argv[2])
    else:
        main()
