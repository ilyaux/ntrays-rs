"""IDAPython batch script: decompile a fixed set of ntoskrnl functions into one .c file each.

    idat -A -S"golden.py select <out_dir>" ntoskrnl.exe   # pick functions, write <out_dir>/functions.json
    idat -A -S"golden.py use <out_dir> <functions.json>" ntoskrnl.exe

`select` picks functions that exercise each NtRays component (named ISRs, functions containing the
lifted instructions, users of the globals the optimizers fold), so the same list can be decompiled
with and without a plugin and diffed.
"""
import json, os, re, sys
import ida_allins, ida_auto, ida_bytes, ida_funcs, ida_hexrays, ida_ida, ida_name, ida_pro, ida_ua, idaapi, idautils, idc

BAD = idaapi.BADADDR
NAMED = [
    "KeYieldProcessorEx", "KiPageFault", "KiSystemCall64", "KiSystemCall64Shadow", "KiDpcInterrupt",
    "KiIpiInterrupt", "KiApcInterrupt", "KiBreakpointTrap", "KiGeneralProtectionFault", "KiSwInterrupt",
    "KiRaiseAssertion", "KxDebugTrapOrFault", "KiDispatchInterrupt", "KeStackAttachProcess",
    "PsGetThreadProcess", "MmAccessFault",
]
ITYPES = [
    "cpuid", "xgetbv", "xsetbv", "rcl", "rcr", "rdrand", "rdseed", "rdsspq", "vmread", "vmwrite", "vmlaunch",
    "vmxon", "invept", "swapgs", "iretq", "sysret", "syscall", "clac", "stac", "invpcid", "xsaves", "xrstors",
    "saveprevssp", "incsspq", "rstorssp", "prefetcht0", "int",
]
GLOBALS = ["KiIrqlFlags", "HvlEnlightenments", "HvlLongSpinCountMask", "PerfGlobalGroupMask", "MiFlags"]
CALLEES = ["MiPteHasShadow", "MiPteInShadowRange", "KiRemoveSystemWorkPriorityKick"]
RSB = "E8 0E 01 00 00 48 83 C4 08 E8 0E 01 00 00"
PER_KIND = 2


def func_name(ea):
    f = ida_funcs.get_func(ea)
    return ida_funcs.get_func_name(f.start_ea) if f else None


def paging_imm(v):
    return 0xFFFFF68000000000 <= v < 0xFFFFF70000000000 or v in (0xFFFFFA8000000000, 0xFFFFDE0000000000)


def select():
    picked = {}  # name -> reason

    def add(name, reason):
        if name and name not in picked:
            picked[name] = reason

    for n in NAMED:
        if ida_name.get_name_ea(BAD, n) != BAD:
            add(n, "named")

    wanted = {getattr(ida_allins, "NN_" + i): i for i in ITYPES if hasattr(ida_allins, "NN_" + i)}
    counts = {}
    insn = ida_ua.insn_t()
    for fea in idautils.Functions():
        for ea in idautils.FuncItems(fea):
            if not ida_ua.decode_insn(insn, ea):
                continue
            kind = wanted.get(insn.itype)
            if kind == "int":
                kind = "int2c" if insn.ops[0].value == 0x2C else None
            elif insn.itype == ida_allins.NN_mov and insn.ops[1].type == idaapi.o_imm and paging_imm(insn.ops[1].value):
                kind = "paging_imm"
            if kind and counts.get(kind, 0) < PER_KIND:
                name = func_name(fea)
                if name not in picked:
                    counts[kind] = counts.get(kind, 0) + 1
                    add(name, kind)

    for g in GLOBALS + CALLEES:
        ea = ida_name.get_name_ea(BAD, g)
        if ea == BAD:
            continue
        users = sorted({func_name(x.frm) for x in idautils.XrefsTo(ea)} - {None})
        for u in users[:PER_KIND]:
            add(u, "uses " + g)

    ea = ida_bytes.find_bytes(RSB, ida_ida.inf_get_min_ea())
    if ea != BAD:
        add(func_name(ea), "rsb_flush")
    return [{"name": n, "reason": r} for n, r in picked.items()]


def export_functions(funcs, out):
    """Export in manifest order; return explicit statuses for the regression runner."""
    ida_auto.auto_wait()
    os.makedirs(out, exist_ok=True)
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays decompiler unavailable")
    results = []
    filenames = set()
    for f in funcs:
        safe = re.sub(r"[^\w.-]", "_", f["name"])[:120] + ".c"
        if safe.casefold() in filenames:
            raise ValueError("colliding output filename: " + safe)
        filenames.add(safe.casefold())
        ea = ida_name.get_name_ea(BAD, f["name"])
        hf = ida_hexrays.hexrays_failure_t()
        error = None
        try:
            if ea == BAD:
                raise ValueError("function not found: " + f["name"])
            # DECOMP_NO_CACHE: the IDB caches pseudocode across plugin runs.
            cf = ida_hexrays.decompile(ea, hf, ida_hexrays.DECOMP_NO_CACHE)
            if cf:
                text = str(cf)
            else:
                error = "%s at %X" % (hf.desc(), hf.errea)
                text = "// decompile failed: " + error
        except Exception as e:
            error = str(e)
            text = "// decompile failed: " + error
        with open(os.path.join(out, safe), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("// %s (%s)\n%s\n" % (f["name"], f["reason"], text))
        results.append({"name": f["name"], "file": safe, "ea": hex(ea), "error": error})
        print("[golden] %d/%d %s: %s" % (len(results), len(funcs), f["name"], error or "ok"), flush=True)
    return results


def main():
    ida_auto.auto_wait()
    mode, out = idc.ARGV[1], idc.ARGV[2]
    os.makedirs(out, exist_ok=True)
    if mode == "select":
        funcs = select()
        with open(os.path.join(out, "functions.json"), "w", encoding="utf-8") as fh:
            json.dump(funcs, fh, indent=1)
    elif mode == "use":
        with open(idc.ARGV[3], encoding="utf-8") as fh:
            funcs = json.load(fh)
    else:
        raise ValueError("expected select or use")
    export_functions(funcs, out)
    ida_pro.qexit(0)


if __name__ == "__main__":
    main()
