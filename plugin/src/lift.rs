//! Instruction lifters: turn one x86 instruction into microcode, or return `false` to let Hex-Rays lift it.
//!
//! Check everything before emitting: `Emitter::ea` generates address microcode straight into the block, so it
//! should be the last thing done before the lifter commits to succeeding.

use std::ffi::CStr;

use crate::mc::{Builtin, Emitter, Flag, HASCALL, Insn, InsnInfo, Mop, NORET, Op, PURE, get_bytes, opnd, reg};

pub fn lift(e: &mut Emitter, insn: Insn, state: *mut std::ffi::c_void) -> bool {
    if let Some(helper) = simple_helper(insn) {
        return simple(e, helper);
    }
    match insn {
        Insn::Cpuid => cpuid(e),
        Insn::Xgetbv => xgetbv(e),
        Insn::Xsetbv => xsetbv(e),
        Insn::Rdrand => read_into_op0(e, c"__rdrand", true),
        Insn::Rdseed => read_into_op0(e, c"__rdseed", true),
        Insn::Rdsspd => read_into_op0(e, c"__rdsspd", false),
        Insn::Rdsspq => read_into_op0(e, c"__rdsspq", false),
        Insn::Vmread => vmread(e),
        Insn::Vmfunc => vmfunc(e),
        Insn::Vmresume => vmresume(e),
        Insn::Vmcall => register_state_call(e, c"__vmcall_regs", OPAQUE_REGS, false),
        Insn::Rdpid => rdpid(e),
        Insn::Rdpkru => pkru(e, false),
        Insn::Wrpkru => pkru(e, true),
        Insn::Xsavec => xstate_memory(e, c"_xsavec", c"_xsavec64"),
        Insn::Xsaveopt => xstate_memory(e, c"_xsaveopt", c"_xsaveopt64"),
        Insn::Xsaves => xstate_memory(e, c"_xsaves", c"_xsaves64"),
        Insn::Xrstors => xstate_memory(e, c"_xrstors", c"_xrstors64"),
        Insn::Umonitor => umonitor(e),
        Insn::Senduipi => one_reg_void(e, c"_senduipi", Builtin::I64),
        Insn::Umwait => waitpkg(e, c"_umwait"),
        Insn::Tpause => waitpkg(e, c"_tpause"),
        Insn::Enqcmd => enqcmd(e),
        Insn::Uiret => uiret(e),
        Insn::Encls => register_state_call(e, c"__encls_regs", SGX_REGS, true),
        Insn::Enclu => register_state_call(e, c"__enclu_regs", OPAQUE_REGS, true),
        Insn::Rcl => rotate_carry(e, c"__rcl"),
        Insn::Rcr => rotate_carry(e, c"__rcr"),
        Insn::Iretq => iretq(e),
        Insn::Sysret => sysretq(e),
        Insn::Int if e.insn().ops[0].value == 0x2E => syscall(e, state),
        Insn::Int => int2c(e),
        Insn::Nop => rsb_flush(e),
        Insn::Lea => trap_frame(e),
        Insn::Mov => paging_reloc(e),
        Insn::Syscall => syscall(e, state),
        _ => false,
    }
}

/// Instructions lifted as `helper(operands...)` with no result.
fn simple_helper(insn: Insn) -> Option<&'static CStr> {
    use Insn::*;
    Some(match insn {
        Clac => c"__clac",
        Stac => c"__stac",
        Swapgs => c"__swapgs",
        Saveprevssp => c"__saveprevssp",
        Setssbsy => c"__setssbsy",
        Endbr64 => c"__endbr64",
        Endbr32 => c"__endbr32",
        Incsspq => c"__incsspq",
        Incsspd => c"__incsspd",
        Rstorssp => c"__rstorssp",
        Wrssd => c"__wrssd",
        Wrssq => c"__wrssq",
        Wrussd => c"__wrussd",
        Wrussq => c"__wrussq",
        Clrssbsy => c"__clrssbsy",
        Clflushopt => c"_mm_clflushopt",
        Clwb => c"_mm_clwb",
        Vmclear => c"__vmclear",
        Vmlaunch => c"__vmlaunch",
        Vmptrld => c"__vmptrld",
        Vmptrst => c"__vmptrst",
        Vmwrite => c"__vmwrite",
        Vmxoff => c"__vmxoff",
        Vmxon => c"__vmxon",
        Invept => c"_invept",
        Invvpid => c"_invvpid",
        Invpcid => c"_invpcid",
        Invlpga => c"_invlpga",
        Prefetcht0 => c"_mm_prefetcht0",
        Prefetcht1 => c"_mm_prefetcht1",
        Prefetcht2 => c"_mm_prefetcht2",
        Prefetchnta => c"_mm_prefetchnta",
        Serialize => c"_serialize",
        _ => return None,
    })
}

fn operand_count(info: &InsnInfo) -> usize {
    info.ops.iter().take_while(|o| o.ty != opnd::VOID).count()
}

/// `helper(op0, op1, ...)`: immediates and registers by value, memory operands by address.
fn simple(e: &mut Emitter, helper: &'static CStr) -> bool {
    let info = e.insn();
    let ops = &info.ops[..operand_count(&info)];
    // Decide everything first; only memory operands need microcode of their own.
    let mut types = Vec::with_capacity(ops.len());
    for op in ops {
        let t = if op.ty == opnd::IMM || op.ty == opnd::REG { Builtin::from_dtype(op.dtype) } else { Some(Builtin::PtrVoid) };
        let Some(t) = t else { return false };
        types.push(t);
    }

    let void = e.ty(Builtin::Void);
    let call = e.call(helper, void, 0);
    for (i, (op, t)) in ops.iter().zip(types).enumerate() {
        let value = match op.ty {
            opnd::IMM => e.num(op.value, t.size()),
            opnd::REG => e.reg(op.reg as i32, t.size()),
            _ => e.ea(i as i32),
        };
        let ty = e.ty(t);
        e.arg(&call, value, ty, c"");
    }
    e.emit_call(call);
    true
}

/// `cpuid` → `r = __cpuid(leaf, subleaf); eax = EAX(r); ebx = EBX(r); ...`
fn cpuid(e: &mut Emitter) -> bool {
    let (i32t, i64t) = (e.ty(Builtin::I32), e.ty(Builtin::I64));
    let call = e.call(c"__cpuid", i64t, 0);
    let (eax, ecx) = (e.reg(reg::AX, 4), e.reg(reg::CX, 4));
    e.arg(&call, eax, i32t, c"leaf");
    e.arg(&call, ecx, i32t, c"subleaf");
    let value = e.result(call);
    let result = e.kreg(8);
    e.mov(value, result);

    for (r, part) in [(reg::AX, c"EAX"), (reg::BX, c"EBX"), (reg::CX, c"ECX"), (reg::DX, c"EDX")] {
        let extract = e.call(part, i32t, PURE);
        e.arg(&extract, result, i64t, c"");
        let v = e.result(extract);
        let dst = e.reg(r, 4);
        e.mov(v, dst);
    }
    true
}

/// `xgetbv` → `r = _xgetbv(ecx); eax = low(r); edx = high(r)`.
/// The original wrote the high half to ecx; xgetbv returns it in edx.
fn xgetbv(e: &mut Emitter) -> bool {
    let (i32t, i64t) = (e.ty(Builtin::I32), e.ty(Builtin::I64));
    let call = e.call(c"_xgetbv", i64t, 0);
    let ecx = e.reg(reg::CX, 4);
    e.arg(&call, ecx, i32t, c"xcr");
    let value = e.result(call);
    let result = e.kreg(8);
    e.mov(value, result);
    let (eax, edx) = (e.reg(reg::AX, 4), e.reg(reg::DX, 4));
    e.emit(Op::Low, Some(result), None, Some(eax));
    e.emit(Op::High, Some(result), None, Some(edx));
    true
}

/// `xsetbv` → `_xsetbv(ecx, edx:eax)`.
fn xsetbv(e: &mut Emitter) -> bool {
    let (void, i32t, i64t) = (e.ty(Builtin::Void), e.ty(Builtin::I32), e.ty(Builtin::I64));
    let call = e.call(c"_xsetbv", void, 0);
    let (ecx, value) = (e.reg(reg::CX, 4), e.reg_pair(reg::AX, reg::DX, 4));
    e.arg(&call, ecx, i32t, c"xcr");
    e.arg(&call, value, i64t, c"value");
    e.emit_call(call);
    true
}

/// `rdrand/rdseed/rdssp reg` → `reg = helper()`; rdrand/rdseed also report success in CF.
fn read_into_op0(e: &mut Emitter, helper: &'static CStr, sets_cf: bool) -> bool {
    let op = e.insn().ops[0];
    if op.ty != opnd::REG {
        return false;
    }
    let Some(t) = Builtin::from_dtype(op.dtype) else { return false };
    let ty = e.ty(t);
    let call = e.call(helper, ty, 0);
    if sets_cf {
        e.spoil_flag(&call, Flag::Cf);
    }
    let value = e.result(call);
    let dst = e.reg(op.reg as i32, t.size());
    e.mov(value, dst);
    true
}

/// Writes `value` to operand 0, a register or memory at `addr`.
fn store_op0(e: &mut Emitter, info: &InsnInfo, value: Mop, size: i32, addr: Option<Mop>) {
    match addr {
        None => {
            let dst = e.reg(info.ops[0].reg as i32, size);
            e.mov(value, dst);
        }
        Some(addr) => e.stx(value, reg::DS, addr),
    }
}

/// `vmread dst, field` → `dst = __vmread(field)`.
fn vmread(e: &mut Emitter) -> bool {
    let info = e.insn();
    let Some(t) = Builtin::from_dtype(info.ops[1].dtype) else { return false };
    if info.ops[1].ty != opnd::REG {
        return false;
    }
    let ty = e.ty(t);
    let call = e.call(c"__vmread", ty, PURE);
    let field = e.reg(info.ops[1].reg as i32, t.size());
    e.arg(&call, field, ty, c"field");
    let addr = (info.ops[0].ty != opnd::REG).then(|| e.ea(0));
    let value = e.result(call);
    store_op0(e, &info, value, t.size(), addr);
    true
}

const FLAGS: &[Flag] = &[Flag::Cf, Flag::Of, Flag::Zf, Flag::Sf, Flag::Pf];
const FLAG_FIELDS: &[(Flag, &CStr)] = &[(Flag::Cf, c"CF"), (Flag::Of, c"OF"), (Flag::Zf, c"ZF"), (Flag::Sf, c"SF"), (Flag::Pf, c"PF")];

fn clear_flags_except(e: &mut Emitter, keep: &[Flag]) {
    for &flag in FLAGS {
        if !keep.contains(&flag) {
            let (zero, dst) = (e.num(0, 1), e.flag(flag));
            e.mov(zero, dst);
        }
    }
}

fn segment_base_prefix(ea: u64) -> bool {
    get_bytes(ea, &mut [0; 15]).iter().take_while(|&&b| b != 0x0F).any(|&b| b == 0x64 || b == 0x65)
}

fn register_address(e: &mut Emitter, op: crate::mc::OpInfo, ptr_size: i32) -> Option<Mop> {
    if op.ty != opnd::REG { return None; }
    let width = Builtin::from_dtype(op.dtype)?.size();
    if !matches!(width, 2 | 4 | 8) || width > ptr_size { return None; }
    let mut address = e.reg(op.reg as i32, width);
    if width < ptr_size {
        let extended = e.kreg(ptr_size);
        e.emit(Op::Xdu, Some(address), None, Some(extended));
        address = extended;
    }
    Some(address)
}

fn vmfunc(e: &mut Emitter) -> bool {
    let (void, i32t) = (e.ty(Builtin::Void), e.ty(Builtin::I32));
    let call = e.call(c"__vmfunc", void, HASCALL);
    for (r, name) in [(reg::AX, c"function"), (reg::CX, c"index")] {
        let value = e.reg(r, 4);
        e.arg(&call, value, i32t, name);
    }
    e.emit_call(call);
    true
}

fn vmresume(e: &mut Emitter) -> bool {
    let i8t = e.ty(Builtin::I8);
    let call = e.call(c"__vmx_vmresume", i8t, HASCALL);
    let value = e.result(call);
    let status = e.kreg(1);
    e.mov(value, status);
    clear_flags_except(e, &[Flag::Cf, Flag::Zf]);
    // VMfailInvalid -> CF; VMfailValid -> ZF. Successful VM entry does not fall through.
    for (flag, code) in [(Flag::Cf, 2), (Flag::Zf, 1)] {
        let (number, dst) = (e.num(code, 1), e.flag(flag));
        e.emit(Op::Setz, Some(status), Some(number), Some(dst));
    }
    true
}

fn rdpid(e: &mut Emitter) -> bool {
    let op = e.insn().ops[0];
    if op.ty != opnd::REG { return false; }
    let Some(dst_ty) = Builtin::from_dtype(op.dtype) else { return false };
    if !matches!(dst_ty.size(), 4 | 8) { return false; }
    let ptr = e.ty(Builtin::PtrVoid);
    let reg_size = e.size_of(ptr);
    if dst_ty.size() > reg_size { return false; }
    let i32t = e.ty(Builtin::I32);
    let call = e.call(c"_rdpid_u32", i32t, 0);
    let result = e.result(call);
    let dst = e.reg(op.reg as i32, reg_size);
    if reg_size == 8 { e.emit(Op::Xdu, Some(result), None, Some(dst)); }
    else { e.mov(result, dst); }
    true
}

fn pkru(e: &mut Emitter, write: bool) -> bool {
    let (void, i32t) = (e.ty(Builtin::Void), e.ty(Builtin::I32));
    let call = e.call(if write { c"__wrpkru" } else { c"__rdpkru" }, if write { void } else { i32t }, HASCALL);
    for (r, name) in if write { &[(reg::AX, c"value"), (reg::CX, c"ecx"), (reg::DX, c"edx")][..] }
                         else { &[(reg::CX, c"ecx")][..] } {
        let value = e.reg(*r, 4);
        e.arg(&call, value, i32t, name);
    }
    if write { e.emit_call(call); }
    else {
        let value = e.result(call);
        let eax = e.reg(reg::AX, 8);
        e.emit(Op::Xdu, Some(value), None, Some(eax));
        let (zero, edx) = (e.num(0, 8), e.reg(reg::DX, 8));
        e.mov(zero, edx);
    }
    true
}

fn xstate_memory(e: &mut Emitter, helper32: &CStr, helper64: &CStr) -> bool {
    let info = e.insn();
    if matches!(info.ops[0].ty, opnd::REG | opnd::IMM | opnd::VOID) { return false; }
    if segment_base_prefix(info.ea) { return false; }
    let mut buf = [0; 15];
    let bytes = get_bytes(info.ea, &mut buf);
    let rex = bytes.iter().position(|&b| b == 0x0F).and_then(|n| n.checked_sub(1)).map(|n| bytes[n]);
    let wide = rex.is_some_and(|b| b & 0xF8 == 0x48);
    let helper = if wide { helper64 } else { helper32 };
    let (void, ptr, i64t) = (e.ty(Builtin::Void), e.ty(Builtin::PtrVoid), e.ty(Builtin::I64));
    let call = e.call(helper, void, HASCALL);
    let mask = e.reg_pair(reg::AX, reg::DX, 4);
    let addr = e.ea(0);
    e.arg(&call, addr, ptr, c"area");
    e.arg(&call, mask, i64t, c"mask");
    e.emit_call(call);
    true
}

fn umonitor(e: &mut Emitter) -> bool {
    let info = e.insn();
    let op = info.ops[0];
    // FS/GS addressing requires a segment-base model; retain Hex-Rays' fallback for those forms.
    if segment_base_prefix(info.ea) { return false; }
    let (void, ptr) = (e.ty(Builtin::Void), e.ty(Builtin::PtrVoid));
    let ptr_size = e.size_of(ptr);
    let Some(address) = register_address(e, op, ptr_size) else { return false };
    let call = e.call(c"_umonitor", void, HASCALL);
    e.arg(&call, address, ptr, c"address");
    e.emit_call(call);
    true
}

fn one_reg_void(e: &mut Emitter, helper: &CStr, ty: Builtin) -> bool {
    let op = e.insn().ops[0];
    if op.ty != opnd::REG { return false; }
    let (void, arg_ty) = (e.ty(Builtin::Void), e.ty(ty));
    let call = e.call(helper, void, HASCALL);
    let value = e.reg(op.reg as i32, ty.size());
    e.arg(&call, value, arg_ty, c"");
    e.emit_call(call);
    true
}

fn waitpkg(e: &mut Emitter, helper: &CStr) -> bool {
    let op = e.insn().ops[0];
    if op.ty != opnd::REG { return false; }
    let (i8t, i32t, i64t) = (e.ty(Builtin::I8), e.ty(Builtin::I32), e.ty(Builtin::I64));
    let call = e.call(helper, i8t, HASCALL);
    let (control, deadline) = (e.reg(op.reg as i32, 4), e.reg_pair(reg::AX, reg::DX, 4));
    e.arg(&call, control, i32t, c"control");
    e.arg(&call, deadline, i64t, c"deadline");
    let (value, cf) = (e.result(call), e.flag(Flag::Cf));
    e.mov(value, cf);
    clear_flags_except(e, &[Flag::Cf]);
    true
}

fn enqcmd(e: &mut Emitter) -> bool {
    let info = e.insn();
    if info.ops[0].ty != opnd::REG || matches!(info.ops[1].ty, opnd::REG | opnd::IMM | opnd::VOID) { return false; }
    if segment_base_prefix(info.ea) { return false; }
    let (i32t, ptr) = (e.ty(Builtin::I32), e.ty(Builtin::PtrVoid));
    let call = e.call(c"_enqcmd", i32t, HASCALL);
    let ptr_size = e.size_of(ptr);
    let Some(dst) = register_address(e, info.ops[0], ptr_size) else { return false };
    let src = e.ea(1);
    e.arg(&call, dst, ptr, c"destination");
    e.arg(&call, src, ptr, c"source");
    let (value, zf) = (e.result(call), e.flag(Flag::Zf));
    e.emit(Op::Low, Some(value), None, Some(zf));
    clear_flags_except(e, &[Flag::Zf]);
    true
}

fn uiret(e: &mut Emitter) -> bool {
    let frame = [(Builtin::PtrVoid, 0, c"ip"), (Builtin::I64, 8, c"flags"), (Builtin::PtrVoid, 16, c"sp")];
    let values: Vec<_> = frame.iter().map(|&(t, off, _)| e.stack_value(t, off)).collect();
    let void = e.ty(Builtin::Void);
    let call = e.call(c"__uiret", void, NORET);
    for ((t, _, name), value) in frame.into_iter().zip(values) {
        let ty = e.ty(t);
        e.arg(&call, value, ty, name);
    }
    e.emit_call(call);
    true
}

const SGX_REGS: &[(i32, &CStr)] = &[(reg::AX, c"RAX"), (reg::BX, c"RBX"), (reg::CX, c"RCX"), (reg::DX, c"RDX")];
const OPAQUE_REGS: &[(i32, &CStr)] = &[
    (reg::AX, c"RAX"), (reg::BX, c"RBX"), (reg::CX, c"RCX"), (reg::DX, c"RDX"), (reg::SI, c"RSI"),
    (reg::DI, c"RDI"), (reg::BP, c"RBP"), (reg::R8, c"R8"), (reg::R9, c"R9"), (reg::R10, c"R10"),
    (reg::R11, c"R11"), (reg::R12, c"R12"), (reg::R13, c"R13"), (reg::R14, c"R14"), (reg::R15, c"R15"),
];

// Opaque register-state token, like the existing CPUID model. No hypervisor ABI or SGX leaf is assumed.
fn register_state_call(e: &mut Emitter, helper: &CStr, regs: &[(i32, &CStr)], eax_leaf: bool) -> bool {
    let (i8t, i32t, i64t) = (e.ty(Builtin::I8), e.ty(Builtin::I32), e.ty(Builtin::I64));
    let call = e.call(helper, i64t, HASCALL);
    for (i, &(reg, name)) in regs.iter().enumerate() {
        let leaf = eax_leaf && i == 0;
        let value = e.reg(reg, if leaf { 4 } else { 8 });
        e.arg(&call, value, if leaf { i32t } else { i64t }, name);
    }
    let rsp = e.reg(reg::SP, 8);
    e.arg(&call, rsp, i64t, c"RSP");
    for &(flag, name) in FLAG_FIELDS {
        let value = e.flag(flag);
        e.arg(&call, value, i8t, name);
    }
    for &flag in FLAGS { e.spoil_flag(&call, flag); }
    let (value, snapshot) = (e.result(call), e.kreg(8));
    e.mov(value, snapshot);
    for &(reg, name) in regs {
        let extract = e.call(name, i64t, PURE);
        e.arg(&extract, snapshot, i64t, c"");
        let (value, dst) = (e.result(extract), e.reg(reg, 8));
        e.mov(value, dst);
    }
    // The token also carries condition codes; do not leave users of SGX/VM-call flags undefined.
    for &(flag, name) in FLAG_FIELDS {
        let extract = e.call(name, i8t, PURE);
        e.arg(&extract, snapshot, i64t, c"");
        let (value, dst) = (e.result(extract), e.flag(flag));
        e.mov(value, dst);
    }
    true
}

/// `rcl/rcr dst, count` → `dst = __rcl(dst, CF, count)`.
/// The original swapped the two helper names and always used count 1 for immediate counts.
fn rotate_carry(e: &mut Emitter, helper: &'static CStr) -> bool {
    let info = e.insn();
    let Some(t) = Builtin::from_dtype(info.ops[0].dtype) else { return false };
    let count_op = info.ops[1];
    if !matches!(count_op.ty, opnd::REG | opnd::IMM | opnd::VOID) {
        return false;
    }

    let size = t.size();
    let value = e.kreg(size);
    let addr = if info.ops[0].ty == opnd::REG {
        let src = e.reg(info.ops[0].reg as i32, size);
        e.mov(src, value);
        None
    } else {
        let addr = e.ea(0);
        e.ldx(reg::DS, addr, value);
        Some(addr)
    };
    let count = match count_op.ty {
        opnd::REG => e.reg(reg::CX, 1),
        opnd::IMM => e.num(count_op.value & 0xFF, 1),
        _ => e.num(1, 1),
    };

    let (ty, i8t) = (e.ty(t), e.ty(Builtin::I8));
    let call = e.call(helper, ty, PURE);
    let carry = e.flag(Flag::Cf);
    e.arg(&call, value, ty, c"value");
    e.arg(&call, carry, i8t, c"carry");
    e.arg(&call, count, i8t, c"count");
    e.spoil_flag(&call, Flag::Cf);
    e.spoil_flag(&call, Flag::Of);
    let result = e.result(call);
    store_op0(e, &info, result, size, addr);
    true
}

/// `iretq` → `__iretq(ip, cs, flags, sp, ss)` read from the interrupt frame on the stack.
fn iretq(e: &mut Emitter) -> bool {
    let frame = [
        (Builtin::PtrVoid, 0x00, c"ip"),
        (Builtin::I16, 0x08, c"cs"),
        (Builtin::I32, 0x10, c"flags"),
        (Builtin::PtrVoid, 0x18, c"sp"),
        (Builtin::I16, 0x20, c"ss"),
    ];
    let values: Vec<_> = frame.iter().map(|&(t, off, _)| e.stack_value(t, off)).collect();
    let void = e.ty(Builtin::Void);
    let call = e.call(c"__iretq", void, NORET);
    for ((t, _, name), value) in frame.into_iter().zip(values) {
        let ty = e.ty(t);
        e.arg(&call, value, ty, name);
    }
    e.emit_call(call);
    true
}

/// `sysretq` (REX.W sysret) → `__sysretq(rcx, r11d)`.
fn sysretq(e: &mut Emitter) -> bool {
    let ea = e.insn().ea;
    if get_bytes(ea, &mut [0u8; 1]) != [0x48] {
        return false;
    }
    let (void, ptr, i32t) = (e.ty(Builtin::Void), e.ty(Builtin::PtrVoid), e.ty(Builtin::I32));
    let call = e.call(c"__sysretq", void, NORET);
    let (rcx, r11) = (e.reg(reg::CX, 8), e.reg(reg::R11, 4));
    e.arg(&call, rcx, ptr, c"ip");
    e.arg(&call, r11, i32t, c"flags");
    e.emit_call(call);
    true
}

/// `int 2Ch` (NT assertion) → `__assert_fail(ecx)`, no return. Other interrupts stay with Hex-Rays.
fn int2c(e: &mut Emitter) -> bool {
    if e.insn().ops[0].value != 0x2C {
        return false;
    }
    let (void, i32t) = (e.ty(Builtin::Void), e.ty(Builtin::I32));
    let call = e.call(c"__assert_fail", void, NORET);
    let ecx = e.reg(reg::CX, 4);
    e.arg(&call, ecx, i32t, c"code");
    e.emit_call(call);
    true
}

/// The patched RSB-stuffing gadget (see `db::patch_rsb_gadgets`) → `__flush_rsb()`.
fn rsb_flush(e: &mut Emitter) -> bool {
    let ea = e.insn().ea;
    if get_bytes(ea, &mut [0u8; 14]) != ntrays_core::RSB_PATCHED {
        return false;
    }
    let void = e.ty(Builtin::Void);
    let call = e.call(c"__flush_rsb", void, 0);
    e.emit_call(call);
    true
}

/// `lea rbp, [rsp+80h]` in an ISR → `rbp = KeGetTrapFrame()`, typed `_KTRAP_FRAME *__shifted(_KTRAP_FRAME, 80h)`.
fn trap_frame(e: &mut Emitter) -> bool {
    let ea = e.insn().ea;
    if get_bytes(ea, &mut [0u8; 8]) != ntrays_core::TRAPFRAME_LEA || !ntrays_core::is_isr(&e.func_name()) {
        return false;
    }
    let Some(ty) = e.shifted_ptr(c"_KTRAP_FRAME", ntrays_core::TRAPFRAME_DELTA) else { return false };
    let call = e.call(c"KeGetTrapFrame", ty, PURE);
    let frame = e.result(call);
    let rbp = e.reg(reg::BP, 8);
    e.mov(frame, rbp);
    true
}

/// `mov reg, imm64` with a paging-structure address → `reg = MmGetPteBase() + offset` (typed `_MMPTE *`).
fn paging_reloc(e: &mut Emitter) -> bool {
    let info = e.insn();
    let (dst, imm) = (info.ops[0], info.ops[1]);
    if dst.ty != opnd::REG || imm.ty != opnd::IMM {
        return false;
    }
    let Some(r) = ntrays_core::classify_paging_imm(imm.value) else { return false };
    let ty = match e.named(r.ty, true) {
        Some(t) => t,
        None => e.ty(Builtin::I64),
    };
    let call = e.call(r.getter, ty, PURE);
    let base = e.result(call);
    let (offset, reg) = (e.num(r.offset, 8), e.reg(dst.reg as i32, 8));
    e.emit(Op::Add, Some(offset), Some(base), Some(reg));
    true
}

/// `syscall` → `NtXxx(args...)` when the API is known, else `__syscall(id, rcx..r9 args)`.
///
/// The API comes from the function the stub lives in (ntdll/win32u stubs are named after it). Unknown APIs keep
/// only the four register arguments: the original also read two stack slots, which made Hex-Rays invent
/// variables and fail lvar allocation on stubs with fewer arguments.
fn syscall(e: &mut Emitter, state: *mut std::ffi::c_void) -> bool {
    use ntrays_core::syscall::{STUB_LOOKBEHIND, stub_id};
    if !crate::db::is_pe64() {
        return false;
    }
    let ea = e.insn().ea;
    let mut before = [0u8; STUB_LOOKBEHIND];
    let id = ea.checked_sub(STUB_LOOKBEHIND as u64).and_then(|start| stub_id(get_bytes(start, &mut before)));
    let (id, api) = crate::syscall_info(state, ea, id, &e.func_name());

    const ARG_REGS: [i32; 4] = [reg::R10, reg::DX, reg::R8, reg::R9];
    let (i32t, i64t) = (e.ty(Builtin::I32), e.ty(Builtin::I64));
    let (call, ret_size) = match api {
        Some(api) => {
            let ret = e.decl(api.ret).filter(|&t| (1..=8).contains(&e.size_of(t))).unwrap_or(i64t);
            let ret_size = e.size_of(ret);
            let Ok(helper) = std::ffi::CString::new(api.name) else { return false };
            let call = e.call(&helper, ret, HASCALL);
            for (i, &(ty, name)) in api.args.iter().enumerate() {
                let t = e.decl(ty).filter(|&t| (1..=8).contains(&e.size_of(t))).unwrap_or(i64t);
                let size = e.size_of(t);
                let value = match ARG_REGS.get(i) {
                    Some(&r) => e.reg(r, size),
                    None => e.stack_value_sized(size, 0x28 + (i as u64 - 4) * 8),
                };
                let name = std::ffi::CString::new(name).unwrap_or_default();
                e.arg(&call, value, t, &name);
            }
            (call, ret_size)
        }
        None => {
            let call = e.call(c"__syscall", i64t, HASCALL);
            let number = match id {
                Some(id) => e.num(id as u64, 4),
                None => e.reg(reg::AX, 4),
            };
            e.arg(&call, number, i32t, c"id");
            for (i, r) in ARG_REGS.into_iter().enumerate() {
                let value = e.reg(r, 8);
                e.arg(&call, value, i64t, ARG_NAMES[i]);
            }
            (call, 8)
        }
    };
    for r in [reg::AX, reg::CX, reg::R11] {
        e.spoil(&call, r, 8);
    }
    let result = e.result(call);
    let rax = e.reg(reg::AX, ret_size);
    e.mov(result, rax);
    true
}
const ARG_NAMES: [&CStr; 4] = [c"arg0", c"arg1", c"arg2", c"arg3"];
