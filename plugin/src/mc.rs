//! Safe Rust side of the microcode builder in `shim.cpp`.
//!
//! Operands, types and calls live in C++ arenas and are referred to by index. Instructions are buffered and
//! only inserted when the lifter returns `true`; if any step fails, C++ marks the builder failed and the whole
//! lift falls back to Hex-Rays' own code generation.

use std::ffi::{CStr, c_char, c_void};
use std::marker::PhantomData;

const NONE: u32 = u32::MAX;

/// x86 register numbers (`RegNo` in the SDK's intel.hpp; stable across SDK versions).
pub mod reg {
    pub const AX: i32 = 0;
    pub const CX: i32 = 1;
    pub const DX: i32 = 2;
    pub const BX: i32 = 3;
    pub const SP: i32 = 4;
    pub const BP: i32 = 5;
    pub const SI: i32 = 6;
    pub const DI: i32 = 7;
    pub const R8: i32 = 8;
    pub const R9: i32 = 9;
    pub const R10: i32 = 10;
    pub const R11: i32 = 11;
    pub const R12: i32 = 12;
    pub const R13: i32 = 13;
    pub const R14: i32 = 14;
    pub const R15: i32 = 15;
    pub const SS: i32 = 31;
    pub const DS: i32 = 32;
}

/// x86 operand types and data types (`o_*`, `dt_*` in the SDK's ua.hpp; stable across SDK versions).
pub mod opnd {
    pub const VOID: u8 = 0;
    pub const REG: u8 = 1;
    pub const IMM: u8 = 5;
}

/// Flag registers Rust can use; order matches `flag_regs[]` in shim.cpp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Flag {
    Cf,
    Of,
    Zf,
    Sf,
    Pf,
}

/// Instructions the dispatcher hands to Rust. Order must match `NTRAYS_INSNS` in shim.cpp (checked at load).
macro_rules! insns {
    ($($v:ident = $n:literal),* $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u32)]
        pub enum Insn { $($v),* }
        pub const INSN_NAMES: &[&str] = &[$($n),*];
        const ALL_INSNS: &[Insn] = &[$(Insn::$v),*];
    };
}
insns! {
    Cpuid = "cpuid", Xgetbv = "xgetbv", Xsetbv = "xsetbv", Rdrand = "rdrand", Rdseed = "rdseed", Rdsspd = "rdsspd",
    Rdsspq = "rdsspq", Vmread = "vmread", Rcl = "rcl", Rcr = "rcr", Iretq = "iretq", Sysret = "sysret", Int = "int",
    Clac = "clac", Stac = "stac", Swapgs = "swapgs", Saveprevssp = "saveprevssp", Setssbsy = "setssbsy",
    Endbr64 = "endbr64", Endbr32 = "endbr32", Incsspq = "incsspq", Incsspd = "incsspd", Rstorssp = "rstorssp",
    Wrssd = "wrssd", Wrssq = "wrssq", Wrussd = "wrussd", Wrussq = "wrussq", Clrssbsy = "clrssbsy",
    Clflushopt = "clflushopt", Clwb = "clwb", Vmclear = "vmclear", Vmlaunch = "vmlaunch", Vmptrld = "vmptrld",
    Vmptrst = "vmptrst", Vmwrite = "vmwrite", Vmxoff = "vmxoff", Vmxon = "vmxon", Invept = "invept",
    Invvpid = "invvpid", Invpcid = "invpcid", Invlpga = "invlpga", Xsaves = "xsaves", Xrstors = "xrstors",
    Prefetcht0 = "prefetcht0", Prefetcht1 = "prefetcht1", Prefetcht2 = "prefetcht2", Prefetchnta = "prefetchnta", Lea = "lea", Nop = "nop", Mov = "mov",
    Syscall = "syscall",
    Vmfunc = "vmfunc", Vmresume = "vmresume", Vmcall = "vmcall", Rdpid = "rdpid", Rdpkru = "rdpkru",
    Wrpkru = "wrpkru", Xsavec = "xsavec", Xsaveopt = "xsaveopt", Serialize = "serialize", Umonitor = "umonitor", Umwait = "umwait",
    Tpause = "tpause", Enqcmd = "enqcmd", Uiret = "uiret", Senduipi = "senduipi", Encls = "encls", Enclu = "enclu",
}

impl Insn {
    pub fn from_index(i: u32) -> Option<Self> {
        ALL_INSNS.get(i as usize).copied()
    }
}

/// Microcode opcodes Rust can emit. Order must match `NTRAYS_OPS` in shim.cpp (checked at load).
#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum Op {
    Mov,
    Add,
    Ldx,
    Stx,
    Low,
    High,
    Xdu,
    Setz,
}
pub const OP_NAMES: &[&str] = &["mov", "add", "ldx", "stx", "low", "high", "xdu", "setz"];

/// Builtin types; order matches `bts[]` in `ntrays_type_builtin`, with `PtrVoid` one past the end.
#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum Builtin {
    Void,
    I8,
    I16,
    I32,
    I64,
    I128,
    Float,
    Double,
    PtrVoid,
}

impl Builtin {
    /// Integer/float type for an operand's `dt_*` data type (the original mapped dt_double to a non-double type).
    pub fn from_dtype(dtype: u8) -> Option<Self> {
        Some(match dtype {
            0 => Builtin::I8,
            1 => Builtin::I16,
            2 => Builtin::I32,
            3 => Builtin::Float,
            4 => Builtin::Double,
            7 => Builtin::I64,
            8 => Builtin::I128,
            _ => return None,
        })
    }
    pub fn size(self) -> i32 {
        match self {
            Builtin::Void => 0,
            Builtin::I8 => 1,
            Builtin::I16 => 2,
            Builtin::I32 | Builtin::Float => 4,
            Builtin::I64 | Builtin::Double | Builtin::PtrVoid => 8,
            Builtin::I128 => 16,
        }
    }
}

pub const PURE: u32 = 1;
pub const NORET: u32 = 2;
pub const HASCALL: u32 = 4;

#[derive(Clone, Copy)]
pub struct Mop(u32);
#[derive(Clone, Copy)]
pub struct Ty(u32);
/// A call being built; consumed by `result` or `emit_call`, so it can be used once.
pub struct Call {
    idx: u32,
    helper: std::ffi::CString,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct OpInfo {
    pub ty: u8,
    pub dtype: u8,
    pub reg: u16,
    pub value: u64,
    pub addr: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct InsnInfo {
    pub ea: u64,
    pub size: u32,
    pub ops: [OpInfo; 8],
}

unsafe extern "C" {
    fn ntrays_mop_reg(b: *mut c_void, reg: i32, size: i32) -> u32;
    fn ntrays_mop_kreg(b: *mut c_void, size: i32) -> u32;
    fn ntrays_mop_num(b: *mut c_void, value: u64, size: i32) -> u32;
    fn ntrays_mop_reg_pair(b: *mut c_void, lo: i32, hi: i32, halfsize: i32) -> u32;
    fn ntrays_mop_flag(b: *mut c_void, flag: u32) -> u32;
    fn ntrays_call_spoil_flag(b: *mut c_void, call: u32, flag: u32);
    fn ntrays_get_bytes(ea: u64, buf: *mut u8, size: usize) -> usize;
    fn ntrays_mop_ea(b: *mut c_void, opnum: i32) -> u32;
    fn ntrays_type_builtin(b: *mut c_void, kind: u32) -> u32;
    fn ntrays_type_named(b: *mut c_void, name: *const c_char, pointer: bool) -> u32;
    fn ntrays_call_new(b: *mut c_void, ret_type: u32, flags: u32) -> u32;
    fn ntrays_call_arg(b: *mut c_void, call: u32, mop: u32, ty: u32, name: *const c_char);
    fn ntrays_call_spoil(b: *mut c_void, call: u32, reg: i32, size: i32);
    fn ntrays_mop_call(b: *mut c_void, call: u32, helper: *const c_char) -> u32;
    fn ntrays_emit_call(b: *mut c_void, call: u32, helper: *const c_char);
    fn ntrays_emit(b: *mut c_void, op: u32, l: u32, r: u32, d: u32);
    fn ntrays_insn(b: *mut c_void, out: *mut InsnInfo);
    fn ntrays_func_name(b: *mut c_void, buf: *mut c_char, size: usize) -> usize;
    fn ntrays_type_shifted_ptr(b: *mut c_void, name: *const c_char, delta: i32) -> u32;
    fn ntrays_type_decl(b: *mut c_void, decl: *const c_char) -> u32;
    fn ntrays_type_size(b: *mut c_void, ty: u32) -> i32;
}

/// Builds microcode for the instruction being lifted. Only valid during one `ntrays_lift` call.
pub struct Emitter<'a> {
    b: *mut c_void,
    _scope: PhantomData<&'a mut ()>,
}

impl Emitter<'_> {
    /// # Safety
    /// `b` must be the builder pointer shim.cpp passed to `ntrays_lift`, used only during that call.
    pub unsafe fn new(b: *mut c_void) -> Self {
        Emitter { b, _scope: PhantomData }
    }

    pub fn insn(&mut self) -> InsnInfo {
        let mut out = InsnInfo::default();
        unsafe { ntrays_insn(self.b, &mut out) };
        out
    }

    pub fn reg(&mut self, reg: i32, size: i32) -> Mop {
        Mop(unsafe { ntrays_mop_reg(self.b, reg, size) })
    }
    pub fn kreg(&mut self, size: i32) -> Mop {
        Mop(unsafe { ntrays_mop_kreg(self.b, size) })
    }
    /// `hi:lo` register pair, e.g. edx:eax with `halfsize` 4.
    pub fn reg_pair(&mut self, lo: i32, hi: i32, halfsize: i32) -> Mop {
        Mop(unsafe { ntrays_mop_reg_pair(self.b, lo, hi, halfsize) })
    }
    pub fn flag(&mut self, flag: Flag) -> Mop {
        Mop(unsafe { ntrays_mop_flag(self.b, flag as u32) })
    }
    pub fn num(&mut self, value: u64, size: i32) -> Mop {
        Mop(unsafe { ntrays_mop_num(self.b, value, size) })
    }
    /// Effective address of memory operand `opnum`, computed into a fresh 8-byte register.
    pub fn ea(&mut self, opnum: i32) -> Mop {
        Mop(unsafe { ntrays_mop_ea(self.b, opnum) })
    }

    pub fn ty(&mut self, t: Builtin) -> Ty {
        Ty(unsafe { ntrays_type_builtin(self.b, t as u32) })
    }
    /// A type from the database's type library, or `None` if it has no such type.
    pub fn named(&mut self, name: &CStr, pointer: bool) -> Option<Ty> {
        match unsafe { ntrays_type_named(self.b, name.as_ptr(), pointer) } {
            NONE => None,
            i => Some(Ty(i)),
        }
    }

    /// `name *__shifted(name, delta)`, or `None` if the database has no such type.
    pub fn shifted_ptr(&mut self, name: &CStr, delta: i32) -> Option<Ty> {
        match unsafe { ntrays_type_shifted_ptr(self.b, name.as_ptr(), delta) } {
            NONE => None,
            i => Some(Ty(i)),
        }
    }

    /// A type from a C declaration ("PHANDLE", "ULONG"), or `None` if the database cannot parse it.
    pub fn decl(&mut self, decl: &str) -> Option<Ty> {
        let decl = std::ffi::CString::new(decl).ok()?;
        match unsafe { ntrays_type_decl(self.b, decl.as_ptr()) } {
            NONE => None,
            i => Some(Ty(i)),
        }
    }
    /// Size of a type in bytes (0 if unknown).
    pub fn size_of(&mut self, ty: Ty) -> i32 {
        unsafe { ntrays_type_size(self.b, ty.0) }
    }

    /// Name of the function being decompiled.
    pub fn func_name(&mut self) -> String {
        let mut buf = [0u8; 512];
        let n = unsafe { ntrays_func_name(self.b, buf.as_mut_ptr().cast(), buf.len()) };
        String::from_utf8_lossy(&buf[..n.min(buf.len())]).into_owned()
    }

    pub fn call(&mut self, helper: &CStr, ret: Ty, flags: u32) -> Call {
        Call { idx: unsafe { ntrays_call_new(self.b, ret.0, flags) }, helper: helper.to_owned() }
    }
    pub fn arg(&mut self, call: &Call, value: Mop, ty: Ty, name: &CStr) {
        unsafe { ntrays_call_arg(self.b, call.idx, value.0, ty.0, name.as_ptr()) }
    }
    pub fn spoil(&mut self, call: &Call, reg: i32, size: i32) {
        unsafe { ntrays_call_spoil(self.b, call.idx, reg, size) }
    }
    pub fn spoil_flag(&mut self, call: &Call, flag: Flag) {
        unsafe { ntrays_call_spoil_flag(self.b, call.idx, flag as u32) }
    }
    /// The call's return value as an operand.
    pub fn result(&mut self, call: Call) -> Mop {
        Mop(unsafe { ntrays_mop_call(self.b, call.idx, call.helper.as_ptr()) })
    }
    /// The call as a statement, result unused.
    pub fn emit_call(&mut self, call: Call) {
        unsafe { ntrays_emit_call(self.b, call.idx, call.helper.as_ptr()) }
    }

    pub fn emit(&mut self, op: Op, l: Option<Mop>, r: Option<Mop>, d: Option<Mop>) {
        let idx = |m: Option<Mop>| m.map_or(NONE, |m| m.0);
        unsafe { ntrays_emit(self.b, op as u32, idx(l), idx(r), idx(d)) }
    }
    pub fn mov(&mut self, src: Mop, dst: Mop) {
        self.emit(Op::Mov, Some(src), None, Some(dst))
    }
    /// `dst = *(seg:addr)`
    pub fn ldx(&mut self, seg: i32, addr: Mop, dst: Mop) {
        let seg = self.reg(seg, 2);
        self.emit(Op::Ldx, Some(seg), Some(addr), Some(dst))
    }
    /// `*(seg:addr) = value`
    pub fn stx(&mut self, value: Mop, seg: i32, addr: Mop) {
        let seg = self.reg(seg, 2);
        self.emit(Op::Stx, Some(value), Some(seg), Some(addr))
    }
    /// Loads a stack value at `[rsp + offset]` into a fresh register.
    pub fn stack_value(&mut self, ty: Builtin, offset: u64) -> Mop {
        self.stack_value_sized(ty.size(), offset)
    }
    /// Loads `size` bytes at `[rsp + offset]` into a fresh register.
    pub fn stack_value_sized(&mut self, size: i32, offset: u64) -> Mop {
        let (rsp, off, addr) = (self.reg(reg::SP, 8), self.num(offset, 8), self.kreg(8));
        self.emit(Op::Add, Some(rsp), Some(off), Some(addr));
        let value = self.kreg(size);
        self.ldx(reg::SS, addr, value);
        value
    }
}

/// Bytes at `ea` in the database (fewer if the range is not loaded).
pub fn get_bytes(ea: u64, buf: &mut [u8]) -> &[u8] {
    let n = unsafe { ntrays_get_bytes(ea, buf.as_mut_ptr(), buf.len()) };
    &buf[..n.min(buf.len())]
}
