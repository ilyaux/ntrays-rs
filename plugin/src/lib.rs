//! Rust side of the NtRays plugin. `shim.cpp` owns the IDA SDK objects and calls the `ntrays_*` functions here.
//!
//! Every entry point runs inside `guard`: a panic must never unwind into IDA, so it is caught, reported in the
//! Output window, and the hook falls back to doing nothing.

mod lift;
#[allow(dead_code)] // the builder API is ahead of the lifters ported so far
mod mc;

use std::ffi::{CStr, CString, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;

use ntrays_core::fold;

unsafe extern "C" {
    /// Prints to IDA's Output window.
    fn ntrays_msg(text: *const c_char);
    /// Name of entry `i` in a shim table (0 = instructions, 1 = opcodes), or null past the end.
    fn ntrays_table_name(table: u32, i: u32) -> *const c_char;
}

fn msg(text: &str) {
    let text = CString::new(text.replace('\0', "")).unwrap();
    unsafe { ntrays_msg(text.as_ptr()) };
}

fn guard<T>(what: &str, fallback: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|e| {
        let why = e
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| e.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        msg(&format!("[ntrays] internal error in {what}: {why}\n"));
        fallback
    })
}

/// The shim's tables must list the same entries in the same order as Rust's enums.
fn tables_match() -> bool {
    [(0, mc::INSN_NAMES), (1, mc::OP_NAMES)].iter().all(|&(table, names)| {
        let mut i = 0;
        loop {
            let p = unsafe { ntrays_table_name(table, i) };
            match (p.is_null(), names.get(i as usize)) {
                (true, None) => return true,
                (false, Some(n)) if unsafe { CStr::from_ptr(p) }.to_bytes() == n.as_bytes() => i += 1,
                _ => return false,
            }
        }
    })
}

/// Database-level operations, outside of decompilation.
mod db {
    unsafe extern "C" {
        fn ntrays_db_is_pe64() -> bool;
        fn ntrays_db_find_bytes(start: u64, pattern: *const u8, size: usize) -> u64;
        fn ntrays_db_patch(ea: u64, bytes: *const u8, size: usize);
        fn ntrays_db_min_ea() -> u64;
        fn ntrays_db_setting(idx: u32) -> u64;
        fn ntrays_db_set_setting(idx: u32, value: u64);
        fn ntrays_db_name_ea(name: *const std::ffi::c_char) -> u64;
        fn ntrays_db_enable_kuser();
        fn ntrays_add_parent_type(child: *const std::ffi::c_char, parent: *const std::ffi::c_char);
        fn ntrays_db_fix_parent_types() -> i32;
    }

    /// Settings slots in the IDB (netnode "$ ntrays-rs").
    const RSB_PATCHED: u32 = 1;
    /// Fold hypervisor-enlightenment globals too (off by default, see `fold::Gate::Hvl`).
    pub const FOLD_HVL: u32 = 2;

    pub fn setting(idx: u32) -> u64 {
        unsafe { ntrays_db_setting(idx) }
    }

    /// Creates the KUSER_SHARED_DATA segment for the binary's mode and keeps it in place across rebases.
    pub fn enable_kuser() {
        unsafe { ntrays_db_enable_kuser() }
    }

    /// Registers the K→E parent type pairs (used for local variables during decompilation) and rewrites
    /// struct fields in the database's types once.
    pub fn use_parent_types() {
        for (child, parent) in ntrays_core::PARENT_TYPES {
            unsafe { ntrays_add_parent_type(child.as_ptr(), parent.as_ptr()) };
        }
        let fixed = unsafe { ntrays_db_fix_parent_types() };
        if fixed > 0 {
            super::msg(&format!("[ntrays-rs] retyped {fixed} struct fields to _ETHREAD / _EPROCESS
"));
        }
    }

    pub fn name_ea(name: &str) -> Option<u64> {
        let name = std::ffi::CString::new(name).ok()?;
        match unsafe { ntrays_db_name_ea(name.as_ptr()) } {
            u64::MAX => None,
            ea => Some(ea),
        }
    }

    pub fn is_pe64() -> bool {
        unsafe { ntrays_db_is_pe64() }
    }

    /// Patches every RSB-stuffing gadget once per database, as a regular IDA patch (Edit > Patch program shows it
    /// and can revert it). Without this, ISRs containing the gadget do not decompile at all.
    pub fn patch_rsb_gadgets() {
        if unsafe { ntrays_db_setting(RSB_PATCHED) } != 0 {
            return;
        }
        let (gadget, patched) = (ntrays_core::RSB_GADGET, ntrays_core::RSB_PATCHED);
        let mut ea = unsafe { ntrays_db_min_ea() };
        let mut count = 0;
        loop {
            ea = unsafe { ntrays_db_find_bytes(ea, gadget.as_ptr(), gadget.len()) };
            if ea == u64::MAX {
                break;
            }
            unsafe { ntrays_db_patch(ea, patched.as_ptr(), patched.len()) };
            ea += patched.len() as u64;
            count += 1;
        }
        unsafe { ntrays_db_set_setting(RSB_PATCHED, 1) };
        if count != 0 {
            super::msg(&format!("[ntrays-rs] patched {count} RSB flush gadgets (revertible in Edit > Patch program)\n"));
        }
    }
}

/// Per-database plugin state.
struct Plugin {
    /// Fold rules resolved to addresses; `None` until first use and after any rename in the database.
    folds: Mutex<Option<fold::Resolved>>,
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_init() -> *mut c_void {
    guard("init", std::ptr::null_mut(), || {
        if !tables_match() {
            msg("[ntrays] shim and Rust tables differ; plugin not loaded\n");
            return std::ptr::null_mut();
        }
        msg(&format!("[ntrays-rs] loaded, built for IDA SDK {}\n", env!("IDA_SDK_VERSION")));
        if db::is_pe64() {
            db::patch_rsb_gadgets();
            db::enable_kuser();
            db::use_parent_types();
        }
        Box::into_raw(Box::new(Plugin { folds: Mutex::new(None) })).cast()
    })
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_term(state: *mut c_void) {
    guard("term", (), || drop(unsafe { Box::from_raw(state.cast::<Plugin>()) }))
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_run(_state: *mut c_void, _arg: usize) -> bool {
    true
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_lift(_state: *mut c_void, builder: *mut c_void, kind: u32) -> bool {
    guard("lift", false, || {
        let Some(insn) = mc::Insn::from_index(kind) else { return false };
        let mut e = unsafe { mc::Emitter::new(builder) };
        lift::lift(&mut e, insn)
    })
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_fold(state: *mut c_void, site: u32, ea: u64, value: u64) -> bool {
    guard("fold", false, || {
        let Some(site) = fold::Site::from_u32(site) else { return false };
        let plugin = unsafe { &*state.cast::<Plugin>() };
        let mut folds = plugin.folds.lock().unwrap_or_else(|e| e.into_inner());
        folds
            .get_or_insert_with(|| fold::Resolved::new(db::setting(db::FOLD_HVL) != 0, db::name_ea))
            .folds(site, ea, value)
    })
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_names_changed(state: *mut c_void) {
    guard("names_changed", (), || {
        let plugin = unsafe { &*state.cast::<Plugin>() };
        *plugin.folds.lock().unwrap_or_else(|e| e.into_inner()) = None;
    })
}
