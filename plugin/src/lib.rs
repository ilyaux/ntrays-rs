//! Rust side of the NtRays plugin. `shim.cpp` owns the IDA SDK objects and calls the `ntrays_*` functions here.
//!
//! Every entry point runs inside `guard`: a panic must never unwind into IDA, so it is caught, reported in the
//! Output window, and the hook falls back to doing nothing.

mod lift;
mod settings;
mod syscall_ui;
#[allow(dead_code)] // the builder API is ahead of the lifters ported so far
mod mc;

use std::ffi::{CStr, CString, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;

use ntrays_core::{fold, syscall, syscall_state};

#[unsafe(no_mangle)]
pub extern "C" fn ntrays_pool_tag_argument(name: *const c_char, value: u64) -> i32 {
    guard("pool_tag_argument", -1, || {
        if name.is_null() { return -1; }
        unsafe { CStr::from_ptr(name) }.to_str().ok()
            .and_then(|name| ntrays_core::literals::pool_tag_argument(name, value))
            .map_or(-1, |index| index as i32)
    })
}

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
        fn ntrays_add_parent_type(child: *const std::ffi::c_char, parent: *const std::ffi::c_char);
        fn ntrays_db_fix_parent_types() -> i32;
        fn ntrays_db_syscall_read(kind: u32, ea: u64, buf: *mut u8, cap: usize) -> isize;
        fn ntrays_db_syscall_write(kind: u32, ea: u64, data: *const u8, size: usize) -> bool;
        fn ntrays_db_syscall_legacy_selection() -> u64;
        fn ntrays_db_syscall_legacy_site(ea: u64) -> u64;
        fn ntrays_db_syscall_legacy_confirmed(expected: *const u8, size: usize) -> bool;
        fn ntrays_db_syscall_exports() -> usize;
        fn ntrays_db_syscall_export(index: usize, number: *mut u32, name: *mut std::ffi::c_char, cap: usize) -> isize;
    }

    /// Settings slots in the IDB (netnode "$ ntrays-rs").
    const RSB_PATCHED: u32 = 1;
    /// Fold hypervisor-enlightenment globals too (off by default, see `fold::Gate::Hvl`).
    pub const FOLD_HVL: u32 = 2;

    pub fn setting(idx: u32) -> u64 {
        unsafe { ntrays_db_setting(idx) }
    }

    /// Registers the K→E parent type pairs (used for local variables during decompilation) and rewrites
    /// struct fields in the database's types once.
    pub fn use_parent_types(log_level: u32) {
        for (child, parent) in ntrays_core::PARENT_TYPES {
            unsafe { ntrays_add_parent_type(child.as_ptr(), parent.as_ptr()) };
        }
        let fixed = unsafe { ntrays_db_fix_parent_types() };
        if fixed > 0 && log_level >= 1 {
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

    pub fn syscall_read(kind: u32, ea: u64) -> Result<Option<Vec<u8>>, String> {
        let size = unsafe { ntrays_db_syscall_read(kind, ea, std::ptr::null_mut(), 0) };
        if size == -1 { return Ok(None); }
        if size < 0 || size as usize > ntrays_core::syscall_state::MAX_BLOB {
            return Err("invalid or unreadable syscall state".into());
        }
        let mut bytes = vec![0; size as usize];
        if size != 0 && unsafe { ntrays_db_syscall_read(kind, ea, bytes.as_mut_ptr(), bytes.len()) } != size {
            return Err("syscall state changed while reading".into());
        }
        Ok(Some(bytes))
    }

    pub fn syscall_write(kind: u32, ea: u64, bytes: &[u8]) -> bool {
        unsafe { ntrays_db_syscall_write(kind, ea, bytes.as_ptr(), bytes.len()) }
    }

    pub fn legacy_selection() -> u64 { unsafe { ntrays_db_syscall_legacy_selection() } }
    pub fn legacy_site(ea: u64) -> u64 { unsafe { ntrays_db_syscall_legacy_site(ea) } }
    pub fn legacy_confirmed() -> bool {
        let sha = ntrays_core::syscall_state::LEGACY_TABLE_SHA256.as_bytes();
        unsafe { ntrays_db_syscall_legacy_confirmed(sha.as_ptr(), sha.len()) }
    }

    pub fn exported_syscalls() -> ntrays_core::syscall::SyscallMap {
        let mut map = ntrays_core::syscall::SyscallMap::new();
        for index in 0..unsafe { ntrays_db_syscall_exports() } {
            let mut number = 0;
            let mut buf = [0u8; 256];
            let len = unsafe { ntrays_db_syscall_export(index, &mut number, buf.as_mut_ptr().cast(), buf.len()) };
            if len > 0 && (len as usize) < buf.len() {
                if let Some(name) = std::str::from_utf8(&buf[..len as usize]).ok().and_then(ntrays_core::syscall::nt_name) {
                    map.entry(number).or_insert(name);
                }
            }
        }
        map
    }

    /// Patches every RSB-stuffing gadget once per database, as a regular IDA patch (Edit > Patch program shows it
    /// and can revert it). Without this, ISRs containing the gadget do not decompile at all.
    pub fn patch_rsb_gadgets(log_level: u32) {
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
        if count != 0 && log_level >= 1 {
            super::msg(&format!("[ntrays-rs] patched {count} RSB flush gadgets (revertible in Edit > Patch program)\n"));
        }
    }
}

struct DbSyscalls {
    state: syscall_state::State,
    writable: bool,
    legacy_confirmed: bool,
}

impl DbSyscalls {
    fn load(log_level: u32) -> Self {
        let mut writable = true;
        let legacy_confirmed = db::legacy_confirmed();
        match db::syscall_read(0, 0).and_then(|blob| blob.map(|b| syscall_state::State::decode(&b)).transpose()) {
            Ok(Some(state)) => return Self { state, writable, legacy_confirmed },
            Ok(None) => (),
            Err(error) => {
                msg(&format!("[ntrays-rs] {error}; stored syscall data kept unchanged\n"));
                return Self { state: syscall_state::State::default(), writable: false, legacy_confirmed };
            }
        }
        let selection = db::legacy_selection();
        let migrated = if !legacy_confirmed {
            if selection != 0 {
                msg("[ntrays-rs] legacy syscall indexes not migrated: table provenance SHA is not confirmed\n");
                writable = false; // leave the new format absent so a later confirmed migration can import it
            }
            Ok(syscall_state::State::default())
        } else if selection == 1 {
            db::syscall_read(1, 0).and_then(|b| syscall_state::migrate_map(selection, b.as_deref().unwrap_or(&[])))
        } else { syscall_state::migrate_map(selection, &[]) };
        let mut state = match migrated {
            Ok(state) => state,
            Err(error) => { msg(&format!("[ntrays-rs] legacy syscall migration: {error}; original node preserved\n")); writable = false; syscall_state::State::default() }
        };
        if state.map.is_empty() && (selection == 0 || !legacy_confirmed) {
            state.map = db::exported_syscalls();
            if !state.map.is_empty() && log_level >= 1 { msg(&format!("[ntrays-rs] extracted {} syscall names from IDB exports\n", state.map.len())); }
        }
        if writable && ((legacy_confirmed && selection != 0) || !state.map.is_empty()) {
            match state.encode() {
                Ok(bytes) if db::syscall_write(0, 0, &bytes) => (),
                _ => { msg("[ntrays-rs] could not commit syscall map; original data preserved\n"); writable = false; }
            }
        }
        Self { state, writable, legacy_confirmed }
    }

    fn site(&self, ea: u64) -> Result<syscall_state::CallInfo, String> {
        match db::syscall_read(2, ea).and_then(|blob| blob.map(|b| syscall_state::CallInfo::decode(&b)).transpose()) {
            Ok(Some(info)) => return Ok(info),
            Ok(None) => (),
            Err(error) => { msg(&format!("[ntrays-rs] callsite {ea:X}: {error}; override not changed\n")); return Err(error); }
        }
        let raw = db::legacy_site(ea);
        if raw == 0 { return Ok(syscall_state::CallInfo::default()); }
        if !self.legacy_confirmed {
            let error = "legacy override not migrated without table provenance SHA".to_string();
            msg(&format!("[ntrays-rs] callsite {ea:X}: {error}\n"));
            return Err(error);
        }
        match syscall_state::migrate_call(raw) {
            Ok(info) => {
                if self.writable {
                    if let Ok(bytes) = info.encode() {
                        if !db::syscall_write(2, ea, &bytes) { msg("[ntrays-rs] could not persist migrated syscall override\n"); }
                    }
                }
                Ok(info)
            }
            Err(error) => { msg(&format!("[ntrays-rs] legacy callsite {ea:X}: {error}; original node preserved\n")); Err(error) }
        }
    }
}

/// Called only inside the guarded lifter entry point; the pointer belongs to its current plugmod/IDB.
pub(crate) fn syscall_info(state: *mut c_void, ea: u64, stub_id: Option<u32>, function: &str) -> (Option<u32>, Option<&'static syscall::Api>) {
    let Some(plugin) = (unsafe { state.cast::<Plugin>().as_ref() }) else { return (stub_id, syscall::find_api(function)) };
    let syscalls = plugin.syscalls.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(site) = syscalls.site(ea) else { return (stub_id, None) };
    let (number, name) = syscalls.state.resolve(&site, stub_id, function);
    (number, syscall::find_api(name))
}

/// Per-database plugin state.
struct Plugin {
    supported: bool,
    /// Fold rules resolved to addresses; `None` until first use and after any rename in the database.
    folds: Mutex<Option<fold::Resolved>>,
    syscalls: Mutex<DbSyscalls>,
    settings: Mutex<settings::Loaded>,
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_init() -> *mut c_void {
    guard("init", std::ptr::null_mut(), || {
        if !tables_match() {
            msg("[ntrays] shim and Rust tables differ; plugin not loaded\n");
            return std::ptr::null_mut();
        }
        let options = settings::Loaded::load();
        if options.value.log_level >= 1 {
            msg(&format!("[ntrays-rs] loaded, built for IDA SDK {}\n", env!("IDA_SDK_VERSION")));
        }
        let syscalls = if db::is_pe64() && options.value.component(1) { DbSyscalls::load(options.value.log_level) } else { DbSyscalls { state: syscall_state::State::default(), writable: false, legacy_confirmed: false } };
        let plugin = Box::new(Plugin { supported: db::is_pe64(), folds: Mutex::new(None), syscalls: Mutex::new(syscalls), settings: Mutex::new(options) });
        settings::apply_database_options(&plugin);
        Box::into_raw(plugin).cast()
    })
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_term(state: *mut c_void) {
    guard("term", (), || drop(unsafe { Box::from_raw(state.cast::<Plugin>()) }))
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_run(state: *mut c_void, arg: usize) -> bool {
    guard("run", false, || {
        // The packed versioned value is also accepted for scripted per-IDB configuration.
        if arg != 0 { return settings::ntrays_settings_apply(state, arg as u64); }
        unsafe { settings::ntrays_settings_dialog(state) }
    })
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_lift(state: *mut c_void, builder: *mut c_void, kind: u32) -> bool {
    guard("lift", false, || {
        let Some(plugin) = (unsafe { state.cast::<Plugin>().as_ref() }) else { return false };
        let Some(insn) = mc::Insn::from_index(kind) else { return false };
        let mut e = unsafe { mc::Emitter::new(builder) };
        let component = if insn == mc::Insn::Syscall || (insn == mc::Insn::Int && e.insn().ops[0].value == 0x2e) { 1 }
            else if insn == mc::Insn::Nop { 4 } else { 0 };
        if !settings::component(plugin, component) { return false; }
        if settings::value(plugin).log_level >= 2 { msg(&format!("[ntrays-rs] lift {insn:?} at {:X}\n", e.insn().ea)); }
        lift::lift(&mut e, insn, state)
    })
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_fold(state: *mut c_void, site: u32, ea: u64, value: u64) -> bool {
    guard("fold", false, || {
        let Some(site) = fold::Site::from_u32(site) else { return false };
        let plugin = unsafe { &*state.cast::<Plugin>() };
        if !settings::component(plugin, 2) { return false; }
        let options = settings::value(plugin);
        let mut folds = plugin.folds.lock().unwrap_or_else(|e| e.into_inner());
        folds
            .get_or_insert_with(|| fold::Resolved::new(options.fold_hvl, db::name_ea))
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
