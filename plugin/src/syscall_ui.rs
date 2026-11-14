//! Explicit UI changes to the current IDB's syscall state. Chooser reads never migrate or write data.
use std::ffi::{CStr, c_char, c_void};

use ntrays_core::{syscall, syscall_presets, syscall_state};

use crate::{DbSyscalls, Plugin, db, guard, msg};

unsafe extern "C" {
    fn ntrays_ui_is_syscall(ea: u64) -> bool;
}

fn plugin(state: *mut c_void) -> Result<&'static Plugin, String> {
    let plugin = unsafe { state.cast::<Plugin>().as_ref() }.ok_or("no current NtRays database")?;
    if !crate::settings::ntrays_component_enabled(state, 1) { return Err("NtRays syscall component is disabled".into()); }
    Ok(plugin)
}

fn writable(syscalls: &DbSyscalls) -> Result<(), String> {
    if syscalls.writable { Ok(()) } else {
        Err("stored syscall state is protected (unknown format, corruption or unconfirmed legacy table); no changes made".into())
    }
}

fn read_site(syscalls: &DbSyscalls, ea: u64) -> Result<syscall_state::CallInfo, String> {
    if let Some(blob) = db::syscall_read(2, ea)? {
        return syscall_state::CallInfo::decode(&blob);
    }
    let legacy = db::legacy_site(ea);
    if legacy == 0 { return Ok(syscall_state::CallInfo::default()); }
    if !syscalls.legacy_confirmed { return Err("legacy override requires table provenance confirmation".into()); }
    syscall_state::migrate_call(legacy)
}

fn commit_map(syscalls: &mut DbSyscalls, map: syscall::SyscallMap) -> Result<(), String> {
    writable(syscalls)?;
    let next = syscall_state::State { map };
    let blob = next.encode()?;
    if !db::syscall_write(0, 0, &blob) { return Err("could not commit syscall map; current map unchanged".into()); }
    syscalls.state = next;
    Ok(())
}

fn report(result: Result<(), String>) -> bool {
    match result {
        Ok(()) => true,
        Err(error) => { msg(&format!("[ntrays-rs] {error}\n")); false }
    }
}

fn copy_text(text: &str, out: *mut c_char, cap: usize) -> bool {
    if out.is_null() || text.len() >= cap { return false; }
    unsafe {
        std::ptr::copy_nonoverlapping(text.as_ptr(), out.cast(), text.len());
        *out.add(text.len()) = 0;
    }
    true
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_ui_api_count() -> u32 { syscall::apis().len() as u32 + 1 }

#[unsafe(no_mangle)]
extern "C" fn ntrays_ui_api_row(index: u32, field: u32, out: *mut c_char, cap: usize) -> bool {
    guard("api_row", false, || {
        if field > 1 { return false; }
        if index == 0 { return copy_text(if field == 0 { "Automatic" } else { "Resolve from the stub and current map" }, out, cap); }
        let Some(api) = syscall::apis().get(index as usize - 1) else { return false; };
        if field == 0 { return copy_text(api.name, out, cap); }
        let args = api.args.iter().map(|(ty, name)| format!("{ty} {name}")).collect::<Vec<_>>().join(", ");
        copy_text(&format!("{} ({args})", api.ret), out, cap)
    })
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_ui_api_selection(state: *mut c_void, ea: u64) -> i64 {
    guard("api_selection", -1, || {
        let Ok(plugin) = plugin(state) else { return -1; };
        let syscalls = plugin.syscalls.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(site) = read_site(&syscalls, ea) else { return -1; };
        match site.api {
            None => 0,
            Some(name) => syscall::apis().iter().position(|a| a.name == name).map_or(-1, |i| i as i64 + 1),
        }
    })
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_ui_set_api(state: *mut c_void, ea: u64, index: u32) -> bool {
    guard("set_api", false, || report((|| {
        let plugin = plugin(state)?;
        if !db::is_pe64() || !unsafe { ntrays_ui_is_syscall(ea) } { return Err("selection is not a syscall instruction".into()); }
        let syscalls = plugin.syscalls.lock().unwrap_or_else(|e| e.into_inner());
        writable(&syscalls)?;
        let mut site = read_site(&syscalls, ea)?;
        site.api = if index == 0 { None } else {
            Some(syscall::apis().get(index as usize - 1).ok_or("invalid API selection")?.name.into())
        };
        let blob = site.encode()?;
        if !db::syscall_write(2, ea, &blob) { return Err("could not commit syscall override".into()); }
        Ok(())
    })()))
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_ui_preset_count() -> u32 { syscall_presets::PRESETS.len() as u32 + 2 }

#[unsafe(no_mangle)]
extern "C" fn ntrays_ui_preset_row(index: u32, out: *mut c_char, cap: usize) -> bool {
    guard("preset_row", false, || {
        let label = match index {
            0 => "Disable number-to-name map".to_owned(),
            1 => "Import ntdll.dll or win32u.dll (merge syscall space)".to_owned(),
            n => {
                let Some(p) = syscall_presets::PRESETS.get(n as usize - 2) else { return false; };
                format!("{} [{}] — {} NT / {} GUI", p.label, p.id, p.nt.len(), p.win32k.len())
            }
        };
        copy_text(&label, out, cap)
    })
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_ui_preset_selection(state: *mut c_void) -> i64 {
    guard("preset_selection", -1, || {
        let Ok(plugin) = plugin(state) else { return -1; };
        let syscalls = plugin.syscalls.lock().unwrap_or_else(|e| e.into_inner());
        if syscalls.state.map.is_empty() { return 0; }
        syscall_presets::PRESETS.iter().position(|p| p.map() == syscalls.state.map).map_or(1, |i| i as i64 + 2)
    })
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_ui_set_preset(state: *mut c_void, index: u32) -> bool {
    guard("set_preset", false, || report((|| {
        if !db::is_pe64() { return Err("syscall maps require an x64 PE database".into()); }
        let map = match index {
            0 => syscall::SyscallMap::new(),
            n if n >= 2 => syscall_presets::PRESETS.get(n as usize - 2).ok_or("invalid Windows selection")?.map(),
            _ => return Err("use a selected DLL file for import".into()),
        };
        let plugin = plugin(state)?;
        let mut syscalls = plugin.syscalls.lock().unwrap_or_else(|e| e.into_inner());
        commit_map(&mut syscalls, map)
    })()))
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_ui_import_map(state: *mut c_void, path: *const c_char) -> bool {
    guard("import_map", false, || report((|| {
        if path.is_null() || !db::is_pe64() { return Err("no x64 PE database or import file selected".into()); }
        let path = unsafe { CStr::from_ptr(path) }.to_str().map_err(|_| "invalid file name encoding")?;
        let file = std::fs::File::open(path).map_err(|e| format!("cannot open syscall DLL: {e}"))?;
        let mut bytes = Vec::new();
        use std::io::Read;
        file.take(256 * 1024 * 1024 + 1).read_to_end(&mut bytes).map_err(|e| format!("cannot read syscall DLL: {e}"))?;
        if bytes.len() > 256 * 1024 * 1024 { return Err("syscall DLL exceeds 256 MiB".into()); }
        let imported = syscall::read_syscall_map(&bytes)?;
        let gui = imported.keys().all(|&n| (0x1000..0x2000).contains(&n));
        let nt = imported.keys().all(|&n| n < 0x1000);
        if !gui && !nt { return Err("DLL contains mixed or unsupported syscall number spaces".into()); }
        let plugin = plugin(state)?;
        let mut syscalls = plugin.syscalls.lock().unwrap_or_else(|e| e.into_inner());
        writable(&syscalls)?;
        // Importing the second DLL replaces its own number space, retaining the first DLL's map.
        let mut map = syscalls.state.map.clone();
        map.retain(|&n, _| if gui { !(0x1000..0x2000).contains(&n) } else { n >= 0x1000 });
        map.extend(imported);
        commit_map(&mut syscalls, map)
    })()))
}
