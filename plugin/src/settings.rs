use std::ffi::c_void;

use ntrays_core::settings::Settings;

use crate::{Plugin, db, guard, msg};

unsafe extern "C" {
    fn ntrays_db_settings_read(value: *mut u64) -> bool;
    fn ntrays_db_settings_write(value: u64) -> bool;
    fn ntrays_db_set_kuser_wanted(enabled: bool);
    fn ntrays_db_apply_kernel_exit_type();
    fn ntrays_ui_refresh();
    pub fn ntrays_settings_dialog(state: *mut c_void) -> bool;
}

pub struct Loaded {
    pub value: Settings,
    pub writable: bool,
}

impl Loaded {
    pub fn load() -> Self {
        let mut raw = 0;
        if !unsafe { ntrays_db_settings_read(&mut raw) } {
            msg("[ntrays-rs] settings could not be read; transformations disabled\n");
            return Self::invalid();
        }
        if raw == 0 {
            return Self { value: Settings { enabled: db::is_pe64(), fold_hvl: db::setting(db::FOLD_HVL) != 0, ..Settings::default() }, writable: true };
        }
        match Settings::decode(raw) {
            Ok(value) => Self { value, writable: true },
            Err(error) => {
                msg(&format!("[ntrays-rs] {error}; stored value preserved and transformations disabled\n"));
                Self::invalid()
            }
        }
    }

    fn invalid() -> Self {
        Self { value: Settings { enabled: false, components: 0, fold_hvl: false, log_level: 0 }, writable: false }
    }
}

pub fn value(plugin: &Plugin) -> Settings {
    plugin.settings.lock().unwrap_or_else(|e| e.into_inner()).value
}

pub fn component(plugin: &Plugin, index: u32) -> bool {
    plugin.supported && value(plugin).component(index)
}

pub fn apply_database_options(plugin: &Plugin) {
    if !db::is_pe64() { return; }
    let options = value(plugin);
    if options.component(4) { db::patch_rsb_gadgets(options.log_level); }
    unsafe { ntrays_db_set_kuser_wanted(options.component(5)) };
    if options.component(3) {
        db::use_parent_types(options.log_level);
        unsafe { ntrays_db_apply_kernel_exit_type() };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ntrays_component_enabled(state: *mut c_void, index: u32) -> bool {
    guard("component_enabled", false, || {
        unsafe { state.cast::<Plugin>().as_ref() }.is_some_and(|plugin| component(plugin, index))
    })
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_settings_value(state: *mut c_void) -> u64 {
    guard("settings_value", 0, || {
        let Some(plugin) = (unsafe { state.cast::<Plugin>().as_ref() }) else { return 0 };
        value(plugin).encode().unwrap_or(0)
    })
}

#[unsafe(no_mangle)]
extern "C" fn ntrays_settings_writable(state: *mut c_void) -> bool {
    guard("settings_writable", false, || {
        let Some(plugin) = (unsafe { state.cast::<Plugin>().as_ref() }) else { return false };
        plugin.settings.lock().unwrap_or_else(|e| e.into_inner()).writable
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ntrays_settings_apply(state: *mut c_void, raw: u64) -> bool {
    guard("settings_apply", false, || {
        let Some(plugin) = (unsafe { state.cast::<Plugin>().as_ref() }) else { return false };
        let Ok(options) = Settings::decode(raw) else { return false };
        let mut loaded = plugin.settings.lock().unwrap_or_else(|e| e.into_inner());
        if !loaded.writable {
            msg("[ntrays-rs] settings are read-only because their stored format is unsupported\n");
            return false;
        }
        if loaded.value == options { return true; }
        if !unsafe { ntrays_db_settings_write(raw) } {
            msg("[ntrays-rs] settings could not be saved; active options unchanged\n");
            return false;
        }
        let old = loaded.value;
        loaded.value = options;
        drop(loaded);
        *plugin.folds.lock().unwrap_or_else(|e| e.into_inner()) = None;
        if !old.component(1) && options.component(1) && db::is_pe64() {
            *plugin.syscalls.lock().unwrap_or_else(|e| e.into_inner()) = crate::DbSyscalls::load(options.log_level);
        }
        apply_database_options(plugin);
        unsafe { ntrays_ui_refresh() };
        if options.log_level >= 1 { msg("[ntrays-rs] database settings saved\n"); }
        true
    })
}
