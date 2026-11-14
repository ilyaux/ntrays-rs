//! Explicit x64 Windows release presets; never infer a release from the host OS or just the build number.
//! Rebuild the offline tables with `python -I tools/gen_syscall_presets.py`.

use crate::syscall::SyscallMap;

#[path = "syscall_presets_data.rs"]
mod data;
pub use data::{CAPTURE_SOURCE, PRESETS};

pub const SOURCE_COMMIT: &str = "8a6806ac9148633e8afbbdb42e6002930b002741";

/// The captured entry is an observed export-stub map, not a claim about the complete SSDT or an OS edition.
#[derive(Debug)]
pub struct CaptureSource {
    pub preset_id: &'static str,
    pub file_version: &'static str,
    pub ntdll_sha256: &'static str,
    pub win32u_sha256: &'static str,
    /// SHA-256 of core/src/syscall.rs after CRLF→LF normalization.
    pub parser_sha256: &'static str,
}

#[derive(Debug)]
pub struct Preset {
    /// Stable persisted identifier, independent of this array's order.
    pub id: &'static str,
    pub label: &'static str,
    /// Release build family, not a claim that every servicing revision has the same syscall map.
    pub build: u32,
    pub nt: &'static [(u32, &'static str)],
    pub win32k: &'static [(u32, &'static str)],
}

impl Preset {
    /// Includes both NT (0x0000..) and GUI (0x1000..) syscall spaces, stored by API name.
    pub fn map(&self) -> SyscallMap {
        self.nt.iter().chain(self.win32k).map(|&(id, name)| (id, name.to_owned())).collect()
    }
}

pub fn find(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|preset| preset.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn pinned_releases_and_core_apis() {
        assert_eq!(PRESETS.len(), 4);
        for (id, build, gui_count) in [
            ("win11-24h2-x64", 26100, 1477),
            ("win11-25h2-x64", 26200, 1485),
            ("server-2025-x64", 26100, 1480),
        ] {
            let preset = find(id).unwrap();
            assert_eq!((preset.build, preset.nt.len(), preset.win32k.len()), (build, 489, gui_count));
            let map = preset.map();
            assert_eq!(map.len(), 489 + gui_count);
            assert_eq!(map.get(&0x000F).map(String::as_str), Some("NtClose"));
            assert_eq!(map.get(&0x0055).map(String::as_str), Some("NtCreateFile"));
            assert_eq!(map.get(&0x1000).map(String::as_str), Some("NtUserGetThreadState"));
            assert_eq!(map.get(&0x1006).map(String::as_str), Some("NtGdiBitBlt"));
        }
        assert!(find("Windows 11").is_none());
        assert!(find("win11-26h2-x64").is_none());
    }

    #[test]
    fn gui_maps_must_not_alias_versions_or_server_with_the_same_build() {
        let old = find("win11-24h2-x64").unwrap().map();
        let new = find("win11-25h2-x64").unwrap().map();
        let server = find("server-2025-x64").unwrap().map();
        assert_ne!(old, new);
        assert_ne!(old, server);
        assert_eq!(old.get(&0x110E).map(String::as_str), Some("NtCompositionSetDropTarget"));
        assert_eq!(new.get(&0x110D).map(String::as_str), Some("NtCompositionSetDropTarget"));
        assert!(!old.values().any(|n| n == "NtDCompositionSendDwmLpcMessage"));
        assert_eq!(new.get(&0x1137).map(String::as_str), Some("NtDCompositionSendDwmLpcMessage"));
        assert_eq!(server.get(&0x1138).map(String::as_str), Some("NtDCompositionSendDwmLpcMessage"));
    }

    #[test]
    fn table_ranges_order_and_names_are_unambiguous() {
        for preset in PRESETS {
            for (table, low) in [(preset.nt, 0), (preset.win32k, 0x1000)] {
                assert!(table.windows(2).all(|p| p[0].0 < p[1].0));
                assert!(table.iter().all(|&(id, name)| (low..low + 0x1000).contains(&id) && name.starts_with("Nt")));
                assert_eq!(table.len(), table.iter().map(|entry| entry.1).collect::<BTreeSet<_>>().len());
            }
        }
    }

    #[test]
    fn returned_maps_are_independently_owned() {
        let preset = find("win11-24h2-x64").unwrap();
        let mut changed = preset.map();
        changed.insert(0x000F, "NtDifferent".into());
        assert_eq!(preset.map().get(&0x000F).map(String::as_str), Some("NtClose"));
    }

    #[test]
    fn captured_snapshot_is_distinct_and_bound_to_exact_files() {
        let captured = find(CAPTURE_SOURCE.preset_id).unwrap();
        let map = captured.map();
        assert_eq!(CAPTURE_SOURCE.file_version, "10.0.26100.9711");
        assert_eq!((captured.nt.len(), captured.win32k.len()), (489, 1498));
        assert_eq!(map.get(&0x011C).map(String::as_str), Some("NtManageWobTicket"));
        assert_ne!(map, find("win11-24h2-x64").unwrap().map());
        assert!(!captured.label.contains("Windows 11"));
        for hash in [CAPTURE_SOURCE.ntdll_sha256, CAPTURE_SOURCE.win32u_sha256, CAPTURE_SOURCE.parser_sha256] {
            assert_eq!(hash.len(), 64);
            assert!(hash.bytes().all(|c| c.is_ascii_hexdigit()));
        }
    }
}
