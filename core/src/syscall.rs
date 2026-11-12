//! System calls: Nt* API signatures, syscall numbers from stubs, and number → API maps from ntdll/win32u.

use std::collections::BTreeMap;

/// An Nt* API signature: C type names as written in the headers (resolved against the database's types).
#[derive(Debug)]
pub struct Api {
    pub name: &'static str,
    pub ret: &'static str,
    pub args: &'static [(&'static str, &'static str)],
}

/// Signature of an Nt*/Zw* API, if known.
pub fn find_api(name: &str) -> Option<&'static Api> {
    let name = nt_name(name)?;
    let apis = crate::syscall_table::APIS;
    apis.binary_search_by(|a| a.name.cmp(name.as_str())).ok().map(|i| &apis[i])
}

/// `ZwClose`/`NtClose` → `NtClose`; anything else → `None`.
pub fn nt_name(name: &str) -> Option<String> {
    let rest = name.strip_prefix("Nt").or_else(|| name.strip_prefix("Zw"))?;
    rest.starts_with(|c: char| c.is_ascii_uppercase()).then(|| format!("Nt{rest}"))
}

/// `mov r10, rcx; mov eax, imm32`: how every syscall stub in ntdll/win32u starts.
const STUB_HEAD: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];
/// Since Windows 10 the stub checks `KUSER_SHARED_DATA.SystemCall` before `syscall`:
/// `test byte ptr [7FFE0308h], 1; jnz +3`.
const STUB_TEST: [u8; 10] = [0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01, 0x75, 0x03];

/// Bytes to read before a `syscall` instruction for `stub_id`.
pub const STUB_LOOKBEHIND: usize = 18;

/// The syscall number of a stub, given the `STUB_LOOKBEHIND` bytes right before its `syscall` instruction.
pub fn stub_id(before: &[u8]) -> Option<u32> {
    let imm = |at: &[u8]| Some(u32::from_le_bytes(at.get(4..8)?.try_into().ok()?));
    let n = before.len();
    // Windows 10+: head, imm32, test, jnz, syscall.
    if n >= 18 && before[n - 18..n - 14] == STUB_HEAD && before[n - 10..] == STUB_TEST {
        return imm(&before[n - 18..]);
    }
    // Older layout: head, imm32, syscall.
    if n >= 8 && before[n - 8..n - 4] == STUB_HEAD {
        return imm(&before[n - 8..]);
    }
    None
}

/// Syscall number → API name (`Nt` prefix), as exported by an ntdll.dll or win32u.dll.
pub type SyscallMap = BTreeMap<u32, String>;

/// Reads syscall numbers from the stubs of an ntdll.dll / win32u.dll image (x64 PE file contents).
///
/// The number is taken from each stub's `mov eax, imm32`, not from the order of exports by address (what the
/// original did), so an export the API table does not know cannot shift the numbers of the ones after it.
pub fn read_syscall_map(pe: &[u8]) -> Result<SyscallMap, String> {
    use object::read::pe::{ExportTarget, PeFile64};

    let file = PeFile64::parse(pe).map_err(|e| format!("not an x64 PE file: {e}"))?;
    let exports = match file.export_table().map_err(|e| format!("bad export table: {e}"))? {
        Some(table) => table.exports().map_err(|e| format!("bad export table: {e}"))?,
        None => Vec::new(),
    };
    let sections = file.section_table();
    let mut map = SyscallMap::new();
    for export in exports {
        let (Some(name), ExportTarget::Address(rva)) = (export.name, export.target) else { continue };
        let Some(nt) = std::str::from_utf8(name).ok().and_then(nt_name) else { continue };
        let Some(code) = sections.pe_data_at(pe, rva).and_then(|d| d.get(..8)) else { continue };
        if code[..4] == STUB_HEAD {
            let id = u32::from_le_bytes(code[4..8].try_into().unwrap());
            map.entry(id).or_insert(nt);
        }
    }
    if map.is_empty() {
        return Err("no syscall stubs found (not an ntdll.dll / win32u.dll?)".into());
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_normalize() {
        assert_eq!(nt_name("ZwClose").as_deref(), Some("NtClose"));
        assert_eq!(nt_name("NtClose").as_deref(), Some("NtClose"));
        assert_eq!(nt_name("Ntoskrnl"), None);
        assert_eq!(nt_name("RtlFoo"), None);
    }

    #[test]
    fn api_lookup() {
        let api = find_api("ZwClose").unwrap();
        assert_eq!((api.name, api.ret, api.args), ("NtClose", "NTSTATUS", &[("HANDLE", "Handle")][..]));
        assert!(find_api("NtDefinitelyNotAnApi").is_none());
        let names: Vec<_> = crate::syscall_table::APIS.iter().map(|a| a.name).collect();
        assert!(names.windows(2).all(|w| w[0] < w[1]), "table must stay sorted");
    }

    #[test]
    fn stub_layouts() {
        let mut win10 = vec![0x4C, 0x8B, 0xD1, 0xB8, 0x0F, 0, 0, 0];
        win10.extend_from_slice(&STUB_TEST);
        assert_eq!(stub_id(&win10), Some(0x0F));
        assert_eq!(stub_id(&[0x90, 0x90, 0x4C, 0x8B, 0xD1, 0xB8, 0x34, 0x12, 0, 0]), Some(0x1234));
        assert_eq!(stub_id(&[0x90; 18]), None);
    }

    /// Reads this machine's ntdll/win32u, if present: every stub number must also be what `stub_id` sees.
    #[test]
    fn system_dlls() {
        for (path, min_id) in [(r"C:\Windows\System32\ntdll.dll", 0), (r"C:\Windows\System32\win32u.dll", 0x1000)] {
            let Ok(pe) = std::fs::read(path) else { continue };
            let map = read_syscall_map(&pe).unwrap();
            assert!(map.len() > 300, "{path}: only {} syscalls", map.len());
            assert!(map.keys().all(|&id| id >= min_id && id < min_id + 0x1000));
            if min_id == 0 {
                assert!(map.values().any(|n| n == "NtClose"));
            }
        }
    }
}
