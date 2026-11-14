//! Per-IDB syscall maps persisted by NAME. The SDK adapter stores per-EA overrides in address-aware supvals.
use crate::syscall::{SyscallMap, nt_name};

const MAGIC: &[u8; 8] = b"NTRSCM\x01\0";
pub const MAX_BLOB: usize = 8 * 1024 * 1024;
/// The original format had no fingerprint; the SDK adapter requires this explicit provenance confirmation.
pub const LEGACY_TABLE_SHA256: &str = "c7929397db55812e0307845e700169a0b36ff2687e992156c0207c16f054bc26";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallInfo {
    pub number: Option<u32>,
    pub api: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub map: SyscallMap,
}

fn valid_name(name: &str) -> bool {
    name.len() <= 255
        && nt_name(name).as_deref() == Some(name)
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn put_name(out: &mut Vec<u8>, name: &str) -> Result<(), String> {
    if !valid_name(name) {
        return Err("invalid Nt API name".into());
    }
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    Ok(())
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let (head, tail) = self.0.split_at_checked(count).ok_or("truncated syscall state")?;
        self.0 = tail;
        Ok(head)
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn name(&mut self) -> Result<String, String> {
        let count = self.u16()? as usize;
        let name = std::str::from_utf8(self.take(count)?).map_err(|_| "invalid API encoding")?;
        if !valid_name(name) {
            return Err("invalid Nt API name".into());
        }
        Ok(name.into())
    }
    fn end(self) -> Result<(), String> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err("trailing syscall state bytes".into())
        }
    }
}

impl State {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut out = MAGIC.to_vec();
        let count = u32::try_from(self.map.len()).map_err(|_| "too many syscalls")?;
        out.extend_from_slice(&count.to_le_bytes());
        for (&id, name) in &self.map {
            out.extend_from_slice(&id.to_le_bytes());
            put_name(&mut out, name)?;
        }
        if out.len() > MAX_BLOB {
            return Err("syscall map exceeds 8 MiB".into());
        }
        Ok(out)
    }

    pub fn decode(blob: &[u8]) -> Result<Self, String> {
        if blob.len() > MAX_BLOB {
            return Err("syscall map exceeds 8 MiB".into());
        }
        let mut r = Reader(blob);
        if r.take(MAGIC.len())? != MAGIC {
            return Err("unsupported syscall state format".into());
        }
        let count = r.u32()? as usize;
        if count > r.0.len() / 9 {
            return Err("invalid syscall map count".into());
        }
        let mut map = SyscallMap::new();
        for _ in 0..count {
            let id = r.u32()?;
            if map.insert(id, r.name()?).is_some() {
                return Err("duplicate syscall number".into());
            }
        }
        r.end()?;
        Ok(State { map })
    }

    /// Explicit API override wins; exact stub bytes win over an older inferred syscall number.
    pub fn resolve<'a>(
        &'a self,
        site: &'a CallInfo,
        stub_id: Option<u32>,
        function: &'a str,
    ) -> (Option<u32>, &'a str) {
        let number = stub_id.or(site.number);
        let api = site
            .api
            .as_deref()
            .or_else(|| number.and_then(|n| self.map.get(&n).map(String::as_str)));
        (number, api.unwrap_or(function))
    }
}

impl CallInfo {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut out = vec![1, u8::from(self.number.is_some())];
        out.extend_from_slice(&self.number.unwrap_or(0).to_le_bytes());
        if let Some(name) = &self.api {
            put_name(&mut out, name)?;
        } else {
            out.extend_from_slice(&0u16.to_le_bytes());
        }
        Ok(out)
    }
    pub fn decode(blob: &[u8]) -> Result<Self, String> {
        let mut r = Reader(blob);
        if r.take(1)? != [1] {
            return Err("unsupported syscall callsite format".into());
        }
        let flag = r.take(1)?[0];
        if flag > 1 {
            return Err("invalid syscall number flag".into());
        }
        let number = r.u32()?;
        if flag == 0 && number != 0 {
            return Err("noncanonical absent syscall number".into());
        }
        let api = if r.0.starts_with(&[0, 0]) {
            r.take(2)?;
            None
        } else {
            Some(r.name()?)
        };
        r.end()?;
        Ok(Self {
            number: (flag == 1).then_some(number),
            api,
        })
    }
}

fn legacy_name(id: u16) -> Result<Option<String>, String> {
    if id == 0 {
        return Ok(None);
    }
    crate::legacy_syscalls::API_NAMES
        .get(id as usize - 1)
        .map(|s| Some((*s).into()))
        .ok_or_else(|| format!("unsupported legacy API index {id}"))
}

pub fn migrate_call(raw: u64) -> Result<CallInfo, String> {
    if raw >> 32 != 0 {
        return Err("unsupported legacy callsite bits".into());
    }
    let encoded_number = raw as u16;
    Ok(CallInfo {
        number: (encoded_number != 0).then(|| u32::from(encoded_number - 1)),
        api: legacy_name((raw >> 16) as u16)?,
    })
}

/// Original NtRays: selection 0 = none, 1 = custom LE-u16 blob, >=2 = frozen preset index.
pub fn migrate_map(selection: u64, blob: &[u8]) -> Result<State, String> {
    let (nt, win32k);
    let (nt, win32k) = match selection {
        0 => return Ok(State::default()),
        1 => {
            let mut r = Reader(blob);
            let nt_count = r.u16()? as usize;
            let win_count = r.u16()? as usize;
            if nt_count > 4096 || win_count > 4096 || r.0.len() != (nt_count + win_count) * 2 {
                return Err("invalid legacy syscall map size".into());
            }
            nt = (0..nt_count).map(|_| r.u16()).collect::<Result<Vec<_>, _>>()?;
            win32k = (0..win_count).map(|_| r.u16()).collect::<Result<Vec<_>, _>>()?;
            (nt.as_slice(), win32k.as_slice())
        }
        n => *crate::legacy_syscalls::PRESETS
            .get(usize::try_from(n - 2).map_err(|_| "legacy preset overflow")?)
            .ok_or("unsupported legacy preset index")?,
    };
    let mut state = State::default();
    for (base, ids) in [(0, nt), (0x1000, win32k)] {
        for (index, &id) in ids.iter().enumerate() {
            if let Some(name) = legacy_name(id)? {
                state.map.insert(base + index as u32, name);
            }
        }
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_roundtrip_and_database_isolation() {
        let mut a = State::default();
        a.map.insert(15, "NtClose".into());
        let b = State::decode(&a.encode().unwrap()).unwrap();
        a.map.insert(15, "NtTestAlert".into());
        assert_eq!(b.map[&15], "NtClose");
        assert_eq!(State::default().map.get(&15), None);
        let info = CallInfo {
            number: Some(0),
            api: Some("NtClose".into()),
        };
        assert_eq!(CallInfo::decode(&info.encode().unwrap()).unwrap(), info);
    }

    #[test]
    fn legacy_numbers_keep_holes_and_unknown_indexes_are_not_guessed() {
        // Anchors from the pinned ORIGINAL table; current signature ordering must not redefine old IDs.
        assert_eq!(crate::legacy_syscalls::API_NAMES[61], "NtClose");
        assert_eq!(crate::legacy_syscalls::API_NAMES[437], "NtTestAlert");
        assert_eq!(crate::legacy_syscalls::API_NAMES[926], "NtTokenManagerCreateFlipObjectReturnTokenHandle");
        assert_eq!(crate::legacy_syscalls::API_NAMES[2253], "NtGdiIcmBrushInfo");
        let close = crate::legacy_syscalls::API_NAMES
            .iter()
            .position(|&n| n == "NtClose")
            .unwrap() as u16
            + 1;
        let mut blob = vec![3, 0, 1, 0];
        for n in [0, close, 0, close] {
            blob.extend_from_slice(&n.to_le_bytes());
        }
        let state = migrate_map(1, &blob).unwrap();
        assert_eq!(state.map.keys().copied().collect::<Vec<_>>(), [1, 0x1000]);
        assert_eq!(state.map[&1], "NtClose");
        assert_eq!(
            migrate_call((u64::from(close) << 16) | 16).unwrap(),
            CallInfo {
                number: Some(15),
                api: Some("NtClose".into())
            }
        );
        assert!(migrate_call(u64::from(u16::MAX) << 16).is_err());
        assert!(migrate_map(1, &[2, 0, 0, 0, 1, 0]).is_err());
        assert!(migrate_map(u64::MAX, &[]).is_err());
        assert!(migrate_map(2, &[]).unwrap().map.len() > 300);
    }

    #[test]
    fn corruption_and_future_versions_are_rejected() {
        let mut state = State::default();
        state.map.insert(15, "NtClose".into());
        let blob = state.encode().unwrap();
        for count in 0..blob.len() {
            assert!(State::decode(&blob[..count]).is_err());
        }
        let mut future = blob.clone();
        future[6] += 1;
        assert!(State::decode(&future).is_err());
        let mut trailing = blob.clone();
        trailing.push(0);
        assert!(State::decode(&trailing).is_err());
        let mut duplicate = blob.clone();
        duplicate[8..12].copy_from_slice(&2u32.to_le_bytes());
        duplicate.extend_from_slice(&blob[12..]);
        assert!(State::decode(&duplicate).is_err());
    }

    #[test]
    fn overrides_and_exact_stub_number_have_explicit_precedence() {
        let state = State {
            map: [(15, "NtClose".into())].into(),
        };
        let mut site = CallInfo {
            number: Some(99),
            api: None,
        };
        assert_eq!(state.resolve(&site, Some(15), "OpaqueStub"), (Some(15), "NtClose"));
        site.api = Some("NtTestAlert".into());
        assert_eq!(state.resolve(&site, Some(15), "NtClose"), (Some(15), "NtTestAlert"));
        assert_eq!(
            State::default().resolve(&CallInfo::default(), None, "NtClose"),
            (None, "NtClose")
        );
    }
}
