//! Windows Driver Intelligence: the result contract for one analyzed WDM x64 driver (`DriverOverview`).
//!
//! The IDA adapter extracts facts, the Rust core builds this structure, and the UI, cache and JSON export read
//! it. Rules the types encode:
//!
//! - Every fact carries `Evidence`: where in the binary it was found, through which helpers, under which path
//!   conditions, with which type layout, and how sure we are (`Status`).
//! - `Status::FoundInCode` means the assignment or comparison exists on some path of the code. It is a static
//!   fact, never a claim that the handler is active at runtime.
//! - "Not found" is not "does not exist": unresolved targets, budget exhaustion and errors are reported in
//!   `Coverage`, and several targets for one slot are kept side by side (see `DriverOverview::conflicts`).
//! - An IOCTL is listed only with evidence that the value is compared against `IoControlCode`. What a command
//!   does is unknown unless separately proven; decoding a number (`crate::ioctl`) explains it, nothing more.
//!
//! Addresses are RVAs (`u32`) relative to `Input::image_base`, so results survive a rebase. The image base itself
//! is serialized as a hex string, because kernel addresses do not fit a JSON number exactly.

use serde::{Deserialize, Serialize};

/// Version of the JSON layout. Bump on any incompatible change; readers refuse versions they do not know.
pub const SCHEMA_VERSION: u32 = 1;

/// How sure a fact is.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The assignment / comparison / call is present in the code on at least one path (not runtime-confirmed).
    FoundInCode,
    /// Inferred from a convention or pattern, not from a direct assignment or comparison.
    Assumed,
    /// Something was seen but could not be resolved (indirect target, unknown layout, out of budget).
    Unresolved,
}

/// What kind of code observation an `Evidence` is.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// A store into a structure field (e.g. `DriverObject->MajorFunction[14] = handler`).
    Store,
    /// A comparison of a value (e.g. `IoControlCode == 0x222004`, including switch cases).
    Compare,
    /// A call (e.g. `IoCreateDevice`, `IoCreateSymbolicLink`).
    Call,
    /// The PE entry point or an exported symbol.
    Entry,
}

/// Where structure offsets used by an observation came from.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum LayoutSource {
    /// The driver's own PDB.
    Pdb,
    /// An IDA type library, e.g. `ntddk64_win10`.
    TypeLibrary { name: String },
    /// A type the user defined or edited in the database.
    UserType,
    /// NtRays' built-in layout for a WDK version and architecture.
    Builtin { wdk: String, arch: String },
}

/// A condition on the path to an observation, as the decompiler shows it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Condition {
    /// RVA of the branch.
    pub site: u32,
    pub text: String,
}

/// Why a fact is believed, and where to look.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub status: Status,
    /// RVA of the instruction that stores / compares / calls.
    pub site: u32,
    /// RVA of the function containing `site`.
    pub function: u32,
    /// Helper functions on the way from the analysis root to `function`, root first (RVAs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<LayoutSource>,
    /// One sentence for the user, e.g. "stored to DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]".
    pub reason: String,
}

/// What a callback / dispatch slot points to.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    /// Code in this image.
    Rva { rva: u32 },
    /// An imported function, e.g. a framework routine.
    Import { module: String, name: String },
    /// A value that could not be resolved to code (computed pointer, loaded from data).
    Unresolved,
}

/// Identity of the analyzed file.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Input {
    /// SHA-256 of the input file, lowercase hex.
    pub sha256: String,
    pub file_name: String,
    #[serde(with = "hex_u64")]
    pub image_base: u64,
    /// PE machine; the MVP supports `"AMD64"` only.
    pub machine: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdb: Option<PdbIdentity>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PdbIdentity {
    pub name: String,
    /// GUID as in the CodeView record, e.g. `"3F2504E0-4F89-11D3-9A0C-0305E82C3301"`.
    pub guid: String,
    pub age: u32,
}

/// Driver model indicators. Several can be present at once (a WDM driver linking a framework).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Framework {
    Wdm,
    Kmdf,
    Minifilter,
    Ndis,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameworkHint {
    pub framework: Framework,
    pub evidence: Vec<Evidence>,
}

/// How the driver is entered.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EntryRole {
    /// `AddressOfEntryPoint` of the PE (often a security-cookie wrapper such as `GsDriverEntry`).
    PeEntry,
    /// The function that initializes the `DRIVER_OBJECT` (the real `DriverEntry`).
    DriverEntry,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryRoot {
    pub role: EntryRole,
    pub target: Target,
    pub evidence: Vec<Evidence>,
}

/// Driver-wide callbacks registered through the `DRIVER_OBJECT`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CallbackRole {
    /// `DriverObject->DriverUnload`
    DriverUnload,
    /// `DriverObject->DriverExtension->AddDevice`
    AddDevice,
    /// `DriverObject->DriverStartIo`
    StartIo,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Callback {
    pub role: CallbackRole,
    pub target: Target,
    pub evidence: Vec<Evidence>,
}

/// One `DriverObject->MajorFunction[major] = target` fact. A slot with several targets (conditional or
/// overwritten assignments) has several entries; one function serving several slots appears once per slot.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IrpHandler {
    /// `IRP_MJ_*` index, 0..=0x1B.
    pub major: u8,
    pub target: Target,
    pub evidence: Vec<Evidence>,
}

/// An I/O control code the driver compares `IoControlCode` against.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ioctl {
    pub code: u32,
    /// `IRP_MJ_DEVICE_CONTROL` (0x0E) or `IRP_MJ_INTERNAL_DEVICE_CONTROL` (0x0F).
    pub major: u8,
    /// The dispatch routine where the comparison was found (a role, not a name).
    pub dispatch: Target,
    /// Code that runs for this code, if resolved (a case body or a called handler).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<Target>,
    pub evidence: Vec<Evidence>,
}

/// A device object the driver creates, with its names.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Device {
    /// `\Device\...` name, if a constant was found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub symbolic_links: Vec<String>,
    /// Device interface class GUIDs (`IoRegisterDeviceInterface`), registry format.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interface_guids: Vec<String>,
    pub evidence: Vec<Evidence>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Diagnostic {
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<u32>,
    pub message: String,
}

/// How much of the driver the analysis covered.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Coverage {
    pub functions_analyzed: u32,
    /// The analysis stopped at a limit (time, functions, depth); results are partial.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_exhausted: Option<String>,
    /// The user cancelled; results are partial.
    #[serde(default)]
    pub cancelled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}

impl Coverage {
    pub fn is_partial(&self) -> bool {
        self.cancelled || self.budget_exhausted.is_some()
    }
}

/// Everything Driver Intelligence knows about one driver.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DriverOverview {
    pub schema: u32,
    pub input: Input,
    #[serde(default)]
    pub frameworks: Vec<FrameworkHint>,
    #[serde(default)]
    pub entry_roots: Vec<EntryRoot>,
    #[serde(default)]
    pub callbacks: Vec<Callback>,
    #[serde(default)]
    pub irp: Vec<IrpHandler>,
    #[serde(default)]
    pub ioctls: Vec<Ioctl>,
    #[serde(default)]
    pub devices: Vec<Device>,
    pub coverage: Coverage,
}

/// The same slot or role has more than one distinct target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Conflict {
    Entry(EntryRole),
    Callback(CallbackRole),
    Irp(u8),
}

/// Merges facts with the same key: their evidence lists are joined, sorted and deduplicated.
fn merge_by_key<T, K: Ord>(
    items: &mut Vec<T>,
    key: impl Fn(&T) -> K,
    evidence: impl Fn(&mut T) -> &mut Vec<Evidence>,
) {
    items.sort_by(|a, b| key(a).cmp(&key(b)));
    let mut merged: Vec<T> = Vec::with_capacity(items.len());
    for mut item in items.drain(..) {
        match merged.last_mut() {
            Some(last) if key(last) == key(&item) => evidence(last).append(evidence(&mut item)),
            _ => merged.push(item),
        }
    }
    for item in &mut merged {
        let ev = evidence(item);
        ev.sort();
        ev.dedup();
    }
    *items = merged;
}

impl DriverOverview {
    pub fn new(input: Input) -> Self {
        DriverOverview {
            schema: SCHEMA_VERSION,
            input,
            frameworks: Vec::new(),
            entry_roots: Vec::new(),
            callbacks: Vec::new(),
            irp: Vec::new(),
            ioctls: Vec::new(),
            devices: Vec::new(),
            coverage: Coverage {
                functions_analyzed: 0,
                budget_exhausted: None,
                cancelled: false,
                diagnostics: Vec::new(),
            },
        }
    }

    /// Canonical form: facts sorted, the same fact found twice merged into one with both evidence lists, exact
    /// duplicates dropped. Distinct targets for one slot are kept. Output order then depends only on content.
    pub fn normalize(&mut self) {
        merge_by_key(&mut self.frameworks, |f| f.framework, |f| &mut f.evidence);
        merge_by_key(
            &mut self.entry_roots,
            |e| (e.role, e.target.clone()),
            |e| &mut e.evidence,
        );
        merge_by_key(
            &mut self.callbacks,
            |c| (c.role, c.target.clone()),
            |c| &mut c.evidence,
        );
        merge_by_key(
            &mut self.irp,
            |h| (h.major, h.target.clone()),
            |h| &mut h.evidence,
        );
        merge_by_key(
            &mut self.ioctls,
            |i| (i.code, i.major, i.dispatch.clone(), i.handler.clone()),
            |i| &mut i.evidence,
        );
        merge_by_key(
            &mut self.devices,
            |d| {
                (
                    d.name.clone(),
                    d.symbolic_links.clone(),
                    d.interface_guids.clone(),
                )
            },
            |d| &mut d.evidence,
        );
        for d in &mut self.devices {
            d.symbolic_links.sort();
            d.symbolic_links.dedup();
            d.interface_guids.sort();
            d.interface_guids.dedup();
        }
        self.coverage.diagnostics.sort();
        self.coverage.diagnostics.dedup();
    }

    /// Slots and roles with more than one distinct target, in order. Call after `normalize`.
    pub fn conflicts(&self) -> Vec<Conflict> {
        fn repeated<T, K: PartialEq + Clone>(items: &[T], key: impl Fn(&T) -> K) -> Vec<K> {
            let mut out: Vec<K> = Vec::new();
            for w in items.windows(2) {
                let k = key(&w[0]);
                if k == key(&w[1]) && out.last() != Some(&k) {
                    out.push(k);
                }
            }
            out
        }
        let mut out: Vec<Conflict> = repeated(&self.entry_roots, |e| e.role)
            .into_iter()
            .map(Conflict::Entry)
            .collect();
        out.extend(
            repeated(&self.callbacks, |c| c.role)
                .into_iter()
                .map(Conflict::Callback),
        );
        out.extend(
            repeated(&self.irp, |h| h.major)
                .into_iter()
                .map(Conflict::Irp),
        );
        out
    }

    /// Normalized, pretty JSON. The same facts always give the same bytes.
    pub fn to_json(&self) -> String {
        let mut canonical = self.clone();
        canonical.normalize();
        serde_json::to_string_pretty(&canonical).expect("DriverOverview always serializes")
    }

    /// Reads JSON written by `to_json`, refusing schema versions this build does not know.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let overview: DriverOverview = serde_json::from_str(json).map_err(|e| e.to_string())?;
        if overview.schema != SCHEMA_VERSION {
            return Err(format!(
                "unsupported schema version {} (this build reads {SCHEMA_VERSION})",
                overview.schema
            ));
        }
        Ok(overview)
    }
}

/// Strongest status among a fact's evidence (`FoundInCode` > `Assumed` > `Unresolved`).
pub fn status_of(evidence: &[Evidence]) -> Status {
    evidence
        .iter()
        .map(|e| e.status)
        .min()
        .unwrap_or(Status::Unresolved)
}

/// `IRP_MJ_*` name of a major function index (values from wdm.h, WDK 10.0.26100).
pub fn irp_major_name(major: u8) -> Option<&'static str> {
    const NAMES: [&str; 0x1C] = [
        "IRP_MJ_CREATE",
        "IRP_MJ_CREATE_NAMED_PIPE",
        "IRP_MJ_CLOSE",
        "IRP_MJ_READ",
        "IRP_MJ_WRITE",
        "IRP_MJ_QUERY_INFORMATION",
        "IRP_MJ_SET_INFORMATION",
        "IRP_MJ_QUERY_EA",
        "IRP_MJ_SET_EA",
        "IRP_MJ_FLUSH_BUFFERS",
        "IRP_MJ_QUERY_VOLUME_INFORMATION",
        "IRP_MJ_SET_VOLUME_INFORMATION",
        "IRP_MJ_DIRECTORY_CONTROL",
        "IRP_MJ_FILE_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CONTROL",
        "IRP_MJ_INTERNAL_DEVICE_CONTROL",
        "IRP_MJ_SHUTDOWN",
        "IRP_MJ_LOCK_CONTROL",
        "IRP_MJ_CLEANUP",
        "IRP_MJ_CREATE_MAILSLOT",
        "IRP_MJ_QUERY_SECURITY",
        "IRP_MJ_SET_SECURITY",
        "IRP_MJ_POWER",
        "IRP_MJ_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CHANGE",
        "IRP_MJ_QUERY_QUOTA",
        "IRP_MJ_SET_QUOTA",
        "IRP_MJ_PNP",
    ];
    NAMES.get(major as usize).copied()
}

/// `u64` as a `"0x..."` string: kernel image bases exceed what JSON numbers carry exactly.
mod hex_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{v:X}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let text = String::deserialize(d)?;
        let digits = text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .ok_or_else(|| {
                serde::de::Error::custom(format!("expected a 0x-prefixed hex string, got {text:?}"))
            })?;
        u64::from_str_radix(digits, 16).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMO: &str = include_str!("../../docs/src/wdi-overview.demo.json");

    fn ev(kind: EvidenceKind, site: u32, function: u32, reason: &str) -> Evidence {
        Evidence {
            kind,
            status: Status::FoundInCode,
            site,
            function,
            context: Vec::new(),
            conditions: Vec::new(),
            layout: None,
            reason: reason.into(),
        }
    }

    #[test]
    fn demo_example_is_valid_and_canonical() {
        let demo = DriverOverview::from_json(DEMO).unwrap();
        assert!(
            demo.input.file_name.contains("DEMO"),
            "the documented example must say it is a demo"
        );
        assert_eq!(
            demo.to_json().trim_end(),
            DEMO.trim_end(),
            "regenerate the demo with to_json()"
        );
    }

    #[test]
    fn json_round_trips() {
        let demo = DriverOverview::from_json(DEMO).unwrap();
        let again = DriverOverview::from_json(&demo.to_json()).unwrap();
        assert_eq!(again, demo);
        assert!(
            DEMO.contains("\"image_base\": \"0xFFFFF80012340000\""),
            "image base stays an exact hex string"
        );
    }

    #[test]
    fn output_does_not_depend_on_discovery_order() {
        let mut a = DriverOverview::from_json(DEMO).unwrap();
        let mut b = a.clone();
        b.irp.reverse();
        b.ioctls.reverse();
        for i in &mut b.ioctls {
            i.evidence.reverse();
        }
        b.coverage.diagnostics.reverse();
        a.normalize();
        assert_eq!(a.to_json(), b.to_json());
    }

    #[test]
    fn same_fact_twice_merges_and_distinct_targets_are_kept() {
        let mut o = DriverOverview::from_json(DEMO).unwrap();
        o.irp.clear();
        let store = |site| {
            ev(
                EvidenceKind::Store,
                site,
                0x1000,
                "stored to MajorFunction[IRP_MJ_DEVICE_CONTROL]",
            )
        };
        o.irp.push(IrpHandler {
            major: 0x0E,
            target: Target::Rva { rva: 0x2000 },
            evidence: vec![store(0x1010)],
        });
        o.irp.push(IrpHandler {
            major: 0x0E,
            target: Target::Rva { rva: 0x2000 },
            evidence: vec![store(0x1010), store(0x1020)],
        });
        o.irp.push(IrpHandler {
            major: 0x0E,
            target: Target::Rva { rva: 0x3000 },
            evidence: vec![store(0x1030)],
        });
        // One function serving two slots is two facts, not a conflict.
        o.irp.push(IrpHandler {
            major: 0x00,
            target: Target::Rva { rva: 0x2000 },
            evidence: vec![store(0x1040)],
        });
        o.normalize();
        assert_eq!(o.irp.len(), 3);
        assert_eq!(
            o.irp[1].evidence.len(),
            2,
            "duplicate evidence dropped, distinct evidence kept"
        );
        assert_eq!(o.conflicts(), vec![Conflict::Irp(0x0E)]);
    }

    #[test]
    fn unknown_schema_is_refused() {
        let newer = DEMO.replacen("\"schema\": 1", "\"schema\": 2", 1);
        assert!(
            DriverOverview::from_json(&newer)
                .unwrap_err()
                .contains("unsupported schema version 2")
        );
    }

    #[test]
    fn status_and_names() {
        let mut e = ev(EvidenceKind::Compare, 1, 1, "x");
        assert_eq!(status_of(&[]), Status::Unresolved);
        e.status = Status::Assumed;
        let mut f = e.clone();
        f.status = Status::FoundInCode;
        assert_eq!(status_of(&[e, f]), Status::FoundInCode);
        assert_eq!(irp_major_name(0x0E), Some("IRP_MJ_DEVICE_CONTROL"));
        assert_eq!(irp_major_name(0x1B), Some("IRP_MJ_PNP"));
        assert_eq!(irp_major_name(0x1C), None);
    }
}
