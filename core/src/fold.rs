//! Which kernel globals and calls the optimizers fold to 0 in conditions, and the name → address cache for them.
//!
//! These are instrumentation, scheduler hints and hypervisor enlightenments that clutter almost every kernel
//! function. Hex-Rays then drops the dead branches.

/// What an operand of a conditional jump looks like, as reported by the shim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Site {
    /// Read of a global at `ea` (possibly inside it, at an offset).
    Global = 0,
    /// Result of a call to `ea`.
    Call = 1,
    /// `global & mask`.
    And = 2,
    /// A call statement to `ea` in a block (the scheduler-hint optimizer removes it with its setup).
    CallStatement = 3,
}

impl Site {
    pub fn from_u32(v: u32) -> Option<Self> {
        [Site::Global, Site::Call, Site::And, Site::CallStatement].get(v as usize).copied()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Always,
    /// Hypervisor enlightenments: folding them removes real code paths (e.g. the long-spin-wait hypercall in
    /// KeYieldProcessorEx, upstream issue 4), so this is opt-in.
    Hvl,
}

struct Rule {
    site: Site,
    name: &'static str,
    /// Bytes of the global covered (accesses at `ea..ea+size` fold), or the mask for `Site::And`.
    arg: u64,
    gate: Gate,
}

const RULES: &[Rule] = &[
    Rule { site: Site::Global, name: "KiIrqlFlags", arg: 4, gate: Gate::Always },
    Rule { site: Site::Global, name: "PerfGlobalGroupMask", arg: 0x10, gate: Gate::Always },
    Rule { site: Site::Global, name: "HvlEnlightenments", arg: 4, gate: Gate::Hvl },
    Rule { site: Site::Global, name: "HvlLongSpinCountMask", arg: 4, gate: Gate::Hvl },
    Rule { site: Site::Call, name: "MiPteHasShadow", arg: 0, gate: Gate::Always },
    Rule { site: Site::Call, name: "MiPteInShadowRange", arg: 0, gate: Gate::Always },
    Rule { site: Site::And, name: "MiFlags", arg: 0xC00000, gate: Gate::Always },
    Rule { site: Site::CallStatement, name: "KiRemoveSystemWorkPriorityKick", arg: 0, gate: Gate::Always },
];

/// Rules with their names resolved to addresses in one database. Rebuild when names change.
pub struct Resolved {
    entries: Vec<(Site, u64, u64)>, // site, ea, arg
}

impl Resolved {
    /// `name_ea` returns the address of a name, or `None` if the database has no such name.
    pub fn new(fold_hvl: bool, mut name_ea: impl FnMut(&str) -> Option<u64>) -> Self {
        let entries = RULES
            .iter()
            .filter(|r| r.gate == Gate::Always || fold_hvl)
            .filter_map(|r| name_ea(r.name).map(|ea| (r.site, ea, r.arg)))
            .collect();
        Resolved { entries }
    }

    /// Should the operand at this site fold to 0? `value` is the mask for `Site::And`.
    pub fn folds(&self, site: Site, ea: u64, value: u64) -> bool {
        self.entries.iter().any(|&(s, start, arg)| {
            s == site
                && match site {
                    Site::Global => ea >= start && ea - start < arg,
                    Site::And => ea == start && value == arg,
                    Site::Call | Site::CallStatement => ea == start,
                }
        })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(n: &str) -> Option<u64> {
        match n {
            "KiIrqlFlags" => Some(0x1000),
            "PerfGlobalGroupMask" => Some(0x2000),
            "HvlEnlightenments" => Some(0x3000),
            "MiFlags" => Some(0x4000),
            "MiPteHasShadow" => Some(0x5000),
            _ => None,
        }
    }

    #[test]
    fn globals_fold_inside_their_size_only() {
        let r = Resolved::new(false, names);
        assert!(r.folds(Site::Global, 0x1000, 0) && r.folds(Site::Global, 0x1003, 0));
        assert!(!r.folds(Site::Global, 0x1004, 0) && !r.folds(Site::Global, 0xFFF, 0));
        assert!(r.folds(Site::Global, 0x200F, 0) && !r.folds(Site::Global, 0x2010, 0));
    }

    #[test]
    fn hvl_is_opt_in() {
        assert!(!Resolved::new(false, names).folds(Site::Global, 0x3000, 0));
        assert!(Resolved::new(true, names).folds(Site::Global, 0x3000, 0));
    }

    #[test]
    fn and_needs_the_exact_mask_and_calls_the_exact_target() {
        let r = Resolved::new(false, names);
        assert!(r.folds(Site::And, 0x4000, 0xC00000) && !r.folds(Site::And, 0x4000, 0x400000));
        assert!(r.folds(Site::Call, 0x5000, 0) && !r.folds(Site::Global, 0x5000, 0));
        assert!(!r.folds(Site::Call, 0x5001, 0));
    }

    #[test]
    fn missing_names_are_skipped() {
        assert!(Resolved::new(true, |_| None).is_empty());
    }
}
