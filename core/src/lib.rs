//! IDA-independent part of NtRays: everything here builds and tests without the IDA SDK.

pub mod fold;
pub mod syscall;
pub mod syscall_state;
pub mod syscall_presets;
mod legacy_syscalls;
mod syscall_table;

use std::ffi::CStr;

/// Self-referencing PML4/PML5 index used by Windows x64 paging.
pub const INDEX_SELF_REF: u64 = 0x1ED;
pub const PFN_LIST_BASE_VA48: u64 = 0xFFFF_FA80_0000_0000;
pub const PFN_LIST_BASE_LA57: u64 = 0xFFFF_DE00_0000_0000;

/// Base of the paging-structure table `level` (0 = top level) for `max_levels` (4 or 5) paging.
pub const fn make_pte_base(level: u32, max_levels: u32) -> u64 {
    let mut result = !0u64 << (max_levels * 9 + 12);
    let mut l = level;
    while l != max_levels {
        result |= INDEX_SELF_REF << (9 * l + 12);
        l += 1;
    }
    result
}

/// A paging-structure address baked into kernel code, shown as `getter() + offset` with `getter` returning
/// `type *`. The kernel relocates these at boot (KASLR of the paging self-map), so the raw constant is misleading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagingReloc {
    pub getter: &'static CStr,
    pub ty: &'static CStr,
    pub offset: u64,
}

/// Recognizes paging-structure and PFN database addresses for 4- and 5-level paging.
pub fn classify_paging_imm(imm: u64) -> Option<PagingReloc> {
    for base in [PFN_LIST_BASE_VA48, PFN_LIST_BASE_LA57] {
        // ponytail: same window as the original (first 48 bytes past the base); widen if real code needs more.
        if (base..=base + 48).contains(&imm) {
            return Some(PagingReloc { getter: c"MmGetPfnDb", ty: c"_MMPFN", offset: imm - base });
        }
    }
    const BASES: [&CStr; 5] = [c"MmGetPml5eBase", c"MmGetPml4eBase", c"MmGetPdpteBase", c"MmGetPdeBase", c"MmGetPteBase"];
    const LIMITS: [&CStr; 5] =
        [c"MmGetPml5eLimit", c"MmGetPml4eLimit", c"MmGetPdpteLimit", c"MmGetPdeLimit", c"MmGetPteLimit"];
    for depth in [4u32, 5] {
        for level in 0..depth {
            let pmin = make_pte_base(level, depth);
            let pmax = pmin + ((1u64 << (12 + 9 * level)) - 1);
            let name = (level + 5 - depth) as usize;
            let pte = |getter, offset| Some(PagingReloc { getter, ty: c"_MMPTE", offset });
            if level == 0 && imm == pmin + 0x7F8 {
                return pte(c"MmGetPxeUserLimit", 0);
            } else if level == 0 && imm == pmin + INDEX_SELF_REF * 8 {
                return pte(c"MmGetPxeSelfRef", 0);
            } else if imm == pmax {
                return pte(LIMITS[name], 0);
            } else if (pmin..=pmax).contains(&imm) {
                return pte(BASES[name], imm - pmin);
            }
        }
    }
    None
}

/// Kernel object types shown as their executive parents: `_KTHREAD *` → `_ETHREAD *`, `_KPROCESS *` → `_EPROCESS *`
/// (the K-structs are the first member of the E-structs, so the pointer is the same).
pub const PARENT_TYPES: [(&CStr, &CStr); 2] = [(c"_KTHREAD", c"_ETHREAD"), (c"_KPROCESS", c"_EPROCESS")];

/// Interrupt/trap entry points whose `lea rbp, [rsp+80h]` sets up a `_KTRAP_FRAME` pointer.
const ISRS: &[&str] = &[
    "KxIsrLinkage", "KiCallUserMode", "KiApcInterrupt", "KiHvInterrupt", "KiVmbusInterrupt0", "KiVmbusInterrupt1",
    "KiVmbusInterrupt2", "KiVmbusInterrupt3", "KiSwInterrupt", "KiDpcInterrupt", "KiIpiInterrupt", "KyStartUserThread",
    "KiDivideErrorFault", "KxDebugTrapOrFault", "KiNmiInterruptStart", "KiBreakpointTrap", "KiOverflowTrap",
    "KiBoundFault", "KiInvalidOpcodeFault", "KiNpxNotAvailableFault", "KiDoubleFaultAbort", "KiNpxSegmentOverrunAbort",
    "KiInvalidTssFault", "KiSegmentNotPresentFault", "KiStackFault", "KiGeneralProtectionFault", "KiPageFault",
    "KiFloatingErrorFault", "KiAlignmentFault", "KiMcheckAbort", "KxMcheckAlternateReturn", "KiXmmException",
    "KiVirtualizationException", "KiControlProtectionFault", "KiRaiseSecurityCheckFailure", "KiRaiseAssertion",
    "KiDebugServiceTrap", "KiSystemService", "KiSystemCall32", "KiServiceInternal", "KiSystemCall64",
    "KiSystemCall32Shadow", "KiSystemCall64Shadow", "HalpBlkDivideErrorFault", "HalpBlkDebugExceptionTrap",
    "HalpBlkBreakpointTrap", "HalpBlkOverflowTrap", "HalpBlkBoundRangeExceededFault", "HalpBlkInvalidOpcodeFault",
    "HalpBlkDeviceNotAvailableFault", "HalpBlkDoubleFaultAbort", "HalpBlkCoprocessorSegmentOverrunFault",
    "HalpBlkInvalidTssFault", "HalpBlkSegmentNotPresentFault", "HalpBlkStackSegmentFault",
    "HalpBlkGeneralProtectionFault", "HalpBlkPageFault", "HalpBlkFloatingPointErrorFault", "HalpBlkAlignmentFault",
    "HalpBlkFloatingPointFault", "HalpBlkVirtualizationFault", "HalpBlkReservedVector21", "HalpBlkReservedVector22",
    "HalpBlkReservedVector23", "HalpBlkReservedVector24", "HalpBlkReservedVector25", "HalpBlkReservedVector26",
    "HalpBlkReservedVector27", "HalpBlkReservedVector28", "HalpBlkReservedVector29", "HalpBlkReservedVector30",
    "HalpBlkReservedVector31", "HalpBlkStubInterrupt", "HalpBlkSpuriousInterrupt", "HalpBlkIpiInterrupt",
    "HalpBlkLocalErrorInterrupt", "HalpBlkMachineCheckAbort", "HalpBlkNmiInterrupt", "HalpBlkUnexpectedInterruptCommon",
];

pub fn is_isr(name: &str) -> bool {
    ISRS.contains(&name)
}

/// `lea rbp, [rsp+80h]`: the ISR prologue that points rbp into the trap frame (`_KTRAP_FRAME` at rbp-80h).
pub const TRAPFRAME_LEA: [u8; 8] = [0x48, 0x8D, 0xAC, 0x24, 0x80, 0x00, 0x00, 0x00];
pub const TRAPFRAME_DELTA: i32 = 0x80;

/// RSB-stuffing gadget in ISRs: `call +10Eh; add rsp, 8; call +10Eh`. IDA cannot follow it, so ISRs that
/// contain it do not decompile at all.
pub const RSB_GADGET: [u8; 14] = [0xE8, 0x0E, 0x01, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x08, 0xE8, 0x0E, 0x01, 0x00, 0x00];
/// What the gadget is patched to (same length): a 9-byte nop carrying the marker `DEADC0FE FE`, then the last
/// call turned into a jump past the stuffing loop's own `add rsp, 8`. Same bytes as the original NtRays, so
/// databases it already patched keep working.
pub const RSB_PATCHED: [u8; 14] = [0x66, 0x0F, 0x1F, 0x84, 0xDE, 0xAD, 0xC0, 0xFE, 0xFE, 0xE9, 0x12, 0x01, 0x00, 0x00];
/// Length of the marker nop at the start of `RSB_PATCHED`.
pub const RSB_NOP_LEN: usize = 9;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paging_constants_are_classified() {
        let c = |imm| classify_paging_imm(imm).map(|r| (r.getter.to_str().unwrap(), r.offset));
        assert_eq!(c(0xFFFF_F680_0000_0000), Some(("MmGetPteBase", 0)));
        assert_eq!(c(0xFFFF_F680_0000_0008), Some(("MmGetPteBase", 8)));
        assert_eq!(c(0xFFFF_F6FB_4000_0000), Some(("MmGetPdeBase", 0)));
        assert_eq!(c(0xFFFF_F6FB_7DBE_D000), Some(("MmGetPml4eBase", 0)));
        assert_eq!(c(0xFFFF_F6FB_7DBE_D7F8), Some(("MmGetPxeUserLimit", 0)));
        assert_eq!(c(0xFFFF_F6FB_7DBE_DF68), Some(("MmGetPxeSelfRef", 0)));
        assert_eq!(c(0xFFFF_F6FB_7DBE_DFFF), Some(("MmGetPml4eLimit", 0)));
        assert_eq!(c(PFN_LIST_BASE_VA48 + 8), Some(("MmGetPfnDb", 8)));
        assert_eq!(c(0xFFED_0000_0000_0000), Some(("MmGetPteBase", 0))); // 5-level
        assert_eq!(c(0x1_4000_0000), None);
        assert_eq!(c(PFN_LIST_BASE_VA48 + 49), None);
    }

    #[test]
    fn isr_lookup() {
        assert!(is_isr("KiPageFault") && is_isr("HalpBlkNmiInterrupt"));
        assert!(!is_isr("KiPageFaul") && !is_isr(""));
    }

    #[test]
    fn rsb_patch_keeps_length_and_target() {
        assert_eq!(RSB_GADGET.len(), RSB_PATCHED.len());
        // The gadget's last call goes to gadget+0x11C; the patched jump lands 4 bytes later, after `add rsp, 8`.
        let call_target = 9 + 5 + i32::from_le_bytes(RSB_GADGET[10..14].try_into().unwrap());
        let jmp_target = 9 + 5 + i32::from_le_bytes(RSB_PATCHED[10..14].try_into().unwrap());
        assert_eq!((call_target, jmp_target), (0x11C, 0x120));
    }

    #[test]
    fn four_level_bases_match_windows() {
        assert_eq!(make_pte_base(0, 4), 0xFFFF_F6FB_7DBE_D000); // PXE base
        assert_eq!(make_pte_base(1, 4), 0xFFFF_F6FB_7DA0_0000); // PPE base
        assert_eq!(make_pte_base(2, 4), 0xFFFF_F6FB_4000_0000); // PDE base
        assert_eq!(make_pte_base(3, 4), 0xFFFF_F680_0000_0000); // PTE base
    }

    #[test]
    fn five_level_pte_base() {
        assert_eq!(make_pte_base(4, 5), 0xFFED_0000_0000_0000);
    }
}
