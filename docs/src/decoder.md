# Instruction decoder extensions

These additions are in the development checkout, after `v0.1.0`. They extend instruction decoding in x64 segments of AMD64 PE databases. No instruction bytes are replaced or patched.

On the tested IDA 9.3.260421 installation, both FRED return encodings decoded as `clac`; the other forms below were unknown. NtRays provides their mnemonics, operands, flow analysis and microcode helpers.

| Instruction | Covered opcode | Presentation and implicit inputs |
|---|---|---|
| ERETS | `F2 0F 01 CA` | `__erets(frame)`, current RSP frame pointer, no return/fall-through |
| ERETU | `F3 0F 01 CA` | `__eretu(frame)`, current RSP frame pointer, no return/fall-through |
| LKGS | `F2 0F 00 /6` | `__lkgs(selector)`, 16-bit register or memory value |
| WRMSRNS | `0F 01 C6` | `__wrmsrns(ecx, edx:eax)`, ignores high halves of the source GPRs |
| INVLPGB | `0F 01 FE` | `__invlpgb(rax, ecx, edx)`; address-size override uses EAX |
| TLBSYNC | `0F 01 FF` | `__tlbsync()`, retained as a side-effecting call |

The FRED helpers represent an opaque event return. Privilege checks, shadow-stack validation, descriptor caches, faults and hardware TLB behavior are not emulated. WRMSRNS is kept distinct from serializing WRMSR. INVLPGB and TLBSYNC calls preserve their order.

LKGS decoding covers extended registers, ModRM/SIB, signed displacements, RIP/EIP-relative and absolute addressing, address-size overrides and segment overrides. The native operand loader reads a word, including the tested GS-relative case. Register values and unaffected arithmetic flags remain available after the helpers.

## Controls and existing databases

The decoder stays active while the plugin is loaded, including when instruction lifters or the master switch are disabled. That keeps FRED disassembly from reverting to the incorrect CLAC interpretation. The controls gate helper generation; disabled helpers use assembly fallback. Stored analysis changes are not undone by changing settings.

For a database analyzed before installing this extension, reanalyze affected code and refresh the pseudocode. NtRays does not scan and rewrite existing functions automatically. Keep the plugin available when reopening databases that use its custom instruction types.

## Scope and validation

The implementation covers these legacy opcode forms in 64-bit segments. VEX/EVEX immediate WRMSRNS forms, 16/32-bit code, LOCK and duplicate legacy-prefix groups are outside the decoder's supported set. Other instructions remain with the native processor module.

The [decoder fixture](regression.md#instruction-decoder-fixture) checks 23 function bodies in two fresh processes, 12 LKGS addressing comparisons with native MOV decoding, a segment-boundary instruction, flags, register widths, FRED flow and settings/cache behavior. Instructions are decompiled, never executed.

An executable-section byte scan of the kernel fixture `10.0.26100.9711` and the installed kernel `10.0.26100.9974` found no matches for these forms, including the checked legacy-prefix/REX variations. Therefore new-instruction semantics are validated on synthetic fixtures; the 63-function kernel regression checks for unintended changes to existing behavior.

## References

- [Intel FRED specification, revision 3.0](https://cdrdv2-public.intel.com/678938/346446-flexible-return-and-event-delivery.pdf), sections 6 and 8.
- [Intel XED FRED/LKGS encoding definitions](https://github.com/intelxed/xed/blob/main/datafiles/fred/fred-isa.xed.txt).
- [Intel instruction-set extensions reference, 319433-059](https://cdrdv2-public.intel.com/865891/319433-059-architecture-instruction-set-extensions-programming-reference_2025-0930.pdf), WRMSRNS.
- [AMD64 Architecture Programmer's Manual, volume 3, revision 3.36](https://www.scs.stanford.edu/~zyedidia/docs/x86/amd-manual-v3.pdf), INVLPGB and TLBSYNC (manufacturer PDF mirrored by Stanford).
