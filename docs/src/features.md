# Features and limits

NtRays works at the Hex-Rays microcode layer and with selected IDA database metadata. Its helpers describe analysis; they are not implementations that execute privileged instructions.

## Kernel analysis

- Recognizes paging self-map and PFN addresses for four- and five-level paging and presents typed getter expressions.
- Uses `_ETHREAD` / `_EPROCESS` parent types for the corresponding leading `_KTHREAD` / `_KPROCESS` structures.
- Recognizes selected interrupt/trap entry patterns and trap-frame setup.
- Creates the mode-appropriate `KUSER_SHARED_DATA` segment and keeps that mapping consistent across rebases.
- Applies the recognized `KiKernelExit` ABI to avoid treating its interrupt frame as ordinary Win64 stack arguments.
- Performs selected constant/branch folding. Hypervisor-enlightenment (`Hvl`) folding is disabled by default because those values are not universally constant.

Recognition depends on the expected names, types, instruction patterns, and database mode. This is not a generic ABI detector for all kernel exits.

## Instruction helpers

The plugin includes helpers for selected CPUID/XGETBV/XSETBV, rotate-through-carry, VMX, SGX, PKRU, WAITPKG, CET, cache, syscall, and interrupt-return instructions. It fixes upstream RCL/RCR direction and immediate counts, XGETBV's high-half destination, syscall-stub numbering, and spurious syscall stack arguments.

Additional lifters cover VMFUNC, VMRESUME, VMCALL, RDPID, RDPKRU/WRPKRU, XSAVEC/XSAVEOPT, UMONITOR/UMWAIT/TPAUSE, ENQCMD, UIRET, SENDUIPI, ENCLS/ENCLU, and `int 2Eh`. XSAVES/XRSTORS also retain the full `EDX:EAX` mask. The [targeted fixture](regression.md#targeted-instruction-probe) checks implicit outputs, tracked flags, address width, and mask high bits in selected forms.

VMCALL and ENCLU use opaque register-state helpers. They do not assume a Hyper-V ABI or an enclave application ABI. A helper name is not a promise to model every architectural state transition or SGX leaf.

Unsupported operand forms return to Hex-Rays. In particular, FS/GS-prefixed forms that require a segment base are deliberately declined by the new address-based lifters. The tested GS-prefixed UMONITOR case remains assembly. See [validation results](validation.md) for what was actually exercised.

## Windows constants

The development checkout also formats typed NTSTATUS return/comparison constants and printable tags in recognized pool calls. See [Windows constant formatting](literals.md) for scope, explicit casts and preservation of user formats.

## Database changes

The plugin can save named syscall maps and per-address overrides, add the KUSER segment, import the Windows status enum, adjust recognized types, and patch RSB-stuffing gadgets. RSB changes are ordinary IDA patches visible and reversible in **Edit → Patch program**. Unloading or uninstalling the plugin does not automatically undo saved database changes.

Keep a pristine analyzed IDB for comparisons and run validation on copies. [Legacy migration](migration.md) preserves original syscall nodes rather than deleting them.

## Boundaries

The runtime suite covers IDA 9.3 and specific Windows x64 fixtures. It does not establish compatibility with every IDA update, Windows servicing revision, operand encoding, or function order. IDA 9.4/9.5 currently have build validation only. AMD SVM instructions already handled by the tested IDA configuration are left to Hex-Rays rather than receiving redundant lifters.

The development checkout includes [per-database settings](settings.md) and [syscall selection actions](syscalls.md#select-a-map-or-api-in-ida). These controls are not present in the original `v0.1.0` preview. Further transformations are tracked in the roadmap.
