# Windows constant formatting

This feature is included in **v0.2.0 Preview**; the original `v0.1.0` preview does not include it. It belongs to **Type/ABI fixes and Windows constant formatting** in the [settings dialog](settings.md). The master switch and that component both gate it.

## NTSTATUS

When a function returns the named 32-bit `NTSTATUS` type, recognized constant returns display as `STATUS_*`. The same applies to a constant compared with a typed `NTSTATUS` expression. Plain integer returns and comparisons retain their number format.

For example, a typed return of `0xC0000022` becomes:

```c
NTSTATUS CheckAccess()
{
  return (int)STATUS_ACCESS_DENIED;
}
```

Names and values come from `MACRO_STATUS` in the installed Windows type library. NtRays imports that enum into the database when first needed. Windows TILs contain both signed and unsigned spellings and can use a 64-bit enum; the explicit cast retains the original 32-bit value and arithmetic type. Function signatures are preserved.

Unknown values remain numeric. Zero uses `STATUS_SUCCESS` even when a wait-status alias occurs first in the type library. Severity-bit labels such as `STATUS_SEVERITY_ERROR` are excluded. If the enum is unavailable or a local type with that name is not an enum, status formatting is skipped and the local definition is preserved. Recognition requires the named `NTSTATUS` type; unrelated integer typedefs are not inferred from variable names.

## Pool tags

Printable four-byte tags display as C character literals in the tag argument of these known calls:

| Function | Tag argument (starting at 1) |
|---|---:|
| `ExAllocatePool2`, `ExAllocatePool3` | 3 |
| `ExAllocatePoolWithTag`, `ExAllocatePoolWithQuotaTag`, `ExAllocatePoolWithTagPriority` | 3 |
| `ExFreePoolWithTag` | 2 |

Imported `__imp_` names are also recognized. For example, `ExAllocatePool2(0, 64, 0x54616731)` displays its last argument as `'Tag1'`. The numeric value and C multi-character literal ordering are preserved. Values containing a zero byte, control character, or non-ASCII byte remain numeric. Other arguments and unknown call targets keep their existing representation.

## User formats and persistence

Explicit number formats, enum selections and character literals are preserved. The automatic representation is applied to each decompiled tree; it does not save user number formats. Disabling the component refreshes cached decompilation. The imported enum remains in local types, like other analysis metadata already added to the IDB.

The [headless literal fixture](regression.md#windows-literal-formatting) checks context, value and type preservation, negative cases, user formats and cache toggles without opening the GUI.
