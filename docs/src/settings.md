# Settings and controls

These controls are included in **v0.2.0 Preview**; the original `v0.1.0` preview does not include them.

Open **Edit → Plugins → NtRays** or press **Alt+F8**. Settings belong to the current IDA database. Closing the dialog with **Cancel** keeps them unchanged; unloading the plugin does not save a disabled state.

The master switch enables or disables future NtRays transformations. Individual controls select instruction lifters, syscall helpers, microcode optimizers, type/ABI fixes and [Windows constant formatting](literals.md), RSB handling, and KUSER mapping. Hvl folding is a separate opt-in because those values are not universally constant. The log-level selector controls routine diagnostic output; internal failures remain visible.

Changes invalidate cached decompilation so reopening the same function uses the new options. Save the IDB to retain the selected settings across IDA sessions.

The [instruction decoder extension](decoder.md) remains active while the plugin is loaded so FRED instructions keep their correct identity. Master/instruction switches gate helper generation; disabled helpers use assembly fallback.

Disabling a component does not undo types, RSB patches or other analysis changes already stored in the database. RSB patches remain visible in **Edit → Patch program**. Use a pristine database copy when comparing enabled and disabled output.

An unknown or damaged settings record is preserved and treated as read-only. NtRays does not reinterpret unsupported values as valid preferences or overwrite them merely because the database was opened.

For syscall selection, see [maps and presets](syscalls.md).
