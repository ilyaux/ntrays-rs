# Migrate original NtRays state

Original NtRays stores API indexes in `$ ntrays syscall` without identifying the generated table. An index is only meaningful with the exact table used by that original DLL. The Rust plugin stores names in `$ ntrays-rs syscall` and will not guess that provenance.

Back up the IDB and retain the original plugin's build information before attempting migration. Existing new-format named data takes precedence and requires no marker. Unknown indexes or formats are not guessed, and the original netnode is retained.

## Confirm the original table

The supported legacy table is the original `nt_syscalls.inc` with SHA-256:

```text
c7929397db55812e0307845e700169a0b36ff2687e992156c0207c16f054bc26
```

Only after verifying that the original plugin used for this IDB was built with that exact table, run this in IDAPython:

```python
import ida_netnode

confirmed_table = b"c7929397db55812e0307845e700169a0b36ff2687e992156c0207c16f054bc26"
node = ida_netnode.netnode("$ ntrays-rs syscall", 0, True)
assert node.supset(0, confirmed_table, ord("M"))
```

Save and reopen the IDB to reload plugin state and migrate supported legacy maps and callsite overrides.

Writing the expected hash is your assertion about the old plugin's table. It does not discover that table or validate an unknown DLL. Checking an unrelated current checkout is insufficient. A missing or different marker leaves the original index-based data intact.

## Check the result

Review the Output window for migration messages and inspect affected syscall decompilation. A malformed stored map is preserved rather than silently overwritten. Keep the original node and your backup until the migrated calls have been reviewed.

`tools/test_syscall_state.py` exercises IDB export maps, confirmed/unconfirmed legacy migration, reopen/rebase behavior, and same-process database isolation in IDA 9.3. See the [regression guide](regression.md#syscall-state-and-original-lifecycle) for its inputs and limits.
