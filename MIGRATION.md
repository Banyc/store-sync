# Migrating `~/code/deploy` onto `storekit`

The crate was extracted from `deploy`, so the migration is mostly deletion: swap
`deploy`'s copies of the substrate for the crate's, keep everything that is
domain. This file is the ordered checklist and the record of what does NOT map.

`deploy` does not depend on the crate yet. Nothing below has been executed.

## What the migration is not

- **Not a drop-in for `deploy`'s tree transfer.** `deploy`'s push is a domain
  protocol — generations, transactions, the `current` symlink, owner markers —
  and stays in `deploy` (`remote/helper/**`). The crate supplies the transport
  and, where the transfer is a plain tree mirror, the `sync` engine.
- **Not tolerant of what `deploy` tolerates.** The crate's fidelity scope is
  strict and documented: no hard links, no absolute or escaping symlink
  targets, NFC-only names, no CR/LF/TAB. A `deploy` directory holding any of
  those is refused, loudly, rather than carried.

## Order

1. **Freeze the crate.** The API is the target of the migration; land
   `docs/API-CONSTRAINTS.md`'s work first.
2. **Data migration before any push** (see below) — the only step that touches
   existing on-disk state, and the one that fails closed if skipped. **DONE.**
3. **Swap the substrate in dependency order**: `digest`/`platform`/`trace` →
   `atomic` → `lock` → `root`/`owned_root` → `relpath` → `transport` (+ runner,
   ssh) → `manifest`/`canonical`.
4. **Adopt `sync`** only where a transfer is a plain mirror of one tree into
   another.

## Module map

| `deploy` | `storekit` | Adaptation |
|---|---|---|
| `store/atomic/{mod,unix,windows}.rs` | `atomic::*` | Every root-relative mutation takes `&RootedRelativePath`, parsed once at the boundary. The path-based helpers `set_private`, `sync_parent_dir`, `ensure_private_dir`, `ensure_private_dir_durable`, `remove_dir_all_path` are gone — use the `_fd` twins. `write_atomic_replace(&Path)` is public for the unconfined, absolute-path case. |
| `deploy/lock/{mod,unix,windows}.rs` | `lock::FileLock` | 1:1. |
| `store/local/owned_root.rs` | `root::OwnedRoot` + `EndpointKey` | Domain cut: the crate owns `EndpointKey`/`LOCAL_ENDPOINT_MARKER`. |
| `identity::*` (`id_newtype!`, `valid_name`, `valid_hex_digest`) | `id::*` | 1:1. The macro names `serde` through the crate, so the call site needs no `serde` dependency. |
| `remote/transport/rooted.rs` | `relpath::RootedRelativePath` | `from_validated` is **crate-private**; use the fallible `parse` at the boundary (a `LazyLock` for the static spellings). |
| `remote/transport/mod.rs`, `runner/**`, `ssh/**` | `transport::*` | `Layout` is a constructor argument; `LocalTransport::new(env, base, layout)`. `Remote::exists` is a default method; `metadata_opt` is the typed probe. |
| `remote/canonical/mod.rs` (tree half) | `manifest::*` | Pick by ROLE: `canonicalize_tree` for a source (strict), `canonicalize_tree_destination` for a destination (tolerant, `UnsupportedEntry { path, kind, reason }`). The `_checked` assemblers carry the completeness fact. |
| *(new)* | `atomic::copy_dir_recursive_fd` + `fsync_tree_recursive_fd` | `deploy`'s shape: an arbitrary, possibly out-of-root `&Path` source into a root-confined `RootedRelativePath` staging destination, then canonicalize + digest + rename. |
| *(new)* | `atomic::copy_tree_verbatim(src, dst)` | The TOLERANT clone: copies a tree (reserved spellings, the `operation.lock` record, and crate-temp shapes included) between two ordinary absolute paths. Use it for `retention`'s clone of a live base; the destination is NOT a store root and must never be handed to the recovery sweep. |
| *(new)* | `transport::{with_operation_lock_sidecar, SIDECAR_WAIT_TIMEOUT, SIDECAR_RETRY_INTERVAL}` | The operation-scoped sidecar critical section (blocking-with-deadline, re-entrant, same record/inode as the far-side lock path). Replaces `deploy`'s own platform flock triple in `deploy/lock/{unix,windows}.rs` and its `remote::transport::{with_operation_lock_sidecar, wait_for_sidecar_flock, ensure_operation_lock_sidecar_durable}`. |
| *(new)* | `sync::sync(direction, .., ownership)` | One entry point. See the ownership note below. |
| `remote/helper/**` (push engine) | — | **Stays in `deploy`.** |
| `store/local/**`, `retention/**`, `kernel/**`, `ledger/**`, `verify/**`, `config/`, `init.rs` | — | **Stays in `deploy`.** |

## Ownership: the two design conflicts

- **(a) The sibling record vs `deploy`'s in-root lock — CLOSED.** The crate's
  plain `DestinationOwnership::lock` takes ONLY a sibling record
  (`<parent>/.<name>.operation.lock`), which does not exclude `deploy`'s in-root
  `state/operation.lock`. `DestinationOwnership::lock_with_in_root_lock(..,
  in_root_lock)` holds BOTH, in a fixed order (sibling first), with both
  acquisitions non-blocking so the order cannot deadlock. A `deploy` destination
  that has its own in-root record should take this form, and it must already
  exist (the composed form refuses a missing root without creating anything).
- **(b) A remote destination can now be locked — CLOSED.**
  `DestinationOwnership::lock_remote(direction, local_root, remote)` holds the
  destination's operation lock ON THE FAR SIDE for the whole run through a
  persistent far-side lock session (a long-lived `ssh` client whose remote
  `perl` takes a non-blocking `flock` on the SAME sibling record the local case
  uses). A `deploy` push into a remote destination should prefer this over
  `DestinationOwnership::Unowned`: it serialises concurrent cooperating runs and
  the record is released on every exit path. It is NOT a lease — a far-side lock
  cannot outlive its client — so `deploy`'s own far-side serialisation need not
  be DELETED for correctness while the run still depends on it; `lock_remote` is
  the crate-level exclusion, and `deploy`'s own protocol can be retired once the
  run no longer needs it. A NON-COOPERATING far-side writer is still outside the
  crate's exclusion. The pre-existing refusal is unchanged: `sync` still refuses
  a remote destination the caller does not own, and `Unowned` still names the
  weaker path.

## The one real data migration: the receiver marker

`deploy` stores `recv-<uuid-v7>` at `<deploy_dir>/receiver-uuid`. The crate
requires **40 lowercase hex** and fails closed on anything else, with no adoption
path — so without this step every existing deployment directory reads as
malformed, and the failure is silent to a test suite that builds fresh fixtures.

### Done (`deploy` `dev`, change `47e0e092`)

Adopt-on-read is implemented in `deploy` (`remote::transport::receiver_marker`):

- **Derivation.** `sha256("deploy/receiver-id/v1\0" || legacy)[..20]`, hex, where
  `legacy` is the canonical trimmed `recv-<uuid-v7>` string. Deterministic from
  the canonical string (file whitespace cannot change it), and domain-separated
  so it cannot collide with another hash of the same string. 160 bits, the same
  budget the crate's own receiver ids use.
- **Where.** The adopting read is `read_receiver_uuid_opt`; a read-only
  `peek_receiver_uuid_opt` is used when a preflight is a `--dry-run`, because
  adopt-on-read would otherwise MUTATE on a dry run. Fresh directories adopt on
  provision.
- **Wire form.** `<40 lowercase hex>\n` at `<deploy_dir>/receiver-id`, beside the
  legacy file. `receiver-uuid` is never opened for write and its bytes are
  unchanged; the module doc states the two conditions that would make it
  removable.
- **Fail closed.** An empty marker, `recv-`, a truncated uuid, or a 39/41-hex
  string is refused by `deploy`'s read AND by the crate, with no adoption.
- **Idempotent.** A second read leaves the inode, mtime and bytes identical.

The alternative (re-provisioning every directory) was not taken: it would discard
a stored identity for no benefit.

The crate will not adopt a foreign format silently, and should not: silently
adopting would misidentify a deployment directory.

## Verification per step

- the crate's gate on BOTH platforms, plus `tests/consumer_fit.rs`, which fails
  to COMPILE if a consumer-required name is removed;
- `deploy`'s own test suite on the touched modules;
- for the marker step: a fixture directory carrying a legacy marker pushes
  successfully after adoption, and a corrupt marker still fails closed.

## Riskiest step

The receiver-marker migration — DONE (above). It was the only step that fails
closed against existing production state, and neither side's tests covered it
beforehand; the adoption test now fails on the pre-change tree and passes after.

## Out of scope

- the Windows runtime (`deploy`'s Windows port is type-checked only, and the
  crate's Windows test target compiles but has never executed).
