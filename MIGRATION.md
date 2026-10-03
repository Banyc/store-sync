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
2. **Data migration before any push** (see below) — it is the only step that
   touches existing on-disk state, and it fails closed if skipped.
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
- **(b) A remote destination cannot be locked — STATED LIMITATION, unresolved.**
  A far-side lock cannot be held by a run, so `sync`/`push` REFUSE a remote
  destination they cannot lock and the caller must write
  `DestinationOwnership::Unowned`. The migration must therefore keep `deploy`'s
  own far-side serialisation and accept that the crate's ownership guarantee
  does not apply to a remote destination. Closing this needs a persistent
  far-side lock session, which the crate does not have.

## The one real data migration: the receiver marker

`deploy` stores `recv-<uuid-v7>` at `<deploy_dir>/receiver-uuid`. The crate
requires **40 lowercase hex** and fails closed on anything else, with no adoption
path — so without this step every existing deployment directory reads as
malformed, and the failure is silent to a test suite that builds fresh fixtures.

Choose one, and prefer the first:

1. **Adopt-on-read in `deploy`**: read the legacy marker, derive the crate's
   receiver id, write it beside the legacy file, and keep the legacy file. One
   shot, idempotent, no operator action, reversible.
2. **Re-provision each deployment directory** — only if no stored identity must
   survive.

The crate will not adopt a foreign format silently, and should not: silently
adopting would misidentify a deployment directory.

## Verification per step

- the crate's gate on BOTH platforms, plus `tests/consumer_fit.rs`, which fails
  to COMPILE if a consumer-required name is removed;
- `deploy`'s own test suite on the touched modules;
- for the marker step: a fixture directory carrying a legacy marker pushes
  successfully after adoption, and a corrupt marker still fails closed.

## Riskiest step

The receiver-marker migration. It is the only step that fails closed against
existing production state, and neither side's tests cover it as it stands.

## Out of scope

- the Windows runtime (`deploy`'s Windows port is type-checked only, and the
  crate's Windows test target compiles but has never executed);
- design conflict (b).
