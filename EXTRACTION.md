# store-sync extraction

`~/code/deploy` is the read-only source of truth. Each slice ports the named
production code **and its tests** here, applies the adaptations below, and
must pass the gate. Do not invent a new design where a faithful port exists:
the value of this crate is the semantics already encoded in the source, and
those semantics live in the doc comments and the tests.

Source paths below are relative to `~/code/deploy`.

## Adaptations (every slice)

1. **Error type.** `crate::error::Error` is already ported here with the same
   variant names and the same constructor helpers: `Error::{store, integrity,
   transport, materialization, preflight, path, not_found, r#ref, conflict}`,
   plus `Io(#[from] io::Error)` and `Json(#[from] serde_json::Error)`. A
   `crate::kernel::KernelError` variant does not exist here; if a ported file
   needs it, that is a signal the file is domain code and must be dropped.
2. **Visibility.** `pub(crate)` becomes `pub` for every item that is part of
   the crate's API. Genuinely internal helpers stay `pub(crate)`.
3. **Test helpers.** `crate::testutil::{fixture_env, fixture_tmpdir,
   proptest_cases, slow_tests_enabled}` become `crate::test_support::{...}`
   (already present). Any other `crate::testutil::*` use means the test is
   domain-bound: drop that test and record the drop.
4. **No application domain.** Forbidden anywhere in this crate:
   `crate::config`, `crate::ledger`, `crate::kernel`, `crate::retention`,
   `crate::deploy::*`, `crate::remote::helper`, `crate::remote::layout`,
   `crate::store::local`, `crate::identity::{ReleaseId, DeploymentId, ...}`.
   Where a ported file depends on one, apply that slice's **domain cut**.
   The cut must preserve the source's behavior with the domain value supplied
   by the caller, never deleted silently.
5. **Doc comments are part of the port.** They carry the invariants and the
   rationale for the design. Keep them; rewrite only intra-doc links
   (`crate::...`) that no longer resolve to the path in this crate.
6. **Dropped tests are reported, not stubbed.** A test that needs a domain
   fixture is dropped, and the report lists `deploy-file:line` and the reason.
   Never replace an assertion with a weaker one to keep a test compiling.
7. **No new dependencies** without a reason in the report. `Cargo.toml`
   already carries the union the whole crate needs.
8. **Windows.** `src/low-level-windows` ports are required (the `#[cfg(windows)]`
   modules exist), but this machine cannot compile them; port them verbatim
   and say so in the report. Do not add `#[cfg(unix)]` to a Windows file.

## Gate

From the repo root:

```sh
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

`cargo fmt` is allowed to reformat; the other two must pass.

## Wave 1 review notes

* `test_support.rs` carries a module-level `#![allow(dead_code)]`: it is a
  test-only module shared by suites that land in separate waves, so a helper
  no current suite calls is not a defect.
* **Known gap from slice-root.** Deploy's
  `src/store/local/owned_root.rs:350` and `:389`
  (`symlink_injected_path_component_cannot_redirect_a_mutation` /
  `..._a_read`) were dropped because they drive the symlink injection through
  `LocalStore`/`TargetName`/`retention_debt`, which are forbidden here. The
  *property* those tests cover — a symlink injected into a path component
  cannot redirect a mutation or a read outside the owned root — is the whole
  point of the `_fd` primitives, so it must reappear as a crate-level
  integration test (`tests/confinement.rs`) against `RootDir`/`OwnedRoot`
  plus `atomic`'s `_fd` family once slice-atomic has landed. This is a
  required follow-up, not an accepted loss.

## Slices

### slice-core — `src/digest.rs`, `src/platform.rs`, `src/trace.rs`, `src/id.rs`

Port in full: `src/digest.rs` -> `src/digest.rs`; `src/platform.rs` ->
`src/platform.rs`; `src/trace.rs` -> `src/trace.rs`. `platform` is
`pub(crate)` in the source; make it `pub`. (`src/env.rs` is already ported
here.)

`src/id.rs` is a **composition, not a file copy**: take the `id_newtype!`
macro from `src/identity/mod.rs` (the macro body, its doc, and the
`#[cfg(test)]` `new` constructor rule — no `Default`), `valid_name` from
`src/identity/identity/scalars.rs`, and `valid_hex_digest` from
`src/identity/identity/id/digests.rs`. Export `id_newtype!` (a
`macro_rules!` with `#[macro_export]`, or a `macro_rules!` + `pub(crate) use`
if that composes more cleanly), `pub fn valid_name`, `pub fn
valid_hex_digest`, and declare the `Identifier` newtype the source builds
from `valid_name` as the worked example. Port the source's tests for these
three functions. Drop the rest of `scalars.rs` (it is domain value types).

Acceptance: a `#[cfg(test)]` test constructs a sample newtype through
`parse`, `FromStr`, and `Deserialize`, and shows an invalid wire string fails
`Deserialize` (fail closed).

### slice-atomic — `src/atomic/{mod,unix,windows}.rs`

Port `src/store/atomic/mod.rs` -> `src/atomic/mod.rs`,
`src/store/atomic/unix.rs` -> `src/atomic/unix.rs`,
`src/store/atomic/windows.rs` -> `src/atomic/windows.rs`, verbatim except
adaptation 1 and: `ReplaceOutcome`, `ReplaceStage`, `DirEntry`, `RootDir`
become `pub`; the `#[cfg(test)]` raw-path `path_state`/`read_json` variants
keep their `cfg(test)`. The per-stage fault hook
(`fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>`) stays — production
callers pass a no-op closure, and no `testutil` fault registry is ported.
Port the tests in `unix.rs`.

Acceptance: the durability protocol's two commit points are covered by a
test (a pre-rename failure leaves the old content visible; a
post-rename/parent-fsync failure reports
`ReplaceOutcome::ReplacedDurabilityUnknown`, never a bare `Err`).

### slice-root — `src/root.rs`

Port `src/store/local/owned_root.rs` -> `src/root.rs`. **Domain cut:** the
file imports `crate::identity::{EndpointKey, LOCAL_ENDPOINT_MARKER}`. Define
here instead a minimal `pub struct EndpointKey(String)` (validated non-empty,
with `parse`/`as_str`) and `pub const LOCAL_ENDPOINT_MARKER: &str = "local"`,
and keep every other behavior identical: sealed fields with no unchecked
constructor, canonicalization, refusal of the filesystem root and of a
symlink root, the process-global refcounted ownership registry, and the
overlap (equal/ancestor/descendant) refusal at construction with release on
last-clone drop. Rewrite the doc's `crate::store::atomic` link to
`crate::atomic`. Port the tests; drop only those that need
`crate::ledger`/`crate::store::local` fixtures and report them.

### slice-lock — `src/lock/{mod,unix,windows}.rs`

Port `src/deploy/lock/mod.rs` -> `src/lock/mod.rs`, `unix.rs`, `windows.rs`.
Domain cut: `crate::store::atomic::ensure_private_dir_durable` becomes
`crate::atomic::ensure_private_dir_durable`. Make `pub` the items the crate's
API needs (`FileLock` and its `acquire`/release surface); keep
`try_lock`/`unlock`/`LockAttempt`/`contended_errno` as `pub(crate)` unless a
ported test needs them. Keep the stable-inode discipline and its doc
verbatim. Port the tests (replace `crate::testutil::{fixture_env,
fixture_tmpdir, proptest_cases}` with `crate::test_support::*`).

### slice-transport — `src/transport/**`

Port `src/remote/transport/rooted.rs` -> `src/transport/rooted.rs`;
`src/remote/transport/mod.rs` -> `src/transport/mod.rs`;
`src/remote/transport/scripted.rs` -> `src/transport/scripted.rs` (keep it
`#[cfg(test)]` if that is what the source does);
`src/remote/transport/runner/{mod,unix,windows}.rs` ->
`src/transport/runner/{mod,unix,windows}.rs`;
`src/remote/transport/ssh/{mod,hostkey}.rs` -> `src/transport/ssh/...`;
`src/remote/transport/ssh/runner/{mod,unix,windows}.rs` ->
`src/transport/ssh/runner/...`.

**Domain cuts (this is the load-bearing part of the slice):**

* `crate::remote::layout::{bootstrap_dirs, operation_lock,
  operation_lock_sidecar}` become a caller-supplied `pub struct Layout {
  pub bootstrap_dirs: Vec<RootedRelativePath>, pub lock: RootedRelativePath,
  pub lock_sidecar: RootedRelativePath, pub receiver_marker:
  Option<RootedRelativePath> }`, taken by `LocalTransport::new` and
  `SshTransport::new` (and held by them). Every sidecar special-case that
  compared against `layout::operation_lock()` compares against
  `self.layout.lock` instead. Provide `Layout::empty()` for callers that
  need no bootstrap and no lock.
* `crate::identity::ReceiverUuid` and `provision_receiver_uuid`: replace with
  an opaque receiver id — 40 lowercase hex generated from `getrandom` — read
  and validated at `Layout::receiver_marker` (when `Some`), stored as
  `<id>\n`, and never re-generated. Same fail-closed reads: a present but
  empty/malformed marker is an error, a missing marker is `Ok(None)`.
* `crate::deploy::lock::*` -> `crate::lock::*`; `crate::platform::*` and
  `crate::digest::*` -> the same names here.
* Any use of `crate::remote::canonical` becomes `crate::manifest` (slice
  manifest owns it; if it is not ported yet, drop the dependent test and
  report it).
* **Drop** everything that needs `crate::config`, `crate::remote::helper`,
  `crate::retention`, `crate::store::local`, `crate::identity` domain ids, or
  `crate::semantic_invariants` — that is the whole `mod tests_ssh` beyond the
  transport's own behavior, and the `scripted.rs` injector if it cannot be
  reduced to a domain-free fake exec. Report each drop with file:line.

Port the transport's own behavior tests: the `Remote` trait's default
methods, `RootedRelativePath`'s validation, the runner's bounded-child
reaping and process-group kill, host-key verification/pinning, and
`SshTransport`'s argument construction and script generation (the parts that
do not need a live ssh).

Acceptance: `LocalTransport` passes the trait's behavior tests end to end
against a temp-dir root, and the SSH command/script builders are covered
without a live connection.

### slice-manifest — `src/manifest/mod.rs`

Port the **tree-metadata half** of `src/remote/canonical/mod.rs`:
`TREE_SCHEMA_VERSION`, `TreeEntry`, `TreeMetadata`, `compute_tree_digest`,
the local canonicalizer (`canonicalize_tree` and the walk it uses),
`remote_tree_verify_script`, and `canonicalize_remote_entries`.
`crate::platform::{chmod, file_mode, metadata_mode}` and `crate::digest::*`
resolve here. Drop the mapping/template materialization
(`materialize.rs` entirely) and any `crate::config` / `crate::push` /
`crate::helper` use; drop the tests that need them and report each.

Acceptance: a local tree canonicalizes to a digest; mutating one byte changes
the digest; a tree with a hard link, an escaping symlink, a FIFO, or a
duplicated normalized path is refused; the remote script's output parses into
the same `TreeMetadata` the local walk produces for the same tree (test the
two paths against one fixture).

### slice-sync — `src/sync/` (new code, wave 3)

Purpose: move a tree between two hosts, transferring only what differs, and
never destroying a destination entry the caller did not sanction. This is the
capability that makes the crate more than local storage: a record book is
pushed to another host and pulled back.

Build it as two committed changes, in order, both inside `src/sync/` (convert
the `src/sync.rs` stub into `src/sync/{mod.rs,diff.rs,apply.rs}`; `lib.rs`
already declares `pub mod sync`).

#### 3a — `sync::diff` (comparison; mutates nothing)

A manifest is [`crate::manifest::TreeMetadata`]. Produce one per side:

* local: `manifest::canonicalize_tree(root)`;
* remote: branch on `Remote::is_local()` — NEVER probe the filesystem to
decide. A local remote is canonicalized directly at
`remote.root().join(rel)`; a remote one is hashed on the far side with
`remote.exec(&["perl".into(), "-e".into(),
manifest::remote_tree_verify_script().into(), abs_path])` and assembled with
`manifest::canonicalize_remote_entries`, so only hashes cross the link.

Compare into a typed, path-ordered diff:

```rust
pub enum EntryDiff { Missing, Changed, Extraneous, Same }
pub struct TreeDiff {
    pub source: TreeMetadata,
    pub dest: TreeMetadata,
    pub entries: Vec<(String, EntryDiff)>,   // sorted by path
}
```

* `Missing` — in the source, not in the destination.
* `Changed` — present on both, but kind, mode, or content hash differs.
* `Extraneous` — in the destination only.
* `Same` — metadata identical.

The diff is the whole decision surface; producing it must not read content
beyond what a manifest already holds.

#### 3b — `sync::apply` (transfer, one direction)

```rust
pub enum Direction { Push, Pull }
pub enum EntryPolicy { Replace, Refuse, AppendTail }
pub trait Policy { fn for_path(&self, rel: &str, kind: EntryKind) -> EntryPolicy; }
```

`Replace` overwrites the destination entry. `Refuse` leaves it alone and
reports a conflict. `AppendTail` is the append-only rule: if the destination
is a PREFIX of the source, the source's tail is appended; if the source is a
prefix of the destination, nothing is written; otherwise the two `Diverged`
— reported as a conflict, never merged, never truncated. `AppendTail` must
read both sides' bytes (a manifest carries hashes, not bytes) and accept a
prefix relation as the ONLY mergeable case.

The crate must not encode any application's file names: the caller supplies
the `Policy`, keyed on the path and entry kind. Provide a `ReplaceAll` policy
as the default "make the destination match the source".

Apply rules:

* Only `Missing` and `Changed` entries are eligible for transfer. `Extraneous`
  is REPORTED and never deleted unless the caller explicitly asks for it (a
  `delete_extraneous` flag, default false), and any removal must happen only
  AFTER the transfers and verification have succeeded, so a failed sync
  destroys nothing. `Same` entries are neither transferred nor verified.
  **The honest invariant, NOT an absolute: a `Same` entry's content and final
  mode are unchanged and it is not re-transferred — but a read-only directory
  holding a `Changed` child MUST be transiently widened to install that child.**
  That widening must be (a) decided from the DESTINATION's current mode, never
  the source's, (b) restored on the success AND the error path, and (c) COUNTED
  and NAMED: `transfers` counts every destination mutation, a `transient_dirs`
  field names each path temporarily adjusted, and no such path may appear in
  `skipped`. A report that names a path `skipped` while having mutated it is a
  defect; an absolute "`Same` implies zero I/O" is unachievable and must not be
  tested for.

  **Scope of the widening: MANIFEST ENTRIES only.** The destination ROOT is not
  a manifest entry and is NOT widened — it is the caller's own directory. A
  read-only destination root therefore makes every top-level mutation fail
  loudly: the failure is counted in `transfers`, the attempted path is named in
  `indeterminate`, and the root's mode is left untouched; no UNSANCTIONED entry
  is destroyed — a top-level `Changed` or `Missing` entry fails before any
  mutation, so nothing is mutated at all, while a top-level removal the caller
  SANCTIONED (an `Extraneous` directory under `delete_extraneous`) may unlink
  that directory's children before the removal's own final `rmdir` fails on the
  read-only root, i.e. a sanctioned deletion stops part-way rather than
  destroying a caller entry.
  The caller widens its own root if it wants top-level writes. This is a
  deliberate limitation, not an oversight: the transport abstraction has no
  root-mode operation (a remote root may name a path on another host), so a
  local-only widen would make the invariant depend on direction and transport.
* A `Refuse` conflict or a `Diverged` append leaves the destination
  byte-identical. Assert it in tests.
* Directories are created before their children. Modes and symlinks are
  transferred faithfully; a symlink is never followed.
* Pull writes locally through this crate's durable, confined primitives
  (`crate::atomic`), never a bare `fs::write`, so an interrupted pull cannot
  leave a torn entry. Push writes through
  `Remote::{write, try_write_new, create_dir_all, symlink, set_mode}`.
* After applying, VERIFY: re-read each written entry and compare its hash to
  the source manifest's. A mismatch is an error, never a silent success.

Report:

```rust
pub struct SyncReport {
    pub applied: Vec<String>,
    pub skipped: Vec<String>,
    pub conflicts: Vec<Conflict>,
    pub extraneous: Vec<String>,
}
```

Diff and report are ordered by path, deterministically.

Acceptance (tests against `LocalTransport` over a second temp directory, plus
`SshTransport` argument/script coverage where no live connection is needed):

* push makes the destination equal to the source manifest; pull does the reverse;
* unchanged entries cause no writes (count transfer operations), and a read-only
  `Same` directory with no changed child still performs zero transfers;
* a read-only `Same` directory WITH a changed child is widened, counted in
  `transfers`, named in `transient_dirs`, absent from `skipped`, and left at its
  original mode — on the failure path too, where the partial report must be
  reachable from the error (manifest entries only; the destination root is
  excluded — see the scope note above);
* `AppendTail` constrains BYTES only: when no bytes need appending it still
  applies a differing mode and never touches content;
* `Refuse` leaves a differing destination byte-identical and reports a conflict;
* `AppendTail` appends the missing tail when one side is a prefix;
* `AppendTail` on divergent content reports a conflict and changes nothing;
* `Extraneous` is reported and survives a default sync;
* a symlink and a non-default mode round-trip;
* a failed write is reported, never a success.
