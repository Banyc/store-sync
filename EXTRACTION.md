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

### slice-sync — `src/sync.rs` (new code — separate wave)

Not part of the first extraction. Push = produce a local manifest, ask the
other side for its manifest, send only what differs. Pull = the reverse, then
apply. Application is per record kind and is the caller's rule, not this
crate's: the crate compares and transfers, and exposes the diff
(`Missing`/`Changed`/`Diverged`) for the caller to merge. Never overwrite a
destination entry that the manifest says differs without the caller's
explicit rule.
