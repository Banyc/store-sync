//! Durable atomic filesystem I/O for the store.
//!
//! The atomic-replace protocol this module implements is the store's
//! durability machinery: write a UNIQUE temp file in the same directory,
//! chmod it private (0o600) BEFORE it can become visible under its final
//! name, fsync it, rename it into place (atomic on POSIX — a reader never
//! sees a torn record), then fsync the parent directory. The replace has
//! TWO DISTINCT COMMIT POINTS and `write_atomic_replace` reports them
//! EXPLICITLY ([`ReplaceOutcome`]): the RENAME is commit point 1 (the new
//! content becomes VISIBLE under its final name), and the PARENT-DIRECTORY
//! FSYNC is commit point 2 (the rename becomes DURABLE across power loss).
//! A failure before the rename is an `Err` — the OLD content is still
//! visible, and the temp file the replace wrote is UNLINKED before the call
//! returns, so a failed replace leaves the directory exactly as it found it
//! (no stray temp entry). The best-effort unlink is never silent: if it
//! itself fails, the error carries both the original failure and the cleanup
//! failure. A failure of the parent-directory open/fsync AFTER the rename
//! is [`ReplaceOutcome::ReplacedDurabilityUnknown`] — the NEW content IS
//! visible but its durability is UNCONFIRMED — never a bare `Err` (a bare
//! `Err` would conflate "the rename never happened" with "the rename
//! happened but the durability commit could not be verified"). The
//! durability of these writes is the ordering guarantee the rest of the
//! crate builds on: [`ReplaceOutcome::ReplacedDurable`] means the new bytes
//! are visible AND durable BEFORE the caller proceeds — including every
//! directory the replace CREATED to hold them, whose own entry is fsynced
//! into its parent before the rename — while
//! [`ReplaceOutcome::ReplacedDurabilityUnknown`] tells the caller the
//! content is visible but its durability is unconfirmed — so a caller's
//! recovery step can always tell "this write committed durably" from "this
//! write is visible but may be lost". The per-operation sequencing on top
//! of these primitives belongs to the caller, not to this module.
//!
//! The helpers here are the shared plumbing — the `pub` free functions this
//! crate exports as its durable-I/O layer:
//! the tri-state existence check (`path_state`), the fail-closed
//! parent-dir fsync (`sync_parent_dir`), unique temp naming
//! (`temp_name_for`), the atomic marker/JSONL rewrites
//! (`write_atomic_replace`, `write_jsonl_atomic`), private permissions
//! (`set_private`, `ensure_private_dir`), the tree-object directory
//! copy (`copy_dir_recursive`), and the JSON readers. Two more are the
//! consumer-facing recovery hooks: [`read_root_dir_fd`] enumerates the OWNED
//! ROOT itself (the empty and `.` child spellings are refused, so residue at
//! the root was otherwise unreachable) and [`is_crate_temp_name`] recognises
//! the crate's own crash residue (B1/B2).
//!
//! Parse-sensitive marker reads: a PRESENT-but-malformed marker CONTENT is
//! semantic CORRUPTION and maps to [`Error::integrity`] via
//! `read_json_marker` (the file exists, it is just not a valid marker),
//! while a mechanical filesystem I/O failure (open/read/rename/fsync)
//! stays [`Error::store`] — the class split a caller can always
//! distinguish "this marker is corrupt" from "disk read failed".
//! `read_json` folds both into [`Error::store`], which is correct for
//! its non-marker callers (observed.json, retention-debt.json, tree
//! metadata, ...); callers of `read_json_marker` must still perform
//! their own schema-version check after a successful parse (also
//! [`Error::integrity`]): an unsupported `schema_version` is a
//! marker-format violation, not an I/O failure.
//!
//! # The lock-record guard is STRUCTURAL, not a list of call sites
//!
//! The single-holder guarantee rests on the lock record's inode never
//! changing. Four earlier passes each fixed the call sites they could find
//! and missed one, so the guard is no longer applied by enumeration:
//!
//! * the private [`guard`] module owns the ONE spelling authority and the
//!   unforgeable [`GuardedRel`] capability (private fields; `new` and
//!   `new_for_owned_lock_record` are the only constructors and the only
//!   callers of the guard); every rel-path mutator mints one, and the rename
//!   worker demands one;
//! * the low-level single-NAME syscall wrappers in [`unix`] (`unlinkat`,
//!   `renameat`, `symlinkat`, `linkat`, `mkdirat`) and the mutating branch of
//!   [`openat_no_follow_io`] run the guard at the PRIMITIVE, so a new caller
//!   of an existing wrapper is guarded without remembering to be;
//! * the wrappers are private and every direct name-mutating `libc` call in
//!   the crate lives in [`unix`] (enforced by the source audits
//!   `guard::tests::no_libc_reference_outside_the_funnel` and
//!   `guard::tests::std_fs_name_mutation_counts_are_pinned`), so a new
//!   primitive must either present the capability or fail an audit.
//!
//! The honest residual is in [`guard`]'s module docs and [`crate::reserved::is_lock_record_name`].
//!
//! # The platform split (ONE cfg switch at the module boundary)
//!
//! The platform-dependent primitives — private permissions, the atomic
//! replace's rename/fsync semantics, and the owned-root confinement — live
//! in the [`unix`] / [`windows`] submodules, selected by the TWO `mod`
//! declarations below (the single cfg switch point). [`unix`] provides the
//! descriptor-relative `_fd` implementation (`openat`/`renameat`/`linkat`/
//! `unlinkat`/`mkdirat` with `O_NOFOLLOW` — on that `_fd` surface every
//! PARENT component is refused as a symlink, and the open/create-new helpers
//! refuse the FINAL component too, while the atomic replace installs with
//! `renameat` and replaces the final entry without ever following it; see
//! [`unix`]'s module docs — plus the POSIX parent-directory fsync
//! durability). That component confinement covers the `_fd` surface only:
//! [`unix`]'s PATH-BASED free functions (`set_private`,
//! `write_atomic_replace`, `sync_parent_dir`, `ensure_private_dir`,
//! `ensure_private_dir_durable`, `copy_dir_recursive`, `remove_dir_all_path`)
//! take an ordinary path and are NOT covered — see [`unix`]'s module docs for
//! the exact split.
//! [`windows`] is the path-based implementation with documented weaker
//! guarantees: no directory descriptors (the root is a path), no
//! parent-directory fsync durability, a non-atomic replace (Windows
//! `rename` does not overwrite), and no Unix mode bits. The rest of the
//! crate calls the re-exported surface below and never sees the switch.

use crate::error::{Error, Result};
#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

mod guard;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

// THE one lock-record guard authority and its unforgeable capability. The
// `guard` module's fields are private, so no other module can build a
// `GuardedRel` without running the guard; the rel-path mutators demand one.
// `OwnedLockRecord` is the unforgeable OWNERSHIP authority the guard consults;
// it can only be built from the transport's own `Layout`.
// The alias keeps the historical spelling used throughout the primitives.
pub(crate) use guard::{GuardedRel, OwnedLockRecord};

/// Run the lock-record guard through the capability's constructors
/// ([`GuardedRel::new`] for ordinary content and
/// [`GuardedRel::new_for_owned_lock_record`] for the protocol's own record);
/// `guard::refuse_lock_record` itself is private to `guard`, so this
/// convenience wrapper — and every rel-path mutator that calls it — must still
/// mint the capability. There is no other way to run the guard.
pub(crate) fn refuse_lock_record_mutation(rel: &Path) -> Result<()> {
    GuardedRel::new(rel).map(|_| ())
}

#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;

/// THE component-confinement property of the platform's primitives: `true`
/// exactly when the `_fd` surface selected by the `mod` declarations above
/// resolves every path COMPONENT without following a symlink, so a symlink
/// injected into a path component is REFUSED rather than traversed.
///
/// It lives HERE, at the single `#[cfg]` switch that chooses `unix` or
/// `windows`, so the claim is stated once and cannot drift from the
/// implementations it describes:
///
/// * `true` on Unix: on the `_fd` surface the `unix` module resolves every
///   parent component with component-wise `openat(O_NOFOLLOW)` and raises
///   `ELOOP` on a symlink there for EVERY primitive of that surface, reads
///   included. That is the confinement an operation can rely on INSTEAD of a
///   live path check. The property does NOT extend to [`unix`]'s PATH-BASED
///   free functions (`set_private`, `write_atomic_replace`, `sync_parent_dir`,
///   `ensure_private_dir`, `ensure_private_dir_durable`, `copy_dir_recursive`,
///   `remove_dir_all_path`): those take an ordinary path, so an intermediate
///   symlink in it IS followed — see [`unix`]'s module docs for the split.
/// * `false` on Windows: the `windows` module is path-based (`Path::join`
///   plus `std::fs`), and `Path::join` has no component-wise `O_NOFOLLOW`,
///   so a symlink in a path component is followed. A caller must not treat a
///   path as confined here; the live preflight remains the only guarantee.
///
/// A caller that reads "component-confined" as a licence to skip a live
/// confinement check MUST consult this property. Consulting the side kind
/// alone is not enough: the side kind says which caller API is in use, not
/// whether THIS platform's primitives refuse a swapped component.
pub const COMPONENT_CONFINED: bool = cfg!(unix);

/// The path-based JSON reader — TEST-ONLY (the crash-consistency assertions
/// read a REOPENED store's files directly to verify the on-disk state). The
/// store's OWN record reads route through [`read_json_fd`]
/// (descriptor-relative: a symlink in any component, final included, is
/// refused); no production caller uses the
/// raw-path reader, so it is `#[cfg(test)]`-gated (no `#[allow(dead_code)]`
/// band-aid).
#[cfg(test)]
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes =
        std::fs::read(path).map_err(|e| Error::store(format!("read {}: {e}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::store(format!("deserialize {}: {e}", path.display())))
}
/// TRI-STATE existence check for marker/backup/log DISCOVERY: is `path`
/// present? A genuine [`std::io::ErrorKind::NotFound`] from
/// [`std::fs::symlink_metadata`] is the ONE outcome that reads as ABSENCE
/// (`Ok(false)`); EVERY other filesystem error (EACCES, EIO, ENOTDIR, ...)
/// is a real failure → [`Error::store`], NEVER treated as absence. This is
/// the fail-closed replacement for the boolean `.exists()` checks that
/// silently read a permission/I/O error on the marker directory as "no
/// floor" / "no pending cleanup" / "no backups".
///
/// The store's WRITE-path open-or-create checks (`append_attempt`,
/// `append_snapshot`, `write_atomic_cas`) are deliberately NOT converted:
/// there a swallowed `exists()` error lands in the subsequent open/create
/// call, which fails and propagates anyway — no silent absence is possible.
///
/// Under `#[cfg(test)]` the check routes through the injectable
/// `MarkerIoOps` seam when a test installed one, so the tri-state
/// property can force each outcome on the marker path.
pub fn path_state(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) => absent_or_store(e, path),
    }
}

/// Classify a metadata error tri-state: ONLY a genuine
/// [`std::io::ErrorKind::NotFound`] is absence (`Ok(false)`); any other io
/// error is [`Error::store`] (a permission/read failure is never "no
/// marker").
fn absent_or_store(e: std::io::Error, path: &Path) -> Result<bool> {
    if e.kind() == std::io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(Error::store(format!("stat {}: {e}", path.display())))
    }
}

/// The largest number of bytes a single filesystem NAME may hold (POSIX
/// `NAME_MAX`). The manifest accepts a name up to this bound (and now ENFORCES
/// it at the boundary: [`crate::manifest`]'s path validator and
/// [`crate::id::valid_name`] both refuse a longer component rather than
/// letting the filesystem refuse it later with `ENAMETOOLONG`), so every temp
/// name the crate derives from a destination must stay within it — a temp
/// that is even one byte longer makes a legal destination untransferable.
pub const NAME_MAX: usize = 255;

/// The number of bytes [`bounded_temp_trunk`] reserves so its two branches
/// cannot collide. The truncated branch's trunk is at least
/// `NAME_MAX - overhead - 3` bytes (3 is the most a UTF-8 boundary back-off
/// can shorten a 4-byte character), while the verbatim branch is taken only
/// when the trunk fits in `NAME_MAX - overhead - SLACK`; with `SLACK = 4` the
/// two length ranges are DISJOINT, so no verbatim name can ever equal a
/// truncated one (F-C).
const BOUNDED_TRUNK_BRANCH_SLACK: usize = 4;

/// Derive the BOUNDED trunk of a temp name from a destination `name`, so
/// `.TRUNK<SUFFIX>` never exceeds [`NAME_MAX`] bytes.
///
/// When the destination's name already leaves room for `suffix` AND the
/// branch slack, the trunk IS the name VERBATIM, so the historical spelling
/// `.name.tmp.<pid>.<n>` is preserved for every name that fits. When it does
/// not fit, the trunk is a byte-truncated prefix of the name plus the SHA-256
/// of the FULL name: the prefix keeps the temp recognizable next to its
/// destination and the hash keeps two DISTINCT long names distinct (a
/// truncation alone could collapse them). Truncation stops on a UTF-8
/// boundary — the names the crate carries are the manifest's UTF-8 names.
///
/// The derivation is INJECTIVE by construction (F-C): the verbatim branch is
/// restricted to trunks of at most `NAME_MAX - overhead - SLACK` bytes, while
/// the truncated branch always emits at least `NAME_MAX - overhead - 3`
/// bytes, so a name returned verbatim can never be the truncation of a
/// different name (the pre-fix bound returned the name verbatim whenever it
/// merely fit, so a 240-byte name's 239-byte hash-truncated trunk was itself
/// returned verbatim by the next call — two distinct destinations shared one
/// lock record). Within the truncated branch two distinct names collide only
/// if their SHA-256 digests collide, and the digest is taken over the FULL
/// name, so the branch stays injective.
pub(crate) fn bounded_temp_trunk(name: &str, suffix: &str) -> String {
    let overhead = 1 + suffix.len();
    if overhead + name.len() + BOUNDED_TRUNK_BRANCH_SLACK <= NAME_MAX {
        return name.to_string();
    }
    let hash = crate::digest::sha256_bytes(name.as_bytes());
    let budget = NAME_MAX
        .saturating_sub(overhead)
        .saturating_sub(1)
        .saturating_sub(hash.len());
    let mut end = budget.min(name.len());
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}.{}", &name[..end], hash)
}

/// The next value of the process-scoped temp counter shared by EVERY local
/// temp-naming authority, so two temps derived for one destination can never
/// collide even when the path-based and descriptor-relative writers both run.
fn next_temp_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// The suffix MARKER the atomic-replace temp authority ([`temp_name_string`])
/// appends to the bounded destination trunk: the `.tmp.` half of
/// `.TRUNK.tmp.<pid>.<counter>`.
pub(crate) const TEMP_SUFFIX_MARKER: &str = ".tmp.";

/// The suffix MARKER of the compare-and-delete CLAIM temp
/// ([`crate::transport::Remote::remove_file_if`]'s fallback claim, which
/// reuses [`bounded_temp_trunk`]): the `.claim.` half of
/// `.TRUNK.claim.<pid>.<counter>`.
pub(crate) const CLAIM_SUFFIX_MARKER: &str = ".claim.";

/// The unique temp NAME for a destination named `name`, shared by
/// [`temp_name_for`] and [`temp_file_name`]: `.trunk.tmp.<pid>.<n>` with the
/// trunk bounded to [`NAME_MAX`] by [`bounded_temp_trunk`].
fn temp_name_string(name: &str) -> String {
    let suffix = format!(
        "{TEMP_SUFFIX_MARKER}{}.{}",
        std::process::id(),
        next_temp_counter()
    );
    format!(".{}{}", bounded_temp_trunk(name, &suffix), suffix)
}

/// The `mktemp` placeholder the far-side authorities append to a temp
/// TEMPLATE; `mktemp` replaces it with EXACTLY this many alphanumeric
/// characters. The generators build the placeholder from THIS constant and the
/// recognizer bounds the far-side tail to its width and charset, so the two
/// share one definition instead of a second hardcoded `"XXXXXX"`.
pub(crate) const MKTEMP_PLACEHOLDER: &str = "XXXXXX";

/// Whether `tail` (the text AFTER a temp marker) is `<n>` non-empty all-digit
/// dot-separated parts.
fn numeric_tail_parts(tail: &str, n: usize) -> bool {
    let mut parts = tail.split('.');
    for _ in 0..n {
        match parts.next() {
            Some(part) if !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()) => {}
            _ => return false,
        }
    }
    parts.next().is_none()
}

/// Whether `tail` is exactly one far-side `mktemp` replacement: as many
/// alphanumeric characters as [`MKTEMP_PLACEHOLDER`] is wide (the charset GNU
/// and BSD `mktemp` draw their replacement from).
pub(crate) fn is_mktemp_tail(tail: &str) -> bool {
    tail.len() == MKTEMP_PLACEHOLDER.len() && tail.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The ONE temp-TAIL grammar: whether `tail`, produced by a generator that
/// appended `marker` after the destination `trunk`, is a tail one of the
/// crate's own temp authorities writes. Each arm names its generator:
///
/// * `TEMP_SUFFIX_MARKER` + `<pid>.<counter>` — the local atomic replace
///   ([`temp_name_string`]);
/// * `TEMP_SUFFIX_MARKER` + `<pid>.<time>.<rand>` — the far-side sidecar
///   replace (`SshTransport::write_sidecar_cmd`);
/// * `TEMP_SUFFIX_MARKER` + `<pid>` when the trunk IS the application lock
///   record — the far-side sidecar recover
///   (`SshTransport::recover_sidecar_cmd`, whose temp is
///   `.operation.lock.tmp.<pid>`);
/// * either marker + one [`MKTEMP_PLACEHOLDER`]-wide alphanumeric token — the
///   far-side `mktemp` write/claim templates (`SshTransport::write_cmd` /
///   `SshTransport::remove_file_if_cmd`);
/// * `CLAIM_SUFFIX_MARKER` + `<pid>.<counter>` — the local compare-and-delete
///   claim (`LocalTransport::remove_file_if`).
///
/// The arms are DISJOINT by shape, so the recognizer cannot confuse a
/// two-part local tail with a three-part sidecar tail, and the one-part arm is
/// gated on the trunk so an ordinary name that merely looks like
/// `.foo.tmp.<digits>` stays ordinary.
fn is_crate_temp_tail(marker: &str, trunk: &str, tail: &str) -> bool {
    if marker == TEMP_SUFFIX_MARKER {
        return numeric_tail_parts(tail, 2)
            || numeric_tail_parts(tail, 3)
            || (trunk == crate::reserved::APPLICATION_LOCK_NAME && numeric_tail_parts(tail, 1))
            || is_mktemp_tail(tail);
    }
    if marker == CLAIM_SUFFIX_MARKER {
        return numeric_tail_parts(tail, 2) || is_mktemp_tail(tail);
    }
    false
}

/// The crate's temp-SHAPE grammar: whether `name` is spelled exactly like one
/// of the crate's own temp names. This is the ONE authority for the shape; it
/// is exposed through the public recovery recognizer
/// [`is_crate_temp_name`] AND consulted by the id/name rule
/// ([`crate::id::valid_name`], via
/// [`crate::reserved::is_unaddressable_name`]), so an id the crate accepts can
/// never look like one of its own temps (F-B: the documented recovery sweep
/// that removes every [`is_crate_temp_name`] match is safe BY CONSTRUCTION —
/// no addressable content can match).
///
/// The leading dot is PART of the shape, not a heuristic: every generator
/// emits it ([`temp_name_string`] and the far-side templates all spell
/// `.<trunk><marker><tail>`), so a name the id rule accepts but no generator
/// can produce — `report.tmp.123.4` — is NOT a crate temp and is never offered
/// to the recovery sweep.
pub(crate) fn is_crate_temp_shape(name: &str) -> bool {
    let Some(rest) = name.strip_prefix('.') else {
        return false;
    };
    [TEMP_SUFFIX_MARKER, CLAIM_SUFFIX_MARKER]
        .iter()
        .any(|marker| match rest.rsplit_once(marker) {
            Some((trunk, tail)) => is_crate_temp_tail(marker, trunk, tail),
            None => false,
        })
}

/// Whether `name` is one of the crate's own TEMP names. This is the public
/// recovery recognizer; it answers with the shape grammar
/// [`is_crate_temp_shape`], which the id/name rule consults too, so a
/// `true` answer here is never a name [`crate::id::valid_name`] accepts.
///
/// This is how a caller tells a CRASHED TEMP from a HELD-ASIDE. Both can sit
/// in the RESERVED `.sync-aside.` namespace (`crate::reserved`), because a temp
/// for a destination whose own name begins `sync-aside.` inherits the prefix:
/// `.sync-aside.<name>.tmp.<pid>.<n>`. A genuine claim-aside, by contrast, is
/// `.sync-aside.<pid>.<n>` with NO marker — it HOLDS the stranded original. The
/// ONLY decisive feature is the authority's own marker and tail, so the test
/// is a shape match on that spelling, never a heuristic on the destination
/// name.
///
/// # Crash residue (B2): the recognizer and the recovery recipe
///
/// A failed atomic replace cleans up its temp on an ERROR RETURN (best-effort,
/// the cleanup failure carried with the original error). A process that is
/// KILLED mid-replace (`SIGKILL`) never returns, so the temp it wrote survives
/// — that residue is inherent to POSIX and is NOT a leak the crate can prevent.
/// This predicate is the crate's OWN recognizer for it, so a consumer's
/// recovery pass can enumerate a directory (including the ROOT, via
/// [`crate::atomic::read_root_dir_fd`]) and remove every entry for which
/// [`is_crate_temp_name`] is true: the atomic replace has TWO commit points, so
/// the destination is either wholly OLD or wholly NEW and a stranded temp
/// carries no committed state. The `.claim.` variant is a compare-and-delete
/// claim temp and is likewise residue once no operation is live. A genuine
/// claim-ASIDE (no authority marker) HOLDS a stranded original and must NOT be
/// removed by this predicate — inspect it first.
pub fn is_crate_temp_name(name: &str) -> bool {
    is_crate_temp_shape(name)
}

/// Unique temp-file name for an atomic replace of `path`: same directory,
/// hidden dot-prefixed name carrying the process id and a process-scoped
/// counter, so concurrent atomic writes on one store stay collision-free. The
/// embedded destination name is BOUNDED ([`bounded_temp_trunk`]), so a
/// destination at the manifest's legal maximum (255 bytes) still has a usable
/// temp name.
pub fn temp_name_for(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(temp_name_string(&name))
}

/// The unique temp FILE NAME for an atomic replace of a file named
/// `file_name`: hidden dot-prefixed, carrying the process id and a
/// process-scoped counter (the same naming as [`temp_name_for`], but for
/// the descriptor-relative writers that need just the name). The embedded
/// name is bounded exactly as [`temp_name_for`] bounds it. Unix-only
/// (the Windows `_fd` writers use the path-based replace's own temp
/// naming).
#[cfg(unix)]
pub fn temp_file_name(file_name: &OsStr) -> std::ffi::OsString {
    std::ffi::OsString::from(temp_name_string(&file_name.to_string_lossy()))
}

/// Best-effort removal of a FAILED atomic replace's temp file.
///
/// `original` is the failure that triggered the cleanup. The unlink is
/// best-effort — the caller is already receiving a failure — but it is NEVER
/// silent: when the unlink itself fails, the returned error carries BOTH the
/// original failure and the cleanup failure, so the caller can see that a
/// stray temp entry may remain. On success the original error is returned
/// unchanged (same class, same message).
///
/// NEVER called after a successful rename: the temp name no longer exists (it
/// IS the destination), so an unlink would remove the committed content. The
/// post-rename parent-fsync failure ([`ReplaceOutcome::ReplacedDurabilityUnknown`])
/// is therefore NOT a cleanup point.
fn discard_temp(original: Error, tmp: &Path) -> Error {
    match std::fs::remove_file(tmp) {
        Ok(()) => original,
        Err(e) => original.with_context(format!(
            "additionally failed to unlink the failed replace's temp {}: {e}",
            tmp.display()
        )),
    }
}

/// The explicit outcome of an atomic replace: the two commit points
/// (the rename — new content VISIBLE — and the parent-directory fsync —
/// new content DURABLE) are reported distinctly, so a caller can always
/// tell "the rename never happened" from "the rename happened but
/// durability is unconfirmed" (see `write_atomic_replace`).
#[derive(Debug)]
pub enum ReplaceOutcome {
    /// BOTH commit points confirmed: the new content is visible under its
    /// final name AND the parent-directory fsync succeeded — the replace
    /// is durable across power loss. When the replace had to CREATE the
    /// parent chain, every newly created directory's own entry was fsynced
    /// into its parent BEFORE the rename (the durable directory helper), so
    /// the claim covers the WHOLE chain, not only the final entry's parent.
    ReplacedDurable,
    /// ONLY the rename (commit point 1) is confirmed: the new content IS
    /// visible under its final name, but the parent-directory open/fsync
    /// (commit point 2) failed AFTER the rename — durability is
    /// UNCONFIRMED and the failure is carried. NEVER a bare `Err`: `Err`
    /// means the rename never happened (the old content is still visible).
    ReplacedDurabilityUnknown { error: Error },
}

/// The [`write_atomic_replace`] stage a test-injected fault fires at. The
/// hook is [`write_atomic_replace`]'s own `fault` parameter, so a
/// per-fixture registry can fault each atomic-replacement stage exactly as
/// the append path's `FaultKind::AppendWrite` family does; production
/// passes a no-op hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplaceStage {
    /// The temp-file CREATE/WRITE stage (before any I/O on the temp): the
    /// visible target is wholly OLD; a fault here is an `Err`.
    Write,
    /// The temp-file FSYNC stage (after the write, before the chmod): a
    /// dot-prefixed temp exists and is unlinked before the `Err` is
    /// returned; the visible target is wholly OLD; a fault here is an
    /// `Err`.
    Sync,
    /// The RENAME stage (after the chmod, before the atomic rename): the
    /// visible target is wholly OLD; a fault here is an `Err`.
    Rename,
    /// The PARENT-DIRECTORY open/fsync stage, AFTER the rename: the new
    /// content IS visible under its final name but its durability is
    /// unconfirmed — reported as
    /// [`ReplaceOutcome::ReplacedDurabilityUnknown`], never an `Err`.
    DirSync,
}

/// One entry of a descriptor-relative directory read.
pub struct DirEntry {
    /// The entry's file name (never `.` or `..`).
    pub name: std::ffi::OsString,
    /// Whether the entry is a directory (classified with
    /// `fstatat(AT_SYMLINK_NOFOLLOW)` — a symlink entry is reported as a
    /// non-directory, never followed).
    pub is_dir: bool,
}

/// The kind of a directory entry, classified WITHOUT following a symlink.
///
/// [`path_kind_fd`] returns this for the entry at a root-relative path. The
/// classification is deliberately independent of the entry's target: a
/// symlink whose TARGET is a directory is [`PathKind::Symlink`], never
/// [`PathKind::Dir`] — exactly the distinction [`DirEntry::is_dir`] cannot
/// make, and the answer [`path_state_fd`] cannot report (its `O_NOFOLLOW`
/// open raises `ELOOP` for a symlink instead of answering "this entry
/// exists and is a symlink").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathKind {
    /// A regular file (`S_IFREG`).
    File,
    /// A directory (`S_IFDIR`).
    Dir,
    /// A symbolic link (`S_IFLNK`), whatever its target's kind.
    Symlink,
    /// Any other entry kind (FIFO, socket, device, ...).
    Other,
}

// =====================================================================
// THE OWNED ROOT (the store's mutation anchor)
// ---------------------------------------------------------------------
// Unix: an open directory descriptor (`O_DIRECTORY | O_NOFOLLOW |
// O_CLOEXEC`) — every mutation resolves component-wise with
// `openat(O_NOFOLLOW)`: a symlink at any parent component is refused and
// the atomic replace replaces the final entry with `renameat` without
// following it, so a symlink injected into a path component can never
// redirect a mutation outside the owned root. Windows: the root
// PATH (no directory descriptors); mutations resolve path-based with
// documented weaker guarantees — Windows symlinks require
// admin/developer mode (a smaller symlink-injection attack surface), and
// there is no parent-directory fsync durability.
// =====================================================================
#[cfg(unix)]
pub struct RootDir(OwnedFd);
#[cfg(windows)]
pub struct RootDir(PathBuf);

/// Normalize the spelling of an owned-root path so two spellings that name
/// the same directory open the same root. Trailing path separators are
/// stripped, along with repeated separators and non-leading `.`
/// components that [`Path::components`] erases anyway (all of these name
/// the same directory). The filesystem root is preserved: `/` normalizes
/// to `/`, never to the empty path.
///
/// The strip is load-bearing, not cosmetic. A trailing separator DEFEATS
/// `O_DIRECTORY | O_NOFOLLOW`, because POSIX resolves `link/` by following
/// `link` as an INTERMEDIATE component (the final component is empty), so
/// the symlink-refusing open never sees the link — while the same root
/// spelled `link` is refused. Normalizing before the open makes both
/// spellings take the same path. A `..` in the root is the caller's own
/// trusted base and is left intact; a `..` in a ROOT-RELATIVE entry path
/// is refused by [`validate_rel`].
fn normalize_root(base: &Path) -> PathBuf {
    base.components().collect()
}

/// Validate that `path` is a ROOT-RELATIVE entry path, refusing every
/// spelling that could resolve outside the owned root. Only
/// [`std::path::Component::Normal`] components are admitted:
///
/// * an absolute path contributes a `RootDir`/`Prefix` component, and
///   `openat` IGNORES the root descriptor for an absolute path (on the
///   Windows port `Path::join` REPLACES the root instead), so the
///   operation would resolve against the real filesystem root — a
///   confinement escape;
/// * a `..` (`ParentDir`) component walks ABOVE the root;
/// * `.` (`CurDir`) and the empty path name the root directory itself,
///   never an entry under it.
///
/// Trailing and repeated separators are NOT refused: [`Path`] erases them,
/// so `a/b/` and `a//b` are the same components as `a/b` and the spellings
/// keep resolving identically. Every refusal is an
/// [`std::io::ErrorKind::InvalidInput`] so each caller folds it into its
/// own path-contextual store error (fail-closed: a path error, never an
/// interesting resolution).
fn validate_rel(path: &Path) -> std::io::Result<()> {
    let mut names_an_entry = false;
    for component in path.components() {
        match component {
            std::path::Component::Normal(_) => names_an_entry = true,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "a root-relative path may contain only normal components \
                     (no absolute path, no `..`, no `.`)",
                ));
            }
        }
    }
    if !names_an_entry {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a root-relative path must name at least one normal component \
             (the empty path is refused)",
        ));
    }
    Ok(())
}

impl RootDir {
    /// Open the owned root.
    ///
    /// The path is normalized first ([`normalize_root`]): trailing path
    /// separators are stripped, so `dir/` and `dir` open the SAME root. On
    /// Unix the open is `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`, so the
    /// descriptor pins the root and a real directory opens, a
    /// symlink-to-directory is refused (`ENOTDIR`/`ELOOP`), and a regular
    /// file is refused (`ENOTDIR`) — IDENTICALLY for both spellings.
    ///
    /// Windows (the path-based port) stores the normalized path, so both
    /// spellings name the same root for every later mutation. It does NOT
    /// guarantee the same refusal: there is no directory descriptor and no
    /// `O_NOFOLLOW` equivalent here, so a symlink root (which on Windows
    /// requires admin/developer mode) is not refused at open — the
    /// documented weaker guarantee of the Windows port.
    pub fn open(base: &Path) -> Result<RootDir> {
        let base = normalize_root(base);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.read(true);
            opts.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let f = opts
                .open(&base)
                .map_err(|e| Error::store(format!("open root {}: {e}", base.display())))?;
            Ok(RootDir(f.into()))
        }
        #[cfg(windows)]
        {
            Ok(RootDir(base))
        }
    }

    #[cfg(unix)]
    pub fn as_fd(&self) -> &OwnedFd {
        &self.0
    }

    #[cfg(windows)]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{
        NAME_MAX, ReplaceOutcome, ReplaceStage, bounded_temp_trunk, is_crate_temp_name,
        normalize_root, temp_name_for, validate_rel, write_atomic_replace,
    };
    use crate::error::Error;
    use crate::test_support::{fixture_env, fixture_tmpdir, proptest_cases, slow_tests_enabled};
    use proptest::prelude::*;

    /// Pin the platform property ITSELF, so a future port cannot leave the
    /// constant claiming a confinement its primitives do not enforce. The
    /// value is cfg-gated because each branch is a claim about the SELECTED
    /// implementation: on Unix the primitives refuse a symlinked component
    /// (`O_NOFOLLOW`), and on every other supported port they are path-based
    /// and follow it. A build in which the constant and the selected
    /// primitives disagree fails HERE.
    #[test]
    fn the_component_confinement_property_matches_the_selected_primitives() {
        // Read through a binding so this stays a runtime assertion about the
        // BUILT platform rather than a constant the linter folds away.
        let confined: bool = super::COMPONENT_CONFINED;
        #[cfg(unix)]
        assert!(
            confined,
            "the Unix primitives refuse a symlinked path component (O_NOFOLLOW), so this \
             platform IS component-confined"
        );
        #[cfg(not(unix))]
        assert!(
            !confined,
            "the path-based primitives (Path::join has no component-wise O_NOFOLLOW) follow a \
             symlinked path component, so this platform is NOT component-confined"
        );
    }

    fn marker_path() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let path = dir.path().join("marker.json");
        (dir, path)
    }

    /// The temp-name authority recognises EXACTLY the shapes its own
    /// generators emit, and nothing else. This is what lets the sync tell a
    /// CRASHED TEMP (extraneous, a removal) from a HELD claim-aside (residue,
    /// inspect first), including when the temp inherits the `.sync-aside.`
    /// prefix from a destination named `sync-aside.*`. The predicate is a SHAPE
    /// test; the reserved-prefix half of the classification lives in
    /// `sync::apply`.
    ///
    /// The recognizer is EXACTLY the shapes the crate's own generators emit:
    /// the local two-part `<pid>.<counter>` tail, the far-side `mktemp`
    /// six-alphanumeric tail, the sidecar three-part `<pid>.<time>.<rand>`
    /// tail, and the operation-lock sidecar recover one-part `<pid>` tail —
    /// and nothing else.
    ///
    /// CHANGED DELIBERATELY (G1/F4): the pre-fix predicate was BOTH over- and
    /// under-broad — it matched `notes.tmp.1.0` (no leading dot: a name the id
    /// rule ACCEPTS, so the documented recovery sweep could delete live
    /// content) and MISSED the far-side `mktemp` tail `.tmp.aB3xY9` and the
    /// sidecar three-part tail, so a crashed far-side temp was misreported as a
    /// held-aside and never removed. The former "near-miss"
    /// `.sync-aside.foo.tmp.1.2.3` is a genuine sidecar temp and is asserted
    /// TRUE now; the dotless spellings moved to the "not a temp" list.
    #[test]
    fn temp_names_are_exactly_the_authoritys_suffixes() {
        let generated = temp_name_for(std::path::Path::new("sync-aside.foo"));
        let generated = generated
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(generated.starts_with(".sync-aside.foo.tmp."), "{generated}");
        assert!(is_crate_temp_name(&generated), "{generated}");

        for temp in [
            // Local atomic-replace tail: `<pid>.<counter>`.
            ".sync-aside.foo.tmp.12345.0",
            ".sync-aside.case.tmp.1.2",
            // Sidecar replace tail: `<pid>.<time>.<rand>` (G1).
            ".sync-aside.foo.tmp.1.2.3",
            ".op.json.tmp.1234.1700000000.42",
            ".sync-aside.foo.tmp.12345.0.1",
            // Far-side `mktemp` tail: six alphanumerics (G1).
            ".sync-aside.foo.tmp.aB3xY9",
            ".op.json.tmp.abc123",
            ".sync-aside.foo.claim.Zz09Qw",
            // Operation-lock sidecar recover tail: one `<pid>`.
            ".operation.lock.tmp.4242",
            // Local claim tail: `<pid>.<counter>`.
            ".sync-aside.1234.claim.7.0",
            ".a.claim.1.0",
        ] {
            assert!(is_crate_temp_name(temp), "{temp:?} is a crate temp");
        }
        for other in [
            // A genuine claim-aside: reserved, but NO authority marker.
            ".sync-aside.999.0",
            ".sync-aside.case-probe.1.2",
            // Near-misses on the tail shape.
            ".sync-aside.foo.tmp.x.0",
            // Four numeric parts: no generator emits this (the sidecar tail is
            // exactly three), so it is not a temp.
            ".sync-aside.foo.tmp.12345.0.1.2",
            ".sync-aside.foo.tmp..0",
            ".sync-aside.foo.tmp.0.",
            ".sync-aside.foo.tmp0.1",
            // A one-part numeric tail with a NON-lock trunk: no generator
            // emits this, so it stays ordinary.
            ".sync-aside.foo.tmp.12345",
            ".operation.lock.tmp.abc",
            "",
        ] {
            assert!(!is_crate_temp_name(other), "{other:?} is NOT a crate temp");
        }

        // F4 NEAR-MISS: the crate's temps ALWAYS begin with `.`, so a dotless
        // name the id rule ACCEPTS must NOT be offered to the recovery sweep.
        // Pre-fix the suffix-only match made every one of these `true`.
        for near_miss in [
            "notes.tmp.1.0",
            "report.tmp.123.4",
            "report.tmp.123.4.5",
            "report.tmp.aB3xY9",
        ] {
            assert!(
                !is_crate_temp_name(near_miss),
                "the dotless near-miss {near_miss:?} must NOT be a crate temp"
            );
            assert!(
                crate::id::valid_name(near_miss),
                "{near_miss:?} is an addressable id, so the recovery sweep must not delete it"
            );
        }
    }

    /// F-B PROPERTY: the recovery recognizer and the id rule can NEVER both
    /// accept a name. `is_crate_temp_name` is documented as the predicate a
    /// consumer's recovery sweep REMOVES every match of, so a name the id rule
    /// also accepts would let the documented sweep DELETE addressable content.
    /// The property is asserted over every shape the crate's generators produce
    /// (local replace, far-side sidecar/`mktemp`, claim), the DOTTED
    /// near-misses (the recognizer matches them, so the id rule must refuse
    /// them), and the DOTLESS near-misses (the id rule accepts them, so the
    /// recognizer must not match them).
    ///
    /// LOAD-BEARING BY MUTATION: broadening `is_crate_temp_name` to match a
    /// dotless name the id rule accepts (for example `notes.tmp.1.0`) fails the
    /// dotless cases below, because the id rule's temp refusal consults the
    /// SHAPE grammar ([`super::is_crate_temp_shape`]) rather than the public
    /// recognizer this test calls.
    #[test]
    fn no_name_is_both_a_crate_temp_and_an_addressable_id() {
        // Every shape the crate's OWN generators produce.
        let generated: Vec<String> = [
            "record.json",
            "sync-aside.foo",
            "report",
            ".operation.lock",
            "nested/entry",
        ]
        .iter()
        .map(|dest| {
            temp_name_for(std::path::Path::new(dest))
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();

        // Far-side and claim shapes: sidecar `<pid>.<time>.<rand>`, `mktemp`
        // six-alphanumeric, lock sidecar one `<pid>`, local claim
        // `<pid>.<counter>`.
        let far_side = [
            ".op.json.tmp.1234.1700000000.42",
            ".op.json.tmp.abc123",
            ".operation.lock.tmp.4242",
            ".sync-aside.1234.claim.7.0",
        ];

        // Dotted near-misses: the recognizer matches them, so the id rule must
        // refuse them (F-B).
        let dotted = [
            ".notes.tmp.1.0",
            ".a.tmp.1.0",
            ".report.tmp.1.0",
            ".a.claim.1.0",
            ".a.tmp.aB3xY9",
            ".operation.lock.tmp.1",
            ".op.json.tmp.1.2.3",
            ".report.tmp.123.4",
        ];

        // Dotless near-misses: the id rule ACCEPTS them, so the recognizer must
        // NOT match them.
        let dotless = [
            "notes.tmp.1.0",
            "report.tmp.123.4",
            "report.tmp.123.4.5",
            "report.tmp.aB3xY9",
        ];

        for name in generated
            .iter()
            .map(String::as_str)
            .chain(far_side)
            .chain(dotted)
            .chain(dotless)
        {
            assert!(
                !(is_crate_temp_name(name) && crate::id::valid_name(name)),
                "{name:?} must never be BOTH a crate temp and an addressable id: the documented \
                 recovery sweep would delete addressable content"
            );
        }
        // The premise is non-vacuous in BOTH directions.
        for name in far_side.iter().copied().chain(dotted) {
            assert!(
                is_crate_temp_name(name),
                "premise: {name:?} is a crate temp"
            );
            assert!(
                !crate::id::valid_name(name),
                "premise: the id rule refuses the temp shape {name:?}"
            );
        }
        for name in dotless {
            assert!(
                !is_crate_temp_name(name),
                "premise: {name:?} is not a crate temp"
            );
            assert!(
                crate::id::valid_name(name),
                "premise: {name:?} is addressable"
            );
        }
    }

    /// F-C: `bounded_temp_trunk` must be INJECTIVE. Pre-fix it returned the
    /// name VERBATIM whenever it merely fit, so `trunk(trunk(B)) == trunk(B)`
    /// for a long `B`: a 240-byte name forces the hash branch and its 239-byte
    /// trunk then fit verbatim, so two DISTINCT sibling destinations shared one
    /// lock record. The fix reserves branch slack so no verbatim trunk can
    /// equal a truncated one, and the hash keeps same-prefix long names
    /// distinct.
    ///
    /// LOAD-BEARING BY MUTATION: removing the hash from the truncation (keeping
    /// only the prefix) makes the same-prefix pair collide and fails this test.
    #[test]
    fn bounded_temp_trunk_is_injective() {
        let suffix = ".operation.lock"; // 15 bytes; `.` + suffix = overhead 16
        // The F-C collision: a 240-byte name forces the hash branch; its trunk
        // is then tested again and must not be returned verbatim.
        let long = "b".repeat(240);
        let trunk_long = bounded_temp_trunk(&long, suffix);
        assert!(
            trunk_long.len() >= NAME_MAX - 16 - 3,
            "the truncated trunk must occupy the reserved branch range, got {} bytes",
            trunk_long.len()
        );
        assert_ne!(
            bounded_temp_trunk(&trunk_long, suffix),
            trunk_long,
            "a truncated trunk must NOT be returned verbatim by a second call"
        );
        // Two long names with the SAME first 174 bytes differ only in their
        // tails: only the hash can keep them apart.
        let same_prefix_a = format!("{}{}", "c".repeat(174), "x".repeat(66));
        let same_prefix_b = format!("{}{}", "c".repeat(174), "y".repeat(66));
        assert_eq!(same_prefix_a.len(), 240);
        assert_eq!(same_prefix_b.len(), 240);
        assert_ne!(
            bounded_temp_trunk(&same_prefix_a, suffix),
            bounded_temp_trunk(&same_prefix_b, suffix),
            "long names with the same prefix must stay distinct (the hash is the distinguisher)"
        );
        // A name that fits verbatim cannot collide with any truncated trunk:
        // the two branches occupy disjoint length ranges.
        let verbatim = "v".repeat(100);
        assert_eq!(bounded_temp_trunk(&verbatim, suffix), verbatim);
    }

    /// COMMIT POINT 1 (the rename): a fault at the rename stage is a
    /// PRE-RENAME failure — `write_atomic_replace` returns a bare `Err`
    /// and the OLD content stays visible under the final name.
    #[test]
    fn pre_rename_failure_leaves_old_content_visible() {
        let (_dir, path) = marker_path();
        std::fs::write(&path, b"OLD").unwrap();
        let err = write_atomic_replace(&path, b"NEW", &mut |stage| {
            (stage == ReplaceStage::Rename).then(|| Error::store("injected rename fault"))
        })
        .unwrap_err();
        assert!(matches!(err, Error::Store(_)));
        assert_eq!(std::fs::read(&path).unwrap(), b"OLD".to_vec());
    }

    /// COMMIT POINT 2 (the parent-directory fsync): a fault AFTER the rename
    /// leaves the NEW content visible and reports
    /// [`ReplaceOutcome::ReplacedDurabilityUnknown`] — NEVER a bare `Err`.
    #[test]
    fn post_rename_parent_fsync_failure_reports_durability_unknown() {
        let (_dir, path) = marker_path();
        std::fs::write(&path, b"OLD").unwrap();
        let outcome = write_atomic_replace(&path, b"NEW", &mut |stage| {
            (stage == ReplaceStage::DirSync).then(|| Error::store("injected dir fsync fault"))
        })
        .unwrap();
        assert!(matches!(
            outcome,
            ReplaceOutcome::ReplacedDurabilityUnknown {
                error: Error::Store(_)
            }
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"NEW".to_vec());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(proptest_cases(64)))]
        /// The no-op hook is the production path: both commit points are
        /// confirmed and the new bytes are what a reader sees.
        #[test]
        fn successful_replace_roundtrips_arbitrary_bytes(old: Vec<u8>, new: Vec<u8>) {
            let (_dir, path) = marker_path();
            std::fs::write(&path, &old).unwrap();
            let outcome = write_atomic_replace(&path, &new, &mut |_stage| None).unwrap();
            prop_assert!(matches!(outcome, ReplaceOutcome::ReplacedDurable));
            prop_assert_eq!(std::fs::read(&path).unwrap(), new);
        }
    }

    /// The exhaustive per-stage sweep — the full suite runs it under
    /// `STORE_SYNC_FULL_TESTS`; the two commit-point tests above always run.
    /// EVERY pre-rename stage leaves the OLD content visible behind an
    /// `Err`; the post-rename stage leaves the NEW content visible behind
    /// `ReplacedDurabilityUnknown`, never an `Err`.
    #[test]
    fn exhaustive_stage_sweep() {
        if !slow_tests_enabled() {
            return;
        }
        for stage in [
            ReplaceStage::Write,
            ReplaceStage::Sync,
            ReplaceStage::Rename,
        ] {
            let (_dir, path) = marker_path();
            std::fs::write(&path, b"OLD").unwrap();
            let err = write_atomic_replace(&path, b"NEW", &mut |s| {
                (s == stage).then(|| Error::store("injected fault"))
            })
            .unwrap_err();
            assert!(matches!(err, Error::Store(_)));
            assert_eq!(std::fs::read(&path).unwrap(), b"OLD".to_vec());
        }
        let (_dir, path) = marker_path();
        std::fs::write(&path, b"OLD").unwrap();
        let outcome = write_atomic_replace(&path, b"NEW", &mut |s| {
            (s == ReplaceStage::DirSync).then(|| Error::store("injected fault"))
        })
        .unwrap();
        assert!(matches!(
            outcome,
            ReplaceOutcome::ReplacedDurabilityUnknown { .. }
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"NEW".to_vec());
    }

    /// The root spelling is NORMALIZED: a trailing separator, a repeated
    /// separator, and a non-leading `.` all name the same root as the plain
    /// spelling, while the filesystem root itself is preserved (`/` never
    /// becomes the empty path).
    #[test]
    fn normalize_root_strips_trailing_separators_and_preserves_the_root() {
        use std::path::{Path, PathBuf};
        for (spelling, want) in [
            ("a/b", "a/b"),
            ("a/b/", "a/b"),
            ("a/b//", "a/b"),
            ("a//b", "a/b"),
            ("a/./b", "a/b"),
            ("a/b///", "a/b"),
        ] {
            assert_eq!(
                normalize_root(Path::new(spelling)),
                PathBuf::from(want),
                "{spelling:?} must normalize to {want:?}"
            );
        }
        assert_eq!(normalize_root(Path::new("/")), PathBuf::from("/"));
        assert_eq!(normalize_root(Path::new("//")), PathBuf::from("/"));
    }

    /// The root-relative path guard: trailing and repeated separators are
    /// accepted (they name the same components), while an absolute path, a
    /// `..` walk, a `.`, and the empty path are refused as path errors.
    #[test]
    fn validate_rel_accepts_normal_spellings_and_refuses_escapes() {
        use std::path::Path;
        for ok in ["a", "a/b", "a/b/", "a//b", "a/./b", "a/b/c/"] {
            assert!(
                validate_rel(Path::new(ok)).is_ok(),
                "{ok:?} must be accepted"
            );
        }
        for bad in ["", ".", "./", "..", "../b", "a/../b", "a/..", "/b", "/"] {
            let err = validate_rel(Path::new(bad))
                .expect_err("an escaping or empty spelling must be refused");
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidInput,
                "{bad:?} must be an invalid-input path error"
            );
        }
    }
}
