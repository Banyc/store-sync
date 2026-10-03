//! The transport stack: connectivity to one server's remote root.
//!
//! The [`Remote`] trait plus the in-process [`LocalTransport`] lead this
//! module; the production SSH transport over `ssh`/`scp`, host-identity
//! verification and pinning (a strict known-hosts file or a pre-verified
//! fingerprint, never trust-on-first-use), and the ONE bounded subprocess
//! runner every ssh operation goes through live in the `ssh` submodule group.
//!
//! Transport setup is split into two phases: [`Remote::prepare_identity`]
//! (verify/pin the host key) runs before ANY remote request — including a dry
//! run's status inspection — while [`Remote::provision_layout`] (create the
//! deployment-directory layout) runs only behind the push engine's
//! non-dry-run gate.
//!
//! # Submodules
//!
//! * `runner` — the shared bounded child-runner: synchronized child
//!   ownership, process-group termination, and mandatory wait/reap before
//!   every returned outcome (used by [`LocalTransport::exec`]).
//! * `scripted` — the deterministic fake exec the property tests inject
//!   (test-only): scripted outcomes keyed by argv, no subprocess, no
//!   wall-clock — the parallel-safety seam.
//! * `ssh` — the SSH transport group: the [`SshTransport`] itself plus
//!   host-key verification (`ssh::hostkey`) and the bounded subprocess
//!   runner (`ssh::runner`).
//!
//! # Symlink-component confinement
//!
//! On Unix, every [`LocalTransport`] operation that resolves a NON-EMPTY
//! root-relative path BELOW the root does so COMPONENT-WISE from an fd-pinned
//! root with `openat(O_NOFOLLOW)` (see the `FD-CONFINED OPERATIONS` block on
//! the impl): a symlink injected at ANY component below the root is REFUSED,
//! never followed, with NO check-then-act window — the same guarantee the
//! crate's fd-confined `Side::Local` destination gives. That includes the
//! READS used as verification sources — `read`, `read_link`, and `metadata_opt`
//! (and therefore `metadata`, and `kind_opt`/`mode_opt` over a [`Remote`]), plus
//! `exists` — so a content/kind/mode verdict can never be computed from an
//! object outside the pinned root.
//!
//! The operations that are NOT component-wise confined are named precisely, and
//! each is documented at its definition:
//!
//! * the destination ROOT listing ([`Remote::list`] with the EMPTY path) is
//!   path-based ([`LocalTransport::list_path_based`]): `read_dir_fd` refuses the
//!   empty path, and the root path itself is the trusted anchor — the residual
//!   ROOT-swap race is the one this module documents;
//! * the durability helpers [`Remote::fsync_parent`] and [`Remote::fsync_tree`]
//!   open their directories by path (they fsync; they never redirect a
//!   mutation or source a verification verdict);
//! * [`Remote::provision_layout`] creates the caller-supplied BOOTSTRAP
//!   directories by path (`base.join(d)`), not by `mkdirat` — a trusted layout
//!   name, not destination content the applier resolves;
//! * [`Remote::copy_tree`] inherits the default list/read/write walk, which is
//!   component-wise confined for every non-root path it visits, but is not a
//!   single fd-pinned operation;
//! * the `#[cfg(not(unix))]` Windows bodies are path-based (the Windows port has
//!   no directory descriptors), the documented weaker guarantee of that port.
//!
//! The [`SshTransport`] far side is a shell script this crate may not change
//! (the `ssh` submodule group), so it CANNOT give that guarantee on its own.
//! There the applier's `sync` preflight is the guarantee: every destination
//! mutation first verifies, with `lstat`, that every strict ancestor component
//! is a REAL directory, so a PRE-EXISTING symlink component is refused before
//! the operation runs. A component SWAPPED between that preflight check and the
//! operation remains a residual race — the same class as the already-documented
//! root-swap race — and is NOT claimed to be closed for `SshTransport`.
//!
//! The transport is application-domain-free: the on-server layout (bootstrap
//! directories, the operation-lock paths, and the immutable receiver marker)
//! is the caller-supplied [`Layout`]; the receiver identity is the opaque
//! [`ReceiverId`].

mod rooted;
mod runner;
#[cfg(test)]
pub(crate) mod scripted;
mod ssh;

pub use rooted::RootedRelativePath;
#[cfg(unix)]
pub use runner::kill_process_group;
pub use runner::{ChildRunner, KillSeam, RealKill, RunError, RunOutcome, RunnerConfig};
pub use ssh::SshTransport;

use crate::env::SysEnv;
use crate::error::{Error, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use walkdir::WalkDir;

/// The caller-supplied deployment layout: the rooted relative paths the
/// transport anchors under its root. The crate carries no application layout
/// of its own — a caller that knows the on-server directory names supplies
/// them here.
///
/// * [`Layout::bootstrap_dirs`] — the directories `provision_layout` creates
///   before the first mutation.
/// * [`Layout::lock`] — the operation-lock record. Every sidecar-serialized
///   mutation of THIS path (create-new, compare-and-delete, recover) runs
///   under the flock on [`Layout::lock_sidecar`]. This is the IN-ROOT layout
///   lock. It is a DIFFERENT FILE from the sync's destination operation lock
///   ([`crate::sync::destination_lock_path`], a SIBLING of the destination
///   root), so the two locks DO NOT exclude each other: holding this one does
///   not exclude a [`crate::sync::sync`], and a sync holding its own record
///   does not exclude a holder of this one. A caller that wants both must take
///   both; neither path composes the other.
/// * [`Layout::lock_sidecar`] — the flock mutex file serializing mutations of
///   [`Layout::lock`]. Created once durably and never removed, so every
///   participant flocks the same inode.
/// * [`Layout::receiver_marker`] — the OPTIONAL immutable receiver-id marker.
///   When `Some`, `provision_layout` creates it once and `read_receiver_id`
///   reads it back; when `None` the transport has no receiver identity.
#[derive(Clone, Debug)]
pub struct Layout {
    pub bootstrap_dirs: Vec<RootedRelativePath>,
    pub lock: RootedRelativePath,
    pub lock_sidecar: RootedRelativePath,
    pub receiver_marker: Option<RootedRelativePath>,
}

impl Layout {
    /// A layout with no bootstrap directories and no receiver marker, whose
    /// lock paths are the conventional `state/operation.lock` and
    /// `state/operation.lock.mutex` — for callers that need no provisioning
    /// and never touch those two paths.
    pub fn empty() -> Layout {
        Layout {
            bootstrap_dirs: Vec::new(),
            lock: RootedRelativePath::from_validated(PathBuf::from("state/operation.lock")),
            lock_sidecar: RootedRelativePath::from_validated(PathBuf::from(
                "state/operation.lock.mutex",
            )),
            receiver_marker: None,
        }
    }
}

/// The length of the opaque receiver id: 40 lowercase hex characters (160
/// bits).
pub const RECEIVER_ID_LEN: usize = 40;

/// The opaque receiver identity: 40 lowercase hex characters generated from
/// 20 bytes of OS entropy, stored at [`Layout::receiver_marker`] as
/// `<id>\n`, read and validated (never regenerated) once provisioned. The
/// type is a newtype with a validating [`ReceiverId::parse`] and no unchecked
/// constructor, so a malformed marker can never be accepted as an identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReceiverId(String);

impl ReceiverId {
    /// Generate a fresh receiver id from 20 bytes of OS entropy (40 lowercase
    /// hex characters). Fails closed if the OS entropy source is unavailable.
    pub fn generate() -> Result<ReceiverId> {
        let mut bytes = [0u8; RECEIVER_ID_LEN / 2];
        getrandom::fill(&mut bytes)
            .map_err(|e| Error::transport(format!("receiver id entropy: {e}")))?;
        Ok(ReceiverId(hex::encode(bytes)))
    }

    /// Validate `s` as a receiver id: EXACTLY 40 lowercase hex characters.
    /// Anything else (empty, wrong length, uppercase, non-hex) is rejected.
    pub fn parse(s: &str) -> Result<ReceiverId> {
        let valid = s.len() == RECEIVER_ID_LEN
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if valid {
            Ok(ReceiverId(s.to_string()))
        } else {
            Err(Error::transport(format!(
                "invalid receiver id {s:?}: expected {RECEIVER_ID_LEN} lowercase hex characters"
            )))
        }
    }

    /// The id as a string slice (40 lowercase hex characters).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The wire form stored at the marker: the id followed by a newline.
    pub fn wire_bytes(&self) -> Vec<u8> {
        let mut out = self.0.as_bytes().to_vec();
        out.push(b'\n');
        out
    }
}

impl std::fmt::Display for ReceiverId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The remote-state protocol version. Bumped 1 -> 2 when the remote
/// generation record (`generations/<gen>/assignment.json`) gained the OWNER
/// MARKER (`application`/`slot`): a protocol-1 client would parse a
/// protocol-2 record WITHOUT the owner fields (serde ignores unknown
/// fields) and drive state whose ownership it cannot verify, so the
/// handshake must refuse a version mismatch in either direction (an old
/// client can never drive a state directory written by a newer one, and
/// vice versa). The protocol-2 read path additionally fails closed on a
/// record WITHOUT the owner marker (a required-field parse failure — a
/// legacy/transplanted record is never read as a valid deployment).
pub const PROTOCOL_VERSION: u32 = 2;

#[derive(Clone, Debug)]
pub struct RemoteEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub mode: u32,
}

#[derive(Clone, Debug)]
pub struct RemoteMeta {
    pub is_dir: bool,
    pub is_symlink: bool,
    pub is_file: bool,
    pub size: u64,
    pub mode: u32,
}

/// The typed cause of an [`ExecOutcome`] that carries the runner's `-1`
/// sentinel rather than a collected exit status — the outcome shape is
/// `exit_code == -1` either way, so the cause must be explicit. Bounding the
/// post-exit output drain made `-1` mean TWO different things, and a consumer
/// (and the manifest classifier) has to tell "the deadline killed a RUNNING
/// command" from "the command ran and exited, and only its bounded output
/// drain gave up".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutCause {
    /// The deadline fired while the command's child was still running: it was
    /// killed and reaped, so no exit status exists.
    CommandStillRunning,
    /// The command RAN and EXITED (its child was reaped and its exit status
    /// WAS collected), but a process that outlived the child still held a
    /// pipe open, so the bounded post-exit output drain gave up and the
    /// collected status could not be reported — the visible `exit_code` is
    /// the `-1` sentinel, not a status.
    ///
    /// The bound the drain gave up at is the runner's POST-EXIT DRAIN bound
    /// (the internal `KILL_REAP_BOUND` / `RunnerConfig::reap_bound`), which is
    /// INDEPENDENT of the caller's deadline: a command that exits early and
    /// leaves a pipe-holding process produces this cause at the drain bound
    /// even though the deadline was never reached. It therefore does NOT claim
    /// that a deadline was outlasted. It is NOT the transport-before-command
    /// layer — the command started and finished.
    OutputDrainGaveUp,
}

#[derive(Clone, Debug)]
pub struct ExecOutcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    /// `Some` when the runner reported its `-1` sentinel rather than a
    /// collected exit status: the typed cause says WHICH case, so a consumer
    /// never has to infer it. The two causes are
    /// [`TimeoutCause::CommandStillRunning`] (the deadline killed a running
    /// command) and [`TimeoutCause::OutputDrainGaveUp`] (the command ran and
    /// exited but its bounded post-exit drain gave up; the status was
    /// collected and then discarded, so it is not reported). `None` for a
    /// normally exited command. A signal-killed child also reports
    /// `exit_code == -1` with `None`, so a consumer must NOT infer "deadline"
    /// — or any other cause — from `-1` alone.
    pub timeout_cause: Option<TimeoutCause>,
}

impl ExecOutcome {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// THE command-execution seam behind [`LocalTransport::exec`]. Production
/// uses [`ChildRunner`] (the bounded real runner: spawn into an own process
/// group, bounded wait, group termination, mandatory reap before every
/// outcome); the deterministic deployment/state-machine properties inject a
/// scripted fake (`ScriptedExec`, test-only: scripted outcomes keyed by argv
/// — no subprocess, no wall-clock). The seam is what makes the property
/// suites parallel-safe: the deterministic tests exercise the SAME logic
/// branches (verification success/failure, activation, compensation) without
/// spawning real processes or contending for the pid space.
pub trait Exec: Send + Sync {
    /// Execute `argv` (no shell) bounded by `timeout`, returning the
    /// outcome. A conforming implementation never leaves a live process
    /// behind. `timeout` bounds the CHILD's lifetime; the mandatory post-exit
    /// drain may add its own bounded tail (see [`ExecOutcome::timeout_cause`]),
    /// so a call may return a little after `timeout` — never unbounded.
    fn exec(&self, argv: &[String], timeout: Duration) -> Result<ExecOutcome>;
}

/// The REAL exec: [`ChildRunner`] through the outcome mapping the transport
/// always applied (a timed-out child surfaces as `exit_code: -1` with the
/// runner's stderr and [`TimeoutCause::CommandStillRunning`]; a kill/reap
/// failure is an error, never a fake success).
impl Exec for ChildRunner {
    fn exec(&self, argv: &[String], timeout: Duration) -> Result<ExecOutcome> {
        match ChildRunner::exec(self, argv, timeout) {
            Ok(RunOutcome::Exited {
                exit_code,
                stdout,
                stderr,
            }) => Ok(ExecOutcome {
                exit_code,
                stdout,
                stderr,
                timeout_cause: None,
            }),
            Ok(RunOutcome::TimedOut { stderr }) => Ok(ExecOutcome {
                exit_code: -1,
                stdout: String::new(),
                stderr,
                // The local runner's `TimedOut` is produced ONLY when the
                // child was still running at the deadline (its post-exit
                // drain reports `Background`, which this mapping surfaces as
                // an ERROR, never a `TimedOut`), so the cause is unambiguous.
                timeout_cause: Some(TimeoutCause::CommandStillRunning),
            }),
            Err(e) => Err(Error::transport(e.to_string())),
        }
    }
}

/// Total and available bytes on the filesystem backing a remote root, as
/// reported by `df`. `total` is the filesystem's full size; `available` is
/// the free space a new upload can consume. Both are in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsBytes {
    pub total: u64,
    pub available: u64,
}

/// Filesystem + execution surface for one server's remote root.
///
/// Every path a transport operation receives is a validated
/// [`RootedRelativePath`]: relative to the deployment root, never absolute,
/// never traversal-bearing — so `root.join(rel)` inside a transport is safe
/// by construction and a caller can never escape the deployment root.
pub trait Remote {
    fn root(&self) -> &Path;
    /// Whether `root()` names a path on THIS host (a [`LocalTransport`]) or
    /// a path on a REMOTE host (an [`SshTransport`]). Callers that must
    /// choose between direct local filesystem access and a remote exec (tree
    /// verification) branch on this DECLARED nature — never on a local
    /// filesystem probe of the root path, which is meaningless for a remote
    /// root and would silently verify a same-named local directory in place
    /// of the remote tree. Every transport MUST declare its nature (no
    /// default): a new remote transport that forgets is a compile error, not
    /// a silent local-verification bug.
    fn is_local(&self) -> bool;
    /// Read the WHOLE entry at `rel` into memory.
    ///
    /// MEMORY BOUND: the entire entry is materialized as one `Vec<u8>` (and the
    /// caller holds it, alongside any copy the sync makes), so a single 350 MB
    /// file costs peak RSS ~362 MB — measured 362,064 KB (macOS) / 362,860 KB
    /// (Linux) — for BOTH snapshot and restore, and a 4 GB entry needs ~4 GB.
    /// There is no streaming read. Keep the largest entry under the process's
    /// memory budget, or move large blobs outside the synced tree and ship them
    /// with a tool that streams; a streaming transport API is a deliberate
    /// future direction, not implemented here.
    fn read(&self, rel: &RootedRelativePath) -> Result<Vec<u8>>;
    /// Write `data` to `rel` with the final `mode`, creating or replacing the
    /// entry.
    ///
    /// ATOMICITY AND DURABILITY, per destination kind (the authoritative
    /// statement is [`crate::manifest`]'s "Durability and atomicity of a
    /// written entry"):
    ///
    /// * [`LocalTransport`] (a LOCAL destination — a PULL, or a PUSH into a
    ///   local path) publishes by the durable atomic replace: a unique temp in
    ///   the destination's own directory, fsync, `renameat` into place, then a
    ///   parent-directory fsync. A failure BEFORE the rename leaves the
    ///   PREVIOUS content untouched and unlinks the temp; a post-rename parent
    ///   fsync failure is reported as durability-UNKNOWN, never as a clean
    ///   success.
    /// * [`SshTransport`] (a REMOTE destination) publishes on the far side with
    ///   the same shape — `mktemp` temp in the destination's own directory,
    ///   the payload on STDIN into it, the final mode, a perl `fsync(2)` of the
    ///   temp, a perl `rename(2)` into place, then a perl `fsync(2)` of the
    ///   parent directory — so a failed upload can no longer truncate or
    ///   destroy the entry it was replacing.
    /// * the Windows local port uses a path-based, NON-atomic replace (no
    ///   directory fsync; the target is removed before the rename). That is
    ///   the ONE destination kind this crate cannot make atomic; the port
    ///   type-checks but is not exercised.
    ///
    /// FIDELITY SCOPE: this primitive carries the manifest model only — the
    /// bytes and the mode. It writes NO ownership, extended attributes
    /// (including `security.capability` and macOS `com.apple.*`), POSIX ACLs,
    /// timestamps, file flags, or sparseness, and the crate's differ cannot see
    /// their absence: a dropped xattr leaves two manifests equal and the sync
    /// reporting no difference. The authoritative list is [`crate::manifest`]'s
    /// "Fidelity scope" section; a caller that needs any of it must apply it
    /// out of band.
    ///
    /// MEMORY AND TIME BOUND, and the LOCAL/REMOTE asymmetry. `data` is the
    /// WHOLE entry, already in memory: a 350 MB file costs peak RSS ~362 MB
    /// (measured 362,064 KB macOS / 362,860 KB Linux), so a 4 GB entry needs
    /// ~4 GB; there is no streaming write. The two kinds are also NOT equally
    /// protected against a slow link: [`SshTransport`] derives a size-aware
    /// deadline from the payload (`upload_deadline` / `transfer_deadline(bytes,
    /// min_rate, command_deadline)`), while [`LocalTransport`] has NEITHER a
    /// deadline NOR streaming. Keep the largest entry under the process's
    /// memory budget, or move large blobs outside the synced tree and ship them
    /// with a tool that streams; a streaming transport API is a deliberate
    /// future direction, not part of the residue change.
    fn write(&self, rel: &RootedRelativePath, data: &[u8], mode: u32) -> Result<()>;
    /// Atomically create `rel` with `data` only if it does not already exist,
    /// and make the install DURABLE before returning: the create-new
    /// primitive (`durable_create_new`) writes a unique temp inside the
    /// destination directory, applies the FINAL MODE, fsyncs the file,
    /// publishes WITHOUT replacement (a concurrent winner is never replaced),
    /// removes the temp, and fsyncs the PARENT DIRECTORY — every failure
    /// propagates. Returns the TYPED [`CreateNewVerdict`]: `Created` when the
    /// record was durably installed by this call; `AlreadyPresent` ONLY when
    /// the destination already existed and VERIFIED as an identical entry —
    /// a DESCRIPTOR-BOUND verification (the entry is OPENED with `O_NOFOLLOW`
    /// and fstat'd + read through the SAME descriptor): a REGULAR FILE with
    /// the EXACT final mode and byte-identical
    /// content, all from the ONE opened inode (the identical retry converges —
    /// the parent directory is
    /// synced here too, so the retry returns with a durable entry);
    /// `Conflict` carrying the TYPED [`VerifiedExisting`] reason when it
    /// existed but did NOT verify (different bytes, a MODE MISMATCH, a
    /// directory/symlink/other entry — a symlink is never followed — or an
    /// unreadable entry; the winner is NEVER replaced or modified, and the
    /// caller receives the typed reason, never an undifferentiated conflict
    /// it can reinterpret); or `Err` on every other failure (a pre-install
    /// failure, a failed parent-dir sync, a transport fault — never a
    /// verdict). This is
    /// the non-racy primitive used for lock acquisition:
    /// `exists`-then-`write` would let two controllers both observe "no lock"
    /// and both proceed.
    fn try_write_new(&self, rel: &RootedRelativePath, data: &[u8]) -> Result<CreateNewVerdict>;
    /// [`Remote::try_write_new`] with a CALLER-CHOSEN content equivalence for
    /// the EEXIST verification: `Semantic` (JSON parse-equal, byte-exact
    /// fallback) is used by the release-file publisher whose idempotent
    /// re-publication legitimately re-serializes the same contract with
    /// different key order/whitespace. Transports whose centralized
    /// verification can apply the equivalence directly (LocalTransport,
    /// SshTransport) override this; the default performs the byte-exact
    /// [`Remote::try_write_new`] and, for `Semantic`, re-reads and
    /// semantically compares a `ContentMismatch` conflict — the identical
    /// outcome a direct application would produce.
    fn try_write_new_with(
        &self,
        rel: &RootedRelativePath,
        data: &[u8],
        equivalence: ContentEquivalence,
    ) -> Result<CreateNewVerdict> {
        let verdict = self.try_write_new(rel, data)?;
        if equivalence != ContentEquivalence::Semantic {
            return Ok(verdict);
        }
        match verdict {
            CreateNewVerdict::Conflict(VerifiedExisting::ContentMismatch) => {
                // The transport's Exact verification reported a content
                // mismatch; the caller's SEMANTIC equivalence may still
                // accept the winner (JSON key order/whitespace are not part
                // of the contract). Type and mode were already verified
                // (that is why the reason is ContentMismatch, not
                // NotRegularFile/ModeMismatch), so only the content needs
                // re-comparing.
                let existing = self.read(rel)?;
                if content_equivalent(&existing, data, ContentEquivalence::Semantic) {
                    Ok(CreateNewVerdict::AlreadyPresent)
                } else {
                    Ok(CreateNewVerdict::Conflict(
                        VerifiedExisting::ContentMismatch,
                    ))
                }
            }
            v => Ok(v),
        }
    }
    fn create_dir(&self, rel: &RootedRelativePath) -> Result<()>;
    fn create_dir_all(&self, rel: &RootedRelativePath) -> Result<()>;
    /// Apply a permission mode to an existing remote entry (file or directory).
    /// Uploads must preserve the canonical tree's modes exactly, or the
    /// post-upload integrity re-hash diverges on hosts with a permissive umask
    /// (a bare `mkdir`/`cat` inherits the remote umask, so modes must be
    /// applied explicitly).
    fn set_mode(&self, rel: &RootedRelativePath, mode: u32) -> Result<()>;
    fn list(&self, rel: &RootedRelativePath) -> Result<Vec<RemoteEntry>>;
    fn rename(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()>;
    /// Rename an entry where EITHER endpoint is the sync's OWN claim-aside (a
    /// residue spelling): the sanctioned engine route used by the claim and
    /// rollback renames. The public [`Remote::rename`] refuses a residue
    /// spelling so a caller cannot replace or move a strand; the production
    /// transports override this so the sync's own `claim_aside`/`rename_back`
    /// keep working. The default delegates to [`Remote::rename`] (a test
    /// wrapper inherits its inner transport's policy).
    fn rename_aside(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
        self.rename(from, to)
    }
    /// Create a symlink at `link` (a rooted relative path) pointing at
    /// `target`. `target` is a LINK TARGET, relative to the link's own
    /// directory — it legitimately traverses up to the object store
    /// (`../../objects/...`), so it is a plain `&Path`, never a
    /// [`RootedRelativePath`].
    fn symlink(&self, target: &Path, link: &RootedRelativePath) -> Result<()>;
    /// Read the target of the symlink at `rel`. The returned target is a
    /// LINK TARGET (relative to the link's directory, legitimately
    /// `../../...`), so it is a plain `PathBuf`, never a
    /// [`RootedRelativePath`].
    fn read_link(&self, rel: &RootedRelativePath) -> Result<PathBuf>;
    fn remove_file(&self, rel: &RootedRelativePath) -> Result<()>;
    fn remove_dir_all(&self, rel: &RootedRelativePath) -> Result<()>;
    /// Remove a FILE (or symlink) that IS the sync's OWN stranded claim-aside —
    /// the explicit-discard route used by `sync::Residue::discard` and the
    /// sync engine's `drop_claim`. The residue guard is SANCTIONED here (the
    /// final component may be a residue), exactly as the local substrate's
    /// `atomic::remove_residue_file_fd` sanctions it. The default delegates to
    /// [`Remote::remove_file`] (a test wrapper inherits its inner transport's
    /// policy); the production transports override it with the sanctioned
    /// primitive so the residue guard does not block the sync's own cleanup.
    fn remove_residue_file(&self, rel: &RootedRelativePath) -> Result<()> {
        self.remove_file(rel)
    }
    /// Remove the (already-emptied) DIRECTORY at `rel` that IS the sync's OWN
    /// stranded claim-aside — the explicit-discard twin of
    /// [`Remote::remove_residue_file`], with `rmdir` semantics.
    fn remove_residue_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        self.remove_dir(rel)
    }
    /// Remove the DIRECTORY at `rel` NON-RECURSIVELY (`rmdir` semantics): the
    /// call fails when the directory is not empty, so a child created after the
    /// caller enumerated the directory is REFUSED LOUDLY, never destroyed
    /// unnamed. This is the leaf primitive of a deepest-first removal walk: the
    /// walk has already removed and authorized every child it enumerated, so an
    /// EMPTY directory is the only thing this may delete, and the walk's claim
    /// "everything under here was sanctioned" is re-established by the
    /// filesystem AT THE MOMENT OF REMOVAL rather than merely at enumeration
    /// time. The DEFAULT runs `rmdir` through the transport's [`Remote::exec`]
    /// seam with `--` so a path beginning with `-` is never parsed as an option
    /// and the remote shell cannot reinterpret the quoted argument; the
    /// production [`LocalTransport`] overrides it with a descriptor-relative
    /// `unlinkat(AT_REMOVEDIR)`.
    fn remove_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        let path = self.root().join(rel.as_path());
        let argv = vec![
            "rmdir".to_string(),
            "--".to_string(),
            path.to_string_lossy().into_owned(),
        ];
        let out = self.exec(&argv, Duration::from_secs(60))?;
        if out.exit_code == 0 {
            Ok(())
        } else {
            Err(Error::transport(format!(
                "rmdir {}: {}",
                rel.display(),
                out.stderr.trim()
            )))
        }
    }
    /// Recursively copy the tree at `src` to `dest` — the per-file dedup's
    /// staging base (the previous tree is copied into the staging dir, then
    /// only the changed files are uploaded). `dest` must not already exist
    /// (the caller removes a stale staging dir first); its parent is
    /// created.
    ///
    /// FIDELITY IS NOT UNIFORM: the two realizations of this ONE operation
    /// carry DIFFERENT metadata, so a caller must not assume they agree. The
    /// DEFAULT below is a list/read/write walk that recreates names, kind,
    /// modes (including the setuid/setgid/sticky bits; two-phase, so a
    /// read-only source tree copies cleanly) and symlink targets, but DROPS
    /// ownership, extended attributes, ACLs, and timestamps — it has no way
    /// to carry them through [`Remote::list`]/[`Remote::read`]/
    /// [`Remote::write`]. A [`LocalTransport`] uses this DEFAULT (a real
    /// local-disk copy: the "download" is a local read), so it drops all
    /// four. The [`SshTransport`] override runs a same-filesystem `cp -a` on
    /// the remote (no bytes cross the link) and ADDITIONALLY preserves
    /// extended attributes, ACLs, and timestamps; ownership is kept as the
    /// copier's for a non-root far-side user (see the override). The full
    /// carried/not-carried list is the crate's fidelity scope in
    /// [`crate::manifest`].
    ///
    /// MEMORY BOUND: the DEFAULT walk carries each file through
    /// [`Remote::read`] and [`Remote::write`], so every file is materialized
    /// WHOLE — the same O(largest entry) peak RSS those primitives document
    /// (a 350 MB file ≈ 362 MB peak), NOT a streaming copy. See
    /// [`Remote::read`] for the measured figures and the workaround.
    fn copy_tree(&self, src: &RootedRelativePath, dest: &RootedRelativePath) -> Result<()> {
        if let Some(parent) = dest.parent() {
            self.create_dir_all(&parent)?;
        }
        // (dest, final_mode, depth) collected during the walk for phase 2.
        let mut dirs: Vec<(RootedRelativePath, u32, usize)> = Vec::new();
        copy_tree_walk(self, src, dest, &mut dirs)?;
        dirs.sort_by_key(|d| std::cmp::Reverse(d.2));
        for (d, mode, _depth) in dirs {
            self.set_mode(&d, mode)?;
        }
        Ok(())
    }
    /// Recursively fsync every file and directory under `rel` (the staged
    /// release bundle), making the WHOLE tree durable before the atomic
    /// install rename — a crash after the fsync but before the rename loses
    /// at most the disposable staging dir, never a partial final release
    /// directory. The DEFAULT is a no-op (test wrappers that delegate to an
    /// inner transport inherit the inner's implementation); the production
    /// transports ([`LocalTransport`], [`SshTransport`]) realize it for
    /// real.
    ///
    /// MAKING A FRESHLY PUSHED SUBTREE DURABLE takes TWO calls on the PARENT
    /// transport: `fsync_tree(<child>)` makes everything UNDER the child
    /// durable (including the child directory itself), and
    /// `fsync_parent(<child>)` makes the PARENT directory entry that names the
    /// child durable. A per-subtree transport cannot perform the second call
    /// on its own root, because a [`RootedRelativePath`] must be non-empty (it
    /// refuses the empty path), so the transport rooted AT the child cannot
    /// name the child to fsync the grandparent. The recipe is therefore:
    /// `parent.fsync_tree(child)` then `parent.fsync_parent(child)`, both on
    /// the transport rooted at the child's PARENT.
    fn fsync_tree(&self, rel: &RootedRelativePath) -> Result<()> {
        let _ = rel;
        Ok(())
    }
    /// Fsync the PARENT DIRECTORY of `rel` so a rename/removal/creation
    /// inside it survives power loss — the durability commit point of every
    /// atomic mutation (the staged-publish renames, the `current` symlink
    /// swap, the record replaces): a mutation's success is reported ONLY
    /// after this succeeds. FAIL-CLOSED: a failed open OR a failed fsync is
    /// a propagated `Err` (never a silent success — the directory entry's
    /// durability is unconfirmed). The DEFAULT is a no-op (test wrappers
    /// that delegate to an inner transport inherit the inner's
    /// implementation); the production transports ([`LocalTransport`],
    /// [`SshTransport`]) realize it for real.
    ///
    /// See [`Remote::fsync_tree`] for the TWO-call recipe that makes a freshly
    /// pushed subtree durable: `fsync_tree(child)` plus this method with
    /// `child`, both on the PARENT transport.
    fn fsync_parent(&self, rel: &RootedRelativePath) -> Result<()> {
        let _ = rel;
        Ok(())
    }
    /// Atomically remove `rel` ONLY IF its content is byte-identical to
    /// `expected` — the compare-and-delete primitive that makes stale
    /// releases and expired-lease breaks safe. Returns the TYPED verdict
    /// ([`RemoveIfVerdict`]); every transport failure propagates as `Err`
    /// (never a fabricated verdict, never a silent no-op). The production
    /// transports ([`LocalTransport`], [`SshTransport`]) realize it
    /// ATOMICALLY: the entry is CLAIMED by an atomic rename to a unique
    /// same-directory temp (only one contender can win), verified against
    /// `expected`, and either deleted (match) or RESTORED no-replace
    /// (mismatch — a successor's lock is never removed, never replaced).
    /// The DEFAULT implementation is the NON-ATOMIC read-compare-remove
    /// fallback: adequate for single-process test wrappers that never race
    /// the lock, and only those; production must override it.
    fn remove_file_if(&self, rel: &RootedRelativePath, expected: &[u8]) -> Result<RemoveIfVerdict> {
        // Typed absence probe first: a transport failure is an `Err`, never
        // a silent `Absent`.
        let Some(_) = self.metadata_opt(rel)? else {
            return Ok(RemoveIfVerdict::Absent);
        };
        let cur = self.read(rel)?;
        if cur == expected {
            self.remove_file(rel)?;
            Ok(RemoveIfVerdict::Removed)
        } else {
            Ok(RemoveIfVerdict::Mismatch)
        }
    }
    fn exists(&self, rel: &RootedRelativePath) -> bool;
    fn metadata(&self, rel: &RootedRelativePath) -> Result<RemoteMeta>;
    /// The TYPED replacement for the `exists`/`metadata` pair: `Ok(Some(meta))`
    /// when the entry exists, `Ok(None)` ONLY for a CONFIRMED `NotFound`, and
    /// `Err` for every other failure (permission, transport fault, ...). A
    /// failed read is NEVER indistinguishable from absence — callers must
    /// never consult `exists` (a `bool` that swallows errors) to disambiguate.
    fn metadata_opt(&self, rel: &RootedRelativePath) -> Result<Option<RemoteMeta>> {
        match self.metadata(rel) {
            Ok(m) => Ok(Some(m)),
            Err(crate::error::Error::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
    /// Execute a command vector (no shell). Returns the outcome.
    fn exec(&self, argv: &[String], timeout: Duration) -> Result<ExecOutcome>;
    /// Total and available bytes on the filesystem backing the remote root.
    /// `total` is the filesystem's full size; `available` is the free space a
    /// new upload can consume. Capacity preflight needs both: the percent
    /// reserve is a percentage of the TOTAL size, while the fit check
    /// compares against the AVAILABLE space.
    fn filesystem_bytes(&self) -> Result<FsBytes>;

    /// Atomic recover of the operation lock: remove `rel` iff it equals
    /// `observed`, then install `new_data`, all while holding the sidecar
    /// mutex exclusively. Returns `Ok(Some(()))` on success, `Ok(None)` if
    /// not implemented (caller falls back to helper-layer flock), `Err` on
    /// mismatch/absent/contended/transport failure. Object-safe so
    /// `RemoteHelper` can call it via `&dyn Remote` without knowing the
    /// transport.
    fn atomic_recover(
        &self,
        rel: &RootedRelativePath,
        observed: &[u8],
        new_data: &[u8],
    ) -> Result<Option<()>> {
        let _ = (rel, observed, new_data);
        Ok(None)
    }

    /// Prepare the host identity (verify/pin the host key) before ANY remote
    /// request, including read-only status inspection in a dry run. A dry run
    /// still connects over the transport to inspect status, so the identity
    /// must be prepared first. Construction is side-effect-free; identity
    /// preparation happens before the first request that needs to connect.
    /// Default: no-op (transports without a host-identity concept, like
    /// `LocalTransport`).
    fn prepare_identity(&self) -> Result<()> {
        let _ = self;
        Ok(())
    }

    /// Create the deployment-directory layout before the first mutation.
    /// Construction is side-effect-free; layout provisioning happens only after
    /// the push engine's non-dry-run gate. The DEFAULT is a no-op (the trait
    /// method has no access to a [`Layout`]); the transports that override it
    /// ([`LocalTransport`], [`SshTransport`]) create the destination ROOT
    /// ITSELF, the caller's bootstrap directories, AND, when
    /// [`Layout::receiver_marker`] is `Some`, the immutable receiver-id marker
    /// (created ONCE at provisioning and never changed). Creating the ROOT is
    /// what makes a FRESH destination usable: the push entry points call this
    /// before reading the destination manifest, and `LocalTransport` already
    /// created its base while `SshTransport` used to omit the root (so the same
    /// consumer call worked locally and failed only on the remote path).
    fn provision_layout(&self) -> Result<()> {
        Ok(())
    }
}

fn join(root: &Path, rel: &RootedRelativePath) -> PathBuf {
    root.join(rel.as_path())
}

/// The iterative half of [`Remote::copy_tree`]'s default: walk `src` with
/// [`Remote::list`], recreating every entry at `dest` (directories
/// owner-writable during the walk, files/symlinks with their final modes),
/// collecting `(dest, final_mode, depth)` for the caller's phase-2 finalize.
///
/// The walk keeps an explicit heap `Vec` of frames instead of recursing one
/// Rust frame per directory level: a deep tree used to exhaust the C stack,
/// and Rust's stack-overflow handler ABORTS the host process — a library
/// must surface a clean `Err` instead. Each frame holds the directory's
/// `(src, dest, depth)` and the entries [`Remote::list`] returned, so the
/// visit order is exactly the recursion's depth-first order.
fn copy_tree_walk<R: Remote + ?Sized>(
    remote: &R,
    src: &RootedRelativePath,
    dest: &RootedRelativePath,
    dirs: &mut Vec<(RootedRelativePath, u32, usize)>,
) -> Result<()> {
    struct Frame {
        src: RootedRelativePath,
        dest: RootedRelativePath,
        depth: usize,
        entries: std::vec::IntoIter<RemoteEntry>,
    }

    remote.create_dir_all(dest)?;
    let mut stack: Vec<Frame> = vec![Frame {
        src: src.clone(),
        dest: dest.clone(),
        depth: 0,
        entries: remote.list(src)?.into_iter(),
    }];
    while let Some(top) = stack.last_mut() {
        let next = top.entries.next();
        let Some(e) = next else {
            stack.pop();
            continue;
        };
        let descend: Option<Frame> = {
            let top = stack.last().expect("the frame just examined");
            let s = top.src.join(&e.name)?;
            let d = top.dest.join(&e.name)?;
            if e.is_dir {
                remote.create_dir_all(&d)?;
                remote.set_mode(&d, (e.mode | 0o200) & 0o7777)?;
                dirs.push((d.clone(), e.mode & 0o7777, top.depth));
                // The recursion created the child directory a second time
                // when it entered it; keep that prologue and the listing in
                // the same order.
                remote.create_dir_all(&d)?;
                let entries = remote.list(&s)?;
                Some(Frame {
                    src: s,
                    dest: d,
                    depth: top.depth + 1,
                    entries: entries.into_iter(),
                })
            } else if e.is_symlink {
                let target = remote.read_link(&s)?;
                remote.symlink(&target, &d)?;
                None
            } else {
                let data = remote.read(&s)?;
                remote.write(&d, &data, e.mode & 0o7777)?;
                None
            }
        };
        if let Some(frame) = descend {
            stack.push(frame);
        }
    }
    Ok(())
}

/// Read the immutable receiver-id marker at `marker` and parse it. Fails
/// closed on a MISSING marker (the deploy_dir was never provisioned) and on
/// a MALFORMED marker (a tampered/foreign marker is never accepted as a
/// physical identity).
pub(crate) fn read_receiver_id<R: Remote + ?Sized>(
    remote: &R,
    marker: &RootedRelativePath,
) -> Result<ReceiverId> {
    read_receiver_id_opt(remote, marker)?.ok_or_else(|| {
        Error::transport(format!(
            "deploy_dir {}: no receiver-id marker ({marker} was never provisioned)",
            remote.root().display()
        ))
    })
}

/// Read the receiver-id marker, returning `Ok(None)` ONLY for a CONFIRMED
/// absent marker (a not-yet-provisioned deploy_dir — the marker is created by
/// [`provision_receiver_id`] during provisioning). A read failure or a
/// malformed marker is an `Err` (fail closed — a marker that exists but
/// cannot be parsed is never silently treated as absent).
pub(crate) fn read_receiver_id_opt<R: Remote + ?Sized>(
    remote: &R,
    marker: &RootedRelativePath,
) -> Result<Option<ReceiverId>> {
    if remote.metadata_opt(marker)?.is_none() {
        return Ok(None);
    }
    let data = remote.read(marker)?;
    let s = std::str::from_utf8(&data).map_err(|e| {
        Error::transport(format!(
            "deploy_dir {}: the receiver-id marker is not valid UTF-8: {e}",
            remote.root().display()
        ))
    })?;
    // FAIL CLOSED, ACTIONABLY. The refusal keeps its `transport` class (a
    // marker that is present but not this crate's format is a
    // marker-protocol violation, and a caller must be able to tell it from a
    // filesystem fault), but the message names the CONDITION (not a
    // 40-hex-character receiver id), the likely CAUSE (a marker written by a
    // tool that predates this crate's format — the source tool writes
    // `recv-<uuid-v7>` — or a tampered/foreign file), and the fact that no
    // adoption exists, so an operator does not have to read this source to
    // diagnose it.
    ReceiverId::parse(s.trim())
        .map_err(|e| {
            Error::transport(format!(
                "deploy_dir {}: refusing the receiver-id marker at {marker}: its content is not a \
                 {RECEIVER_ID_LEN}-character lowercase-hex receiver id ({e}). This is a FAIL-CLOSED \
                 refusal — a marker this crate did not write, such as a legacy `recv-<uuid-v7>` \
                 marker from a tool that predates this crate's format (or a tampered/foreign \
                 file), is never adopted as a physical identity, because silently adopting a \
                 foreign format would misidentify the deploy_dir. Point the store at a deploy_dir \
                 this crate provisioned, or re-provision a fresh one.",
                remote.root().display()
            ))
        })
        .map(Some)
}

/// Provision the immutable receiver-id marker at `marker`: create it ONCE
/// (a fresh [`ReceiverId`], stored as `<id>\n`) and return the deploy_dir's
/// physical identity. The marker is never replaced: a re-provisioning or a
/// concurrent provisioner adopts the EXISTING marker (the first writer wins —
/// the deploy_dir's physical identity is whatever was created first), and a
/// marker with different content is adopted too (fail closed on a malformed
/// marker, never on a differing-but-valid one: the physical identity is
/// immutable, so the existing marker is the truth).
pub(crate) fn provision_receiver_id<R: Remote + ?Sized>(
    remote: &R,
    marker: &RootedRelativePath,
) -> Result<ReceiverId> {
    // Fast path: the deploy_dir already carries its immutable identity.
    if remote.metadata_opt(marker)?.is_some() {
        return read_receiver_id(remote, marker);
    }
    let id = ReceiverId::generate()?;
    match remote.try_write_new(marker, &id.wire_bytes())? {
        CreateNewVerdict::Created => Ok(id),
        // A concurrent provisioner won the create-new race (or the marker
        // exists with different content): the deploy_dir's identity is
        // whatever was created FIRST — adopt it, never replace it.
        CreateNewVerdict::AlreadyPresent | CreateNewVerdict::Conflict(_) => {
            read_receiver_id(remote, marker)
        }
    }
}

/// True when `p` has at least one NORMAL path component below the root —
/// i.e. `p` is not the filesystem root (nor a root-with-only-dots form that
/// normalizes to it, like `//` or `/./`). A transport must never operate on
/// `/`: deployment cleanup (rotation/retention deleting stale generations,
/// the GC sweep) would otherwise run against system-level directories.
pub(crate) fn has_normal_component_below_root(p: &Path) -> bool {
    p.components()
        .any(|c| matches!(c, std::path::Component::Normal(_)))
}

fn meta_to_remote(m: &std::fs::Metadata) -> RemoteMeta {
    RemoteMeta {
        is_dir: m.is_dir(),
        is_symlink: m.file_type().is_symlink(),
        is_file: m.is_file(),
        size: m.len(),
        mode: crate::platform::metadata_mode(m),
    }
}

/// The canonical FINAL MODE for immutable records installed through
/// [`Remote::try_write_new`]: the same `0o644` every sibling JSON record is
/// written with (the inventory, transactions, and the force-path lock rewrite
/// all use `Remote::write(..., 0o644)`). The published inode must carry THIS
/// mode — never the process umask the temp was created with — or the record's
/// permissions would silently depend on the caller's umask.
pub(crate) const IMMUTABLE_RECORD_MODE: u32 = 0o644;

/// How long a contender waits for the sidecar mutex before failing: a
/// MONOTONIC deadline (not an attempt count). Ordinary critical sections
/// (file syncs inside the flock) finish well within it; a holder that is
/// still alive after the deadline is a genuinely stuck/unbounded operation.
pub(crate) const SIDECAR_WAIT_TIMEOUT: Duration = Duration::from_secs(2);
/// The sleep between non-blocking flock retries (bounded by the remaining
/// time to the deadline, so no retry ever extends past it).
pub(crate) const SIDECAR_RETRY_INTERVAL: Duration = Duration::from_millis(5);

// Thread-local re-entrancy depth for the sidecar critical section. When
// `>0`, the current thread already holds the sidecar flock, so nested
// transport calls for the lock path skip re-acquiring it. Depth is
// incremented on entry and decremented on exit, even on error.
thread_local! {
    static SIDECAR_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Ensure the sidecar mutex file exists durably: create the parent
/// directory, create the file with `create_new` (so a concurrent creator
/// is not truncated), `fsync` the file and `fsync` the parent directory.
/// The file is created once and never removed/renamed, so every
/// participant flocks the same inode. Mode 0o644, durable.
pub(crate) fn ensure_operation_lock_sidecar_durable(
    base: &Path,
    sidecar: &RootedRelativePath,
) -> Result<()> {
    let p = join(base, sidecar);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::transport(format!("mkdir {}: {e}", parent.display())))?;
    }
    // Fast path: already exists.
    if p.exists() {
        return Ok(());
    }
    // Create with create_new to avoid truncating a concurrent winner.
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&p)
    {
        Ok(f) => {
            let _ = crate::platform::chmod(&p, 0o644);
            f.sync_all()
                .map_err(|e| Error::transport(format!("fsync {}: {e}", p.display())))?;
            drop(f);
            if let Some(parent) = p.parent() {
                let dir = std::fs::File::open(parent)
                    .map_err(|e| Error::transport(format!("open dir {}: {e}", parent.display())))?;
                dir.sync_all().map_err(|e| {
                    Error::transport(format!("fsync dir {}: {e}", parent.display()))
                })?;
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(Error::transport(format!("create {}: {e}", p.display()))),
    }
}

/// Run `f` while holding an exclusive `flock` on the sidecar mutex file.
/// The sidecar is ensured durably before locking. Uses non-blocking
/// `LOCK_EX|LOCK_NB` with a monotonic deadline (`SIDECAR_WAIT_TIMEOUT`)
/// and a 5ms sleep between attempts (bounded by the remaining time to the
/// deadline); a contended sidecar after the deadline fails with an explicit
/// transport error, never hangs. Re-entrant: if the current thread already
/// holds the sidecar (depth>0), `f` runs directly.
pub(crate) fn with_operation_lock_sidecar<R>(
    base: &Path,
    sidecar: &RootedRelativePath,
    f: impl FnOnce() -> Result<R>,
) -> Result<R> {
    let depth = SIDECAR_DEPTH.with(|c| c.get());
    if depth > 0 {
        return f();
    }
    ensure_operation_lock_sidecar_durable(base, sidecar)?;
    let p = join(base, sidecar);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .open(&p)
        .map_err(|e| Error::transport(format!("open sidecar {}: {e}", p.display())))?;
    // The platform lock (flock on Unix, LockFileEx on Windows — the split
    // lives in [`crate::lock`]): the closure returns the
    // 0/-1 convention `wait_for_sidecar_flock` expects.
    let try_lock = || match crate::lock::try_lock(&file) {
        crate::lock::LockAttempt::Acquired => 0,
        _ => -1,
    };
    wait_for_sidecar_flock(
        &p,
        SIDECAR_WAIT_TIMEOUT,
        SIDECAR_RETRY_INTERVAL,
        try_lock,
        || std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        Instant::now,
        std::thread::sleep,
    )?;
    SIDECAR_DEPTH.with(|c| c.set(depth + 1));
    let res = f();
    SIDECAR_DEPTH.with(|c| c.set(depth));
    crate::lock::unlock(&file);
    res
}

/// The flock-contention wait, with the OS interactions injected so the
/// timeout/retry policy can be property-tested deterministically. `try_flock`
/// returns the flock(2) result convention (0 = acquired, -1 = error with
/// errno consultable via `last_errno`), `now` the monotonic clock, `sleep`
/// the wait primitive. The policy: keep acquiring until the deadline —
/// `EWOULDBLOCK` sleeps `interval.min(deadline - now)`, `EINTR` retries
/// immediately, any other errno fails immediately; a holder that is still
/// contended when the deadline passes fails with the timeout error.
pub(crate) fn wait_for_sidecar_flock(
    path: &std::path::Path,
    timeout: Duration,
    interval: Duration,
    mut try_flock: impl FnMut() -> i32,
    mut last_errno: impl FnMut() -> i32,
    mut now: impl FnMut() -> Instant,
    mut sleep: impl FnMut(Duration),
) -> Result<()> {
    let deadline = now() + timeout;
    loop {
        if try_flock() == 0 {
            break;
        }
        let errno = last_errno();
        match errno {
            x if x == crate::lock::contended_errno() => {
                let cur = now();
                if cur >= deadline {
                    return Err(Error::transport(format!(
                        "sidecar mutex remained contended for {:?}: {}",
                        timeout,
                        path.display()
                    )));
                }
                sleep(interval.min(deadline - cur));
            }
            // EINTR (Unix only — Windows has no equivalent): retry
            // immediately.
            #[cfg(unix)]
            x if x == libc::EINTR => continue,
            _ => {
                return Err(Error::transport(format!(
                    "flock sidecar {}: {}",
                    path.display(),
                    std::io::Error::from_raw_os_error(errno)
                )));
            }
        }
    }
    Ok(())
}

/// The verdict of one atomic compare-and-delete attempt
/// ([`Remote::remove_file_if`]): the entry was removed because it carried
/// EXACTLY the expected bytes ([`RemoveIfVerdict::Removed`]), the entry
/// existed but did NOT match ([`RemoveIfVerdict::Mismatch`] — it is never
/// removed, and a no-replace restore put it back), or the entry was
/// GENUINELY absent ([`RemoveIfVerdict::Absent`]). `pub` because it crosses
/// the [`Remote`] trait boundary: every transport's `remove_file_if` returns
/// it, and every caller (and external test crate) branches on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoveIfVerdict {
    /// The entry existed with content byte-identical to `expected` and was
    /// removed: the slot is now free.
    Removed,
    /// The entry existed but its content differed from `expected`: it was
    /// restored (or left as the winner's), NEVER removed. A stale release or
    /// a stale break lands here — the successor's lock survives.
    Mismatch,
    /// The entry was genuinely absent: nothing to remove (an idempotent
    /// success for a release, a free slot for an acquire).
    Absent,
}

/// The verdict of one canonical create-new attempt (`durable_create_new`).
/// `pub` because it crosses the [`Remote`] trait boundary: every transport's
/// `try_write_new` returns it, and every caller (and external test crate)
/// branches on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreateNewVerdict {
    /// The record was durably installed: exact bytes, the final mode, and a
    /// parent-directory-fsync'd directory entry all hold.
    Created,
    /// The destination already existed and VERIFIED as an identical entry:
    /// the `lstat` succeeded, the entry is a REGULAR FILE, its mode matched
    /// EXACTLY, and its content matched per the caller's requested
    /// equivalence — the identical retry converges, no error, no replace.
    AlreadyPresent,
    /// The destination already existed but did NOT verify as an identical
    /// entry: the TYPED [`VerifiedExisting`] reason says why (not a regular
    /// file — directory/symlink/other, never followed; a MODE MISMATCH; a
    /// CONTENT MISMATCH per the caller's equivalence; unreadable; or
    /// vanished). The winner is NEVER replaced or modified, and the caller
    /// receives the typed reason — it can never reinterpret an
    /// undifferentiated conflict as "already present, fine".
    Conflict(VerifiedExisting),
}

/// The seven stages of the canonical create-new sequence — the crash/failure
/// model's injection points. Test-only in practice (the proptest arms exactly
/// one stage), but plain `pub(crate)` so the primitive can consult it in both
/// build profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CreateNewStep {
    CreateTemp,
    Write,
    Chmod,
    FileFsync,
    Publish,
    Unlink,
    ParentFsync,
}

/// One-shot stage failure injection for [`durable_create_new`]: armed for
/// EXACTLY ONE step, fires ONCE (then disarms), per-fixture (never a
/// process-global slot — two fixtures' faults can never consume each other).
/// Production code never arms one (the `None` options path); the durability
/// proptest arms exactly one stage to model a crash at that point.
#[derive(Debug)]
pub(crate) struct CreateNewFault {
    step: CreateNewStep,
    armed: std::sync::atomic::AtomicBool,
}

impl CreateNewFault {
    /// Arm a one-shot fault for `step`. Test-only (production never arms a
    /// fault); the type itself stays plain `pub(crate)` because the
    /// primitive's options carry it in both build profiles.
    #[cfg(test)]
    pub(crate) fn new(step: CreateNewStep) -> Self {
        Self {
            step,
            armed: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Consume the fault: fire exactly once when `step` matches the armed
    /// stage (and never again).
    pub(crate) fn consume(&self, step: CreateNewStep) -> bool {
        use std::sync::atomic::Ordering;
        self.step == step && self.armed.swap(false, Ordering::SeqCst)
    }
}

/// The caller-chosen content-equivalence relation applied to an EXISTING
/// entry during create-new verification: the create-new EEXIST path verifies
/// the existing entry and the CALLER decides whether byte-exact equality is
/// required or whether a semantic (JSON parse-equal) relation is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentEquivalence {
    /// Byte-exact: the existing entry's bytes must equal the intended bytes.
    /// Every immutable record's identical retry (markers, locks, the protocol
    /// marker, assignment records) converges under this relation.
    Exact,
    /// Semantic: JSON parse-equal (object key order and whitespace are not
    /// part of the contract), falling back to byte-exact when either side is
    /// not JSON. Used by the release-file publisher whose idempotent
    /// re-publication legitimately re-serializes the same contract with
    /// different key order/whitespace.
    Semantic,
}

/// WHY an existing create-new destination is not a clean identical retry —
/// the typed companion of [`CreateNewVerdict::Conflict`]. Every reason is a
/// distinct variant: a caller can never reinterpret an undifferentiated
/// conflict (a directory, a symlink, a mode mismatch, or unreadable entry
/// can never be silently accepted as "already present, fine").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotRegularFileKind {
    /// A directory occupies the destination path.
    Directory,
    /// A symlink occupies the destination path — reported from the
    /// `O_NOFOLLOW` open's ELOOP (never followed — a symlink pointing at a
    /// matching regular file is still a conflict, never an accepted retry).
    Symlink,
    /// Any other non-regular kind: a fifo, socket, device, ...
    Other,
}

/// The TYPED result of verifying an EXISTING create-new destination against
/// the intended content — the single DESCRIPTOR-BOUND verification shared by
/// BOTH transports (the local `durable_create_new` verify-on-retry and the
/// SSH transport's EEXIST verification): the entry is opened with `O_NOFOLLOW`
/// and the type/mode AND the content all come from the ONE opened inode
/// (fstat + read through the SAME descriptor — never an lstat followed by a
/// separate, symlink-following path re-open). `Ok` is reached ONLY when the
/// open succeeded AND the OPENED inode is a REGULAR FILE AND its content was
/// read through the same descriptor; every other outcome is one of the
/// explicit reasons below. The verdict [`CreateNewVerdict::AlreadyPresent`]
/// is produced ONLY when this is [`VerifiedExisting::Ok`] with `mode_ok` true
/// (the mode matched EXACTLY) and the content matched per the caller's
/// requested equivalence; EVERY other variant is
/// [`CreateNewVerdict::Conflict`] carrying this reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedExisting {
    /// The descriptor-bound open succeeded, the OPENED inode is a REGULAR
    /// FILE, and its content was read THROUGH THE SAME opened descriptor.
    /// `mode_ok` records whether the entry's mode matched the
    /// required mode EXACTLY (a mismatch is reported as
    /// [`VerifiedExisting::ModeMismatch`]; `mode_ok` stays a first-class
    /// dimension so the verdict constructor must consult it — an entry is
    /// only ever [`CreateNewVerdict::AlreadyPresent`] when it is true) and
    /// `content` records the caller's requested content equivalence, which
    /// HELD (a failed comparison is [`VerifiedExisting::ContentMismatch`]).
    Ok {
        mode_ok: bool,
        content: ContentEquivalence,
    },
    /// The `O_NOFOLLOW` open reported the destination absent (ENOENT/ENOTDIR).
    /// Should not happen on the
    /// EEXIST-confirmed path (the no-clobber publish observed the
    /// destination), but typed rather than assumed.
    NotFound,
    /// The opened (fstat'd) inode is NOT a regular file: a
    /// directory, a symlink (never followed), or another kind.
    NotRegularFile { kind: NotRegularFileKind },
    /// The entry is a regular file whose mode does NOT match the required
    /// mode EXACTLY — the mode is part of the immutable record, so a mode
    /// mismatch is a real conflict, never an accepted retry.
    ModeMismatch { actual: u32, required: u32 },
    /// The entry is a regular file with the EXACT required mode, but its
    /// content did NOT match per the caller's requested equivalence.
    ContentMismatch,
    /// The entry exists (and is a regular file) but its content could not be
    /// read during verification (permission, I/O fault): a real failure, never
    /// a fabricated verdict. The payload carries the errno-bearing error text.
    Unreadable(String),
}

/// Settings for one [`durable_create_new`] attempt: the FINAL MODE the
/// published inode must carry, the caller-chosen CONTENT EQUIVALENCE the
/// EEXIST verification applies to the existing entry, and (test-only) the
/// one-shot stage fault.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CreateNewOptions<'a> {
    pub(crate) mode: u32,
    pub(crate) content: ContentEquivalence,
    pub(crate) fault: Option<&'a CreateNewFault>,
}

/// THE ONE CANONICAL CREATE-NEW PRIMITIVE — the durable install protocol for
/// immutable records (commit markers, locks, the protocol marker, assignment
/// and release records). Realized by [`LocalTransport::try_write_new`] on
/// this host and by the `SshTransport` remote script (`write_new_cmd`) with
/// the IDENTICAL seven-step sequence:
///
/// 1. **create temp** — a unique, dot-prefixed temp name INSIDE the
///    destination directory (so the no-replace publish is atomic within the
///    same directory), created with create-new semantics;
/// 2. **write** — all bytes;
/// 3. **final chmod** — the caller's FINAL MODE is applied to the temp
///    BEFORE the fsync, so the published inode carries the exact mode, never
///    the process umask;
/// 4. **file fsync** — the temp file is durable;
/// 5. **no-replace publish** — `link(2)` under the final name: `EEXIST` is
///    the conflict verdict (the winner is NEVER replaced), every other
///    failure propagates;
/// 6. **unlink temp** — the temp name is removed (best-effort cleanup — the
///    ERROR path propagates the REAL failure);
/// 7. **parent-directory fsync** — the PARENT DIRECTORY is fsync'd (the step
///    the old code claimed but never performed) so the directory entry is
///    durable; a FAILED parent fsync is a propagated error.
///
/// Every state failure in every step PROPAGATES as an error — `Ok(Created)`
/// therefore implies exact bytes (the fully-written inode), the final mode,
/// and a DURABLE directory entry. On a conflict (step 5's `EEXIST`) the
/// existing entry is VERIFIED through the ONE centralized DESCRIPTOR-BOUND
/// verification ([`verify_existing`] — the local [`open_verify_local`]
/// opens with `O_NOFOLLOW` and fstats + reads through the SAME opened
/// descriptor, so the metadata and the content provably come from the same
/// opened inode): only a regular file whose mode matched
/// EXACTLY and whose content matched per the caller's requested equivalence
/// → [`CreateNewVerdict::AlreadyPresent`] (the identical retry converges —
/// no error, no replace); EVERY other outcome →
/// [`CreateNewVerdict::Conflict`] carrying the TYPED [`VerifiedExisting`]
/// reason (never an undifferentiated conflict — a directory, a symlink that
/// is never followed, a mode mismatch, or an unreadable entry is a real
/// conflict). `Ok(AlreadyPresent)` runs the parent fsync too, so the
/// convergent path still returns with a durable entry.
pub(crate) fn durable_create_new(
    base: &Path,
    guarded: crate::atomic::GuardedRel<'_>,
    data: &[u8],
    options: CreateNewOptions<'_>,
) -> Result<CreateNewVerdict> {
    use std::io::Write;

    let p = base.join(guarded.as_path());
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::transport(format!("mkdir {}: {e}", parent.display())))?;
    }
    // 1. create temp: the crate's ONE bounded local temp name inside the
    //    destination directory (see [`crate::atomic::temp_name_for`]), with
    //    create-new semantics (never truncates a stale temp a crashed
    //    controller left behind). The embedded destination name is bounded to
    //    `NAME_MAX`, so a legal 255-byte destination still has a usable temp.
    let tmp = crate::atomic::temp_name_for(&p);
    let fail = |step: CreateNewStep| options.fault.is_some_and(|f| f.consume(step));
    if fail(CreateNewStep::CreateTemp) {
        return Err(Error::transport(format!(
            "test fault: create-new step {step:?} forced to fail (once)",
            step = CreateNewStep::CreateTemp
        )));
    }
    let mut f = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
    {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::transport(format!("create {}: {e}", tmp.display())));
        }
    };
    // 2. write — all bytes.
    if fail(CreateNewStep::Write) {
        return Err(Error::transport(format!(
            "test fault: create-new step {step:?} forced to fail (once)",
            step = CreateNewStep::Write
        )));
    }
    f.write_all(data)
        .map_err(|e| Error::transport(format!("write {}: {e}", tmp.display())))?;
    // 3. final chmod — the FINAL MODE is applied to the temp BEFORE the
    //    fsync, so the published inode carries the caller's mode, never the
    //    process umask.
    if fail(CreateNewStep::Chmod) {
        return Err(Error::transport(format!(
            "test fault: create-new step {step:?} forced to fail (once)",
            step = CreateNewStep::Chmod
        )));
    }
    crate::platform::chmod(&tmp, options.mode & 0o7777)
        .map_err(|e| Error::transport(format!("chmod {}: {e}", tmp.display())))?;
    // 4. file fsync — the temp file is durable.
    if fail(CreateNewStep::FileFsync) {
        return Err(Error::transport(format!(
            "test fault: create-new step {step:?} forced to fail (once)",
            step = CreateNewStep::FileFsync
        )));
    }
    f.sync_all()
        .map_err(|e| Error::transport(format!("fsync {}: {e}", tmp.display())))?;
    drop(f);
    // 5. no-replace publish — link(2) fails with EEXIST when a concurrent
    //    writer won; the winner is NEVER replaced. On EEXIST the existing
    //    entry is VERIFIED (verify-on-retry) through THE ONE CENTRALIZED
    //    lstat-based verification ([`verify_existing`] — a regular file with
    //    the EXACT required mode and the caller's accepted content
    //    equivalence → AlreadyPresent, the identical retry converges; every
    //    other outcome → Conflict carrying the TYPED reason).
    if fail(CreateNewStep::Publish) {
        return Err(Error::transport(format!(
            "test fault: create-new step {step:?} forced to fail (once)",
            step = CreateNewStep::Publish
        )));
    }
    let verdict = match std::fs::hard_link(&tmp, &p) {
        Ok(()) => CreateNewVerdict::Created,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // The DESCRIPTOR-BOUND verification (the LOCAL side opens with
            // `O_NOFOLLOW` — a symlink at the destination makes the open
            // fail with ELOOP → NotRegularFile{Symlink}, so a symlink is
            // NEVER followed, even when it points at a matching regular
            // file — then fstats and reads through the SAME opened
            // descriptor, so the metadata and the content provably come
            // from the same opened inode) and the shared verdict
            // construction.
            let p2 = p.clone();
            let verified = verify_existing(
                || {
                    open_verify_local(
                        &p2,
                        #[cfg(test)]
                        None,
                    )
                },
                data,
                options.mode,
                options.content,
            );
            match verified {
                Ok(v) => verified_to_verdict(v),
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e);
                }
            }
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::transport(format!("install {}: {e}", p.display())));
        }
    };
    // 6. unlink temp — remove ONLY the temp this invocation created
    //    (best-effort cleanup; the REAL failure above already propagated).
    if fail(CreateNewStep::Unlink) {
        return Err(Error::transport(format!(
            "test fault: create-new step {step:?} forced to fail (once)",
            step = CreateNewStep::Unlink
        )));
    }
    let _ = std::fs::remove_file(&tmp);
    // 7. parent-directory fsync — the step the old code CLAIMED but never
    //    performed: fsync the PARENT DIRECTORY so the published directory
    //    entry survives a crash. FAIL-CLOSED: a failed open OR a failed
    //    fsync is a propagated error (never swallowed). Runs for a Created
    //    install AND for an AlreadyPresent retry (the convergent entry is
    //    made durable too); a Conflict's entry is not ours to bless — it is
    //    only ever read, never modified.
    if matches!(
        verdict,
        CreateNewVerdict::Created | CreateNewVerdict::AlreadyPresent
    ) && let Some(parent) = p.parent()
    {
        if fail(CreateNewStep::ParentFsync) {
            return Err(Error::transport(format!(
                "test fault: create-new step {step:?} forced to fail (once)",
                step = CreateNewStep::ParentFsync
            )));
        }
        let dir = std::fs::File::open(parent)
            .map_err(|e| Error::transport(format!("open dir {}: {e}", parent.display())))?;
        dir.sync_all()
            .map_err(|e| Error::transport(format!("fsync dir {}: {e}", parent.display())))?;
    }
    Ok(verdict)
}

/// Compare two byte slices under the caller's requested content equivalence:
/// `Exact` is byte equality; `Semantic` is JSON parse-equality (object key
/// order and whitespace are not part of the contract), falling back to byte
/// equality when either side does not parse as JSON. The ONE content
/// comparison used by the centralized verification ([`verify_existing`]) and
/// by the trait's default [`Remote::try_write_new_with`] semantic fallback.
pub(crate) fn content_equivalent(a: &[u8], b: &[u8], equivalence: ContentEquivalence) -> bool {
    match equivalence {
        ContentEquivalence::Exact => a == b,
        ContentEquivalence::Semantic => {
            if a == b {
                return true;
            }
            match (
                serde_json::from_slice::<serde_json::Value>(a),
                serde_json::from_slice::<serde_json::Value>(b),
            ) {
                (Ok(va), Ok(vb)) => va == vb,
                _ => false,
            }
        }
    }
}

/// THE ONE CENTRALIZED verification of an EXISTING create-new destination —
/// used by BOTH transports (the local [`durable_create_new`] verify-on-retry
/// and the SSH transport's EEXIST verification), so the two can never drift.
/// The verification is DESCRIPTOR-BOUND: the single `open` closure performs
/// the ONE open→fstat→read sequence on a SINGLE opened inode
/// ([`OpenedExisting::Entry`] carries the metadata from the fstat of the
/// OPENED descriptor AND the content read THROUGH THE SAME descriptor), so a
/// concurrent actor that swaps the entry at the path between the checks can
/// never mix two inodes' observations — a swap AFTER the open is irrelevant
/// (the descriptor pins the inode; the checks observe the pinned inode
/// consistently), and a swap BEFORE the open merely changes WHAT was opened
/// (the checks then run on the swapped inode consistently). The checks run
/// IN ORDER and the FIRST APPLICABLE class WINS — this first-failure
/// precedence IS the source of truth the create-new verification ORACLE
/// mirrors (the cross-product proptest in the ssh test module computes its
/// expected [`VerifiedExisting`] class from THIS order, never from ad-hoc
/// per-cell logic):
///
/// 1. **open** — the transport's `O_NOFOLLOW` open (the local
///    [`open_verify_local`] / the ssh framed helper), the FIRST check: an
///    ABSENT destination (ENOENT/ENOTDIR) → [`VerifiedExisting::NotFound`];
///    a SYMLINK → `NotRegularFile`{Symlink} (the `O_NOFOLLOW` open's ELOOP —
///    NEVER followed, even a symlink pointing at a matching regular file);
///    an UNREADABLE entry (EACCES/EPERM/EIO on the open/fstat/read) →
///    [`VerifiedExisting::Unreadable`]; a DIRECTORY → `NotRegularFile`
///    {Directory};
/// 2. **regular-file type** — from the OPENED descriptor's fstat: a
///    directory/symlink/other is [`VerifiedExisting::NotRegularFile`]. The
///    type check runs BEFORE readability, mode, and content: an unreadable or
///    wrong-mode DIRECTORY is still `NotRegularFile`, never `Unreadable` or
///    `ModeMismatch`;
/// 3. **readability** — the content read happens BEFORE the mode check: a
///    regular file whose content cannot be read is
///    [`VerifiedExisting::Unreadable`] (never a fabricated verdict) even
///    when its mode is wrong;
/// 4. **exact mode** — a regular file whose mode (masked to `0o7777`) does
///    not match the required mode is [`VerifiedExisting::ModeMismatch`],
///    decided BEFORE the content comparison;
/// 5. **the caller's content equivalence** ([`ContentEquivalence`]: exact
///    bytes or semantic JSON equality, per the caller's request) — the LAST
///    check: only a readable, mode-exact regular file is ever compared, and
///    a failed comparison is [`VerifiedExisting::ContentMismatch`].
///
/// `Ok` — and therefore [`CreateNewVerdict::AlreadyPresent`] via
/// [`verified_to_verdict`] — is produced ONLY when EVERY check held on the
/// ONE opened inode.
pub(crate) fn verify_existing(
    open: impl FnOnce() -> Result<OpenedExisting>,
    intended: &[u8],
    required_mode: u32,
    equivalence: ContentEquivalence,
) -> Result<VerifiedExisting> {
    // 1. open — the descriptor-bound open→fstat→read sequence (one inode).
    let opened = open()?;
    let OpenedExisting::Entry(entry) = opened else {
        return Ok(match opened {
            OpenedExisting::NotFound => VerifiedExisting::NotFound,
            OpenedExisting::NotRegular { kind } => VerifiedExisting::NotRegularFile { kind },
            OpenedExisting::Unreadable(m) => VerifiedExisting::Unreadable(m),
            OpenedExisting::Entry(_) => unreachable!(),
        });
    };
    let meta = entry.meta;
    // 2. regular-file type — from the OPENED descriptor's fstat (a symlink
    //    is unrepresentable here — the `O_NOFOLLOW` open never opened one —
    //    but kept for defense in depth).
    let kind = if meta.is_dir {
        NotRegularFileKind::Directory
    } else if meta.is_symlink {
        NotRegularFileKind::Symlink
    } else if meta.is_file {
        // 3. exact mode — the mode is part of the immutable record.
        let actual = meta.mode & 0o7777;
        let required = required_mode & 0o7777;
        if actual != required {
            return Ok(VerifiedExisting::ModeMismatch { actual, required });
        }
        // 4. the caller's content equivalence.
        if content_equivalent(&entry.content, intended, equivalence) {
            return Ok(VerifiedExisting::Ok {
                mode_ok: true,
                content: equivalence,
            });
        }
        return Ok(VerifiedExisting::ContentMismatch);
    } else {
        NotRegularFileKind::Other
    };
    Ok(VerifiedExisting::NotRegularFile { kind })
}

/// The descriptor-bound observation of an EXISTING create-new destination:
/// the type/mode (from `fstat` on the OPENED descriptor) and the content
/// (read THROUGH THE SAME descriptor). Metadata and content provably come
/// from the SAME OPENED INODE — the property that closes the
/// check-then-use (TOCTOU) hole: a concurrent actor that swaps the entry at
/// the path AFTER the open is irrelevant, because the descriptor pins the
/// inode.
#[derive(Clone, Debug)]
pub(crate) struct OpenedEntry {
    pub(crate) meta: RemoteMeta,
    pub(crate) content: Vec<u8>,
}

/// The OUTCOME of the descriptor-bound open — [`verify_existing`]'s single
/// `open` step (the LOCAL [`open_verify_local`] / the ssh framed helper):
/// the entry was opened with `O_NOFOLLOW` and its metadata + content were
/// observed through the SAME opened descriptor ([`OpenedExisting::Entry`]),
/// or the open/fstat/read failed with a TYPED reason — absent
/// (ENOENT/ENOTDIR → [`OpenedExisting::NotFound`]), a symlink (the
/// `O_NOFOLLOW` open's ELOOP — NEVER followed, even when the symlink points
/// at a matching regular file), a directory (EISDIR from the open, or the
/// opened inode's own type), or unreadable (EACCES/EPERM/EIO/... — a real
/// failure, never a fabricated verdict).
#[derive(Clone, Debug)]
pub(crate) enum OpenedExisting {
    /// The opened inode's metadata (fstat) AND content (read through the
    /// same descriptor): the checks run on ONE consistent inode.
    Entry(OpenedEntry),
    /// The `O_NOFOLLOW` open reported the destination absent (ENOENT/ENOTDIR).
    NotFound,
    /// The opened (or fstat'd) inode is NOT a regular file: a directory, a
    /// symlink (never followed), or another kind.
    NotRegular { kind: NotRegularFileKind },
    /// The entry could not be opened/fstat'd/read (EACCES/EPERM/EIO/...): a
    /// real failure, never a fabricated verdict.
    Unreadable(String),
}

/// The boundary of [`verify_existing`]'s descriptor-bound sequence at which a
/// one-shot test swap fires: BEFORE the `O_NOFOLLOW` open (the swap changes
/// WHAT is opened), or AFTER the open / AFTER the fstat (the swap changes the
/// PATH while the descriptor keeps pinning the ORIGINAL inode — the
/// fd-bound property under test).
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VerifySwapBoundary {
    BeforeOpen,
    AfterOpen,
    AfterFstat,
}

/// The one-shot test-only entry a [`VerifySwap`] places at the destination
/// (originally a REGULAR file): a SYMLINK (pointing at the pre-staged
/// `swap_target` regular file — a following open would ACCEPT it, the
/// `O_NOFOLLOW` open must reject it), a DIRECTORY, or a DIFFERENT-INODE
/// regular file (the pre-staged `swap_target`, moved onto the destination).
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VerifySwapKind {
    Symlink,
    Directory,
    DifferentInode,
}

/// One-shot swap injection for [`verify_existing`]'s descriptor-bound
/// sequence: at the chosen [`VerifySwapBoundary`], replaces the destination
/// with a [`VerifySwapKind`] entry (the original is moved aside, so the
/// fd-pinned inode stays observable). Fires EXACTLY ONCE, per fixture
/// (never a process-global slot — two fixtures' swaps can never consume each
/// other). Test-only (production never arms one); the swap-at-every-boundary
/// proptest arms exactly one.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct VerifySwap {
    boundary: VerifySwapBoundary,
    kind: VerifySwapKind,
    /// The pre-staged SWAP entry: the symlink target (a regular file) or the
    /// different-inode regular file (the directory swap ignores it).
    swap_target: PathBuf,
    armed: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl VerifySwap {
    pub(crate) fn new(
        boundary: VerifySwapBoundary,
        kind: VerifySwapKind,
        swap_target: &Path,
    ) -> Self {
        Self {
            boundary,
            kind,
            swap_target: swap_target.to_path_buf(),
            armed: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Fire the swap exactly once when the boundary matches; `true` when it
    /// fired (the destination was replaced with the swap entry).
    pub(crate) fn fire(&self, boundary: VerifySwapBoundary, p: &Path) -> bool {
        use std::sync::atomic::Ordering;
        if self.boundary != boundary || !self.armed.swap(false, Ordering::SeqCst) {
            return false;
        }
        self.swap(p);
        true
    }

    fn swap(&self, p: &Path) {
        // Move the ORIGINAL entry aside (its inode survives for identity
        // checks — and for the post-open boundaries, the opened descriptor
        // keeps pinning it), then place the swap entry at the destination.
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let backup = p.with_file_name(format!(".{name}.swap-orig"));
        let _ = std::fs::rename(p, &backup);
        match self.kind {
            VerifySwapKind::Symlink => {
                let _ = std::os::unix::fs::symlink(&self.swap_target, p);
            }
            VerifySwapKind::Directory => {
                let _ = std::fs::create_dir(p);
            }
            VerifySwapKind::DifferentInode => {
                let _ = std::fs::rename(&self.swap_target, p);
            }
        }
    }
}

/// Open `p` with `O_NOFOLLOW` (a symlink at the path → ELOOP →
/// [`OpenedExisting::NotRegular`]{Symlink} — NEVER followed, even when it
/// points at a matching regular file), `fstat` the SAME descriptor, and read
/// THROUGH THE SAME descriptor — the LOCAL realization of the descriptor-
/// bound sequence [`verify_existing`] requires (the ssh transport's framed
/// helper performs the SAME sequence in ONE remote exec). `O_NONBLOCK`
/// keeps the open from blocking on a fifo/device (the entry is then
/// classified by its `fstat` type, never read). A swap at the path AFTER the
/// open is irrelevant — the descriptor pins the inode.
fn open_verify_local(p: &Path, #[cfg(test)] swap: Option<&VerifySwap>) -> Result<OpenedExisting> {
    use std::io::Read;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(test)]
    if swap.is_some_and(|s| s.fire(VerifySwapBoundary::BeforeOpen, p)) {
        // The swap consumed: the destination was replaced BEFORE the open,
        // so the open observes the SWAPPED entry.
    }
    let mut f = match opts.open(p) {
        Ok(f) => f,
        Err(e) => return Ok(local_open_err(p, e)),
    };
    #[cfg(test)]
    if swap.is_some_and(|s| s.fire(VerifySwapBoundary::AfterOpen, p)) {
        // The swap consumed: the PATH was replaced AFTER the open — the fd
        // pins the ORIGINAL inode, so the fstat and read below still
        // observe it (the swap is harmless).
    }
    let meta = match f.metadata() {
        Ok(m) => meta_to_remote(&m),
        Err(e) => {
            return Ok(OpenedExisting::Unreadable(format!(
                "verify fstat {}: {e}",
                p.display()
            )));
        }
    };
    #[cfg(test)]
    if swap.is_some_and(|s| s.fire(VerifySwapBoundary::AfterFstat, p)) {
        // The swap consumed: the PATH was replaced AFTER the fstat — the fd
        // still pins the ORIGINAL inode, so the read below observes it.
    }
    if meta.is_dir {
        return Ok(OpenedExisting::NotRegular {
            kind: NotRegularFileKind::Directory,
        });
    }
    if meta.is_symlink {
        return Ok(OpenedExisting::NotRegular {
            kind: NotRegularFileKind::Symlink,
        });
    }
    if !meta.is_file {
        return Ok(OpenedExisting::NotRegular {
            kind: NotRegularFileKind::Other,
        });
    }
    let mut content = Vec::new();
    if let Err(e) = f.read_to_end(&mut content) {
        return Ok(OpenedExisting::Unreadable(format!(
            "verify read {}: {e}",
            p.display()
        )));
    }
    Ok(OpenedExisting::Entry(OpenedEntry { meta, content }))
}

/// Map a failed `O_NOFOLLOW` open to the TYPED reason in the
/// [`VerifiedExisting`] first-failure order: ENOENT/ENOTDIR → NotFound; ELOOP
/// → NotRegularFile{Symlink} (the open NEVER follows a symlink — even one
/// pointing at a matching regular file); EISDIR → NotRegularFile{Directory};
/// every other errno (EACCES/EPERM/EIO/...) → Unreadable (a real failure,
/// never a fabricated verdict).
fn local_open_err(p: &Path, e: std::io::Error) -> OpenedExisting {
    match e.raw_os_error() {
        Some(libc::ENOENT) | Some(libc::ENOTDIR) => OpenedExisting::NotFound,
        Some(libc::ELOOP) => OpenedExisting::NotRegular {
            kind: NotRegularFileKind::Symlink,
        },
        Some(libc::EISDIR) => OpenedExisting::NotRegular {
            kind: NotRegularFileKind::Directory,
        },
        _ => OpenedExisting::Unreadable(format!("verify open {}: {e}", p.display())),
    }
}

/// The ONE verdict-construction path: [`CreateNewVerdict::AlreadyPresent`]
/// ONLY when the typed verification is `Ok` WITH the mode check held (the
/// entry was a regular file whose mode matched EXACTLY — `content` already
/// held by construction); EVERY other reason is
/// [`CreateNewVerdict::Conflict`] carrying the typed reason. Callers receive
/// the typed reason and can never reinterpret an undifferentiated conflict.
pub(crate) fn verified_to_verdict(v: VerifiedExisting) -> CreateNewVerdict {
    match v {
        VerifiedExisting::Ok { mode_ok: true, .. } => CreateNewVerdict::AlreadyPresent,
        v => CreateNewVerdict::Conflict(v),
    }
}

/// A transport that operates on a local directory, executing commands on the
/// host. It mirrors the SSH remote layout exactly.
pub struct LocalTransport {
    base: PathBuf,
    /// The caller-supplied deployment layout: the bootstrap directories
    /// `provision_layout` creates, the operation-lock path whose mutations
    /// are sidecar-serialized, and the optional receiver-id marker.
    layout: Layout,
    /// The child environment snapshot: every spawned child (`df`)
    /// receives THIS snapshot as its ENTIRE environment
    /// ([`SysEnv::apply_to_command`]: `env_clear` first, then the snapshot's
    /// variables) — a deterministic HERMETIC environment resolved at the
    /// construction boundary, never whatever the parent env looks like at
    /// spawn time, and nothing else.
    env: SysEnv,
    /// THE command-execution seam every `exec` goes through: production uses
    /// [`ChildRunner`] (the bounded real runner: owns the child from spawn
    /// to the mandatory reap, terminates the whole process GROUP on timeout
    /// (TERM, grace, KILL), and returns every outcome — success, timeout,
    /// error — only after the child was reaped; a timeout-kill failure is an
    /// error, never a successful timeout outcome); the deterministic
    /// properties inject a scripted fake (no subprocess, no wall-clock).
    exec: Box<dyn Exec>,
}

impl LocalTransport {
    /// Build a transport rooted at `base` whose children run with the
    /// environment snapshot `env` (see [`SysEnv::apply_to_command`]) as their
    /// ENTIRE environment. Construction
    /// is side-effect-free: no directories are created and nothing is
    /// touched on disk. Call [`Remote::provision_layout`] to create the
    /// deployment layout before the first mutation (the push engine does
    /// this behind its non-dry-run gate).
    ///
    /// The FILESYSTEM ROOT is refused (defense in depth): a transport rooted
    /// at `/` would make the deployment cleanup operate on the system root,
    /// so the base must have at least one normal path component below the
    /// root.
    pub fn new(env: &SysEnv, base: PathBuf, layout: Layout) -> Result<Self> {
        let runner_base = base.clone();
        Self::with_exec(
            env,
            base,
            layout,
            ChildRunner::new(env, runner_base, RunnerConfig::production()),
        )
    }

    /// Build a transport whose `exec` calls are handled by `exec` instead of
    /// the production [`ChildRunner`]. Construction stays side-effect-free
    /// (no directories created, nothing spawned). Test-support seam: the
    /// deterministic properties inject a scripted fake so the push LOGIC
    /// (verification/activation outcomes) is exercised without spawning real
    /// processes.
    pub fn with_exec(
        env: &SysEnv,
        base: PathBuf,
        layout: Layout,
        exec: impl Exec + 'static,
    ) -> Result<Self> {
        if !has_normal_component_below_root(&base) {
            return Err(Error::transport(format!(
                "deploy_dir {:?} must have at least one normal path component below the root (the filesystem root is not a valid deploy_dir)",
                base
            )));
        }
        Ok(LocalTransport {
            base,
            layout,
            env: env.clone(),
            exec: Box::new(exec),
        })
    }
}

impl LocalTransport {
    // =================================================================
    // FD-CONFINED OPERATIONS (the applier's destination surface, `unix`)
    // -------------------------------------------------------------
    // Every operation the sync applier issues on a `LocalTransport`
    // destination — MUTATIONS and the READS it verifies against — resolves
    // COMPONENT-WISE from an fd-pinned root with `openat(O_NOFOLLOW)` when it
    // names a non-empty path below the root: a symlink injected at ANY
    // component below the root is refused (never followed), exactly as the
    // fd-confined `Side::Local` destination already does. The reads (`read`,
    // `read_link`, `metadata_opt`/`metadata`, `exists`) are confined so a
    // verification verdict cannot be sourced from outside the pinned root. The
    // path-based bodies below are kept `#[cfg(not(unix))]` (the Windows port
    // has no directory descriptors and keeps its documented weaker guarantee)
    // or are the NAMED exceptions: the destination ROOT listing, and the
    // durability helpers (`fsync_parent`/`fsync_tree`).
    // =================================================================

    /// Open the transport root as an fd-pinned directory. With `create`, a
    /// MISSING root path is created first (path-based: the root itself is the
    /// trusted anchor, and its swap race is the one the module documents).
    /// `Ok(None)` ONLY when the root does not exist and `create` is false, so
    /// the absent-root-enumerates-as-empty behaviour is preserved. Every
    /// COMPONENT BELOW the root is then resolved with `openat(O_NOFOLLOW)`.
    #[cfg(unix)]
    fn root_dir(&self, create: bool) -> Result<Option<crate::atomic::RootDir>> {
        if create && !self.base.exists() {
            std::fs::create_dir_all(&self.base)
                .map_err(|e| Error::transport(format!("mkdir {}: {e}", self.base.display())))?;
        }
        match crate::atomic::RootDir::open(&self.base) {
            Ok(root) => Ok(Some(root)),
            Err(error) => {
                if self.base.exists() {
                    Err(error)
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Create the parent chain of `rel` fd-relatively, preserving the mode of
    /// an EXISTING directory and creating only MISSING components (0o700, the
    /// local intermediate mode; the caller finalizes the real mode). A symlink
    /// at any component is refused.
    #[cfg(unix)]
    fn ensure_dir_confined(
        &self,
        root: &crate::atomic::RootDir,
        rel: &RootedRelativePath,
    ) -> Result<()> {
        let Some(parent) = rel.parent() else {
            return Ok(());
        };
        match crate::atomic::path_kind_fd(root, parent.as_path()) {
            Ok(Some(crate::atomic::PathKind::Dir)) => Ok(()),
            Ok(Some(_)) => Err(Error::transport(format!(
                "mkdir {}: a parent component exists but is not a directory",
                rel.display()
            ))),
            // A missing parent component (or any other failure resolving the
            // final entry) is handled by the fd-safe create below, which
            // REFUSES a symlink at any component.
            Ok(None) | Err(_) => {
                crate::atomic::ensure_private_dir_durable_fd(root, parent.as_path())
                    .map(|_| ())
                    .map_err(|e| Error::transport(format!("mkdir {}: {e}", rel.display())))
            }
        }
    }

    #[cfg(unix)]
    fn write_confined(&self, rel: &RootedRelativePath, data: &[u8], mode: u32) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let root = self.root_dir(true)?.ok_or_else(|| {
            Error::transport(format!(
                "write {}: the destination root is unavailable",
                rel.display()
            ))
        })?;
        self.ensure_dir_confined(&root, rel)?;
        // THE DESTINATION IS WRITTEN ATOMICALLY AND DURABLY: a unique temp in
        // the same directory, fsynced, then renamed into place, then the
        // parent directory fsynced — the replace has TWO commit points and a
        // failure BEFORE the rename leaves the PREVIOUS content untouched and
        // unlinks the temp (see [`crate::atomic::write_atomic_replace`]). The
        // old path here (`atomic::write_file_fd`) opened the destination
        // `O_WRONLY|O_CREAT|O_TRUNC` and did ONE `write` with no temp, no
        // rename and no fsync, so a push into a LOCAL destination could leave
        // the entry torn and truncated. A post-rename parent-fsync failure is
        // EXPLICIT (`ReplacedDurabilityUnknown`): the content is visible but
        // its durability is unconfirmed, and the caller must not read that as
        // a clean success.
        match crate::atomic::write_atomic_replace_fd_under_existing_parent(
            &root,
            rel.as_path(),
            data,
            &mut |_| None,
        )
        .map_err(|e| Error::transport(format!("write {}: {e}", rel.display())))?
        {
            crate::atomic::ReplaceOutcome::ReplacedDurable => {}
            crate::atomic::ReplaceOutcome::ReplacedDurabilityUnknown { error } => {
                return Err(Error::transport(format!(
                    "write {}: the entry is visible but its durability is unconfirmed: {error}",
                    rel.display()
                )));
            }
        }
        if mode != 0 {
            let fd = crate::atomic::openat_no_follow(
                root.as_fd(),
                rel.as_path(),
                libc::O_RDONLY | libc::O_NOFOLLOW,
                0,
            )?;
            std::fs::File::from(fd)
                .set_permissions(std::fs::Permissions::from_mode(mode & 0o7777))
                .map_err(|e| Error::transport(format!("chmod {}: {e}", rel.display())))?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn create_dir_all_confined(&self, rel: &RootedRelativePath) -> Result<()> {
        let root = self.root_dir(true)?.ok_or_else(|| {
            Error::transport(format!(
                "mkdir {}: the destination root is unavailable",
                rel.display()
            ))
        })?;
        match crate::atomic::path_kind_fd(&root, rel.as_path()) {
            // An EXISTING directory (whatever its mode) is left exactly as it
            // is: `create_dir_all` never chmods an existing directory.
            Ok(Some(crate::atomic::PathKind::Dir)) => return Ok(()),
            Ok(Some(_)) => {
                return Err(Error::transport(format!(
                    "mkdir {}: the path exists but is not a directory",
                    rel.display()
                )));
            }
            // A missing component (or any failure) is handled by the fd-safe
            // create below, which refuses a symlink at any component.
            Ok(None) | Err(_) => {}
        }
        crate::atomic::ensure_private_dir_durable_fd(&root, rel.as_path())
            .map(|_| ())
            .map_err(|e| Error::transport(format!("mkdir {}: {e}", rel.display())))
    }

    #[cfg(unix)]
    fn set_mode_confined(&self, rel: &RootedRelativePath, mode: u32) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let root = self.root_dir(false)?.ok_or_else(|| {
            Error::transport(format!(
                "chmod {}: the destination root is absent",
                rel.display()
            ))
        })?;
        let fd = crate::atomic::openat_no_follow(
            root.as_fd(),
            rel.as_path(),
            libc::O_RDONLY | libc::O_NOFOLLOW,
            0,
        )?;
        std::fs::File::from(fd)
            .set_permissions(std::fs::Permissions::from_mode(mode & 0o7777))
            .map_err(|e| Error::transport(format!("chmod {}: {e}", rel.display())))
    }

    #[cfg(unix)]
    fn rename_confined(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
        let root = self.root_dir(false)?.ok_or_else(|| {
            Error::transport(format!(
                "rename {}: the destination root is absent",
                from.display()
            ))
        })?;
        // The destination parent must exist (the old path-based rename created
        // it, best-effort); creating it here is component-wise with
        // `O_NOFOLLOW`.
        self.ensure_dir_confined(&root, to)?;
        crate::atomic::renameat_paths(&root, from.as_path(), to.as_path()).map_err(|e| {
            Error::transport(format!(
                "rename {} -> {}: {e}",
                from.display(),
                to.display()
            ))
        })
    }

    #[cfg(unix)]
    fn symlink_confined(&self, target: &Path, link: &RootedRelativePath) -> Result<()> {
        // R1: the whole symlink (ensure parent, unlink any existing entry,
        // symlinkat, fsync parent) is issued by the ONE guarded atomic
        // authority, so a link spelled as the lock record cannot unlink the
        // record and install a link. There is NO raw `libc::unlinkat` /
        // `libc::symlinkat` left here.
        let root = self.root_dir(true)?.ok_or_else(|| {
            Error::transport(format!(
                "symlink {}: the destination root is unavailable",
                link.display()
            ))
        })?;
        crate::atomic::symlink_fd(&root, target, link.as_path()).map_err(|e| {
            Error::transport(format!(
                "symlink {} -> {}: {e}",
                link.display(),
                target.display()
            ))
        })
    }

    #[cfg(unix)]
    fn remove_file_confined(&self, rel: &RootedRelativePath) -> Result<()> {
        let Some(root) = self.root_dir(false)? else {
            return Ok(());
        };
        match crate::atomic::remove_file_fd(&root, rel.as_path()) {
            Ok(()) => Ok(()),
            Err(error) => match crate::atomic::openat_no_follow_io(
                root.as_fd(),
                rel.as_path(),
                libc::O_RDONLY,
                0,
            ) {
                // A missing entry OR a missing parent component is the
                // old path-based `remove_file`'s tolerated `NotFound`.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                _ => Err(Error::transport(format!(
                    "remove {}: {error}",
                    rel.display()
                ))),
            },
        }
    }

    #[cfg(unix)]
    fn remove_dir_all_confined(&self, rel: &RootedRelativePath) -> Result<()> {
        let Some(root) = self.root_dir(false)? else {
            return Ok(());
        };
        match crate::atomic::remove_dir_all_fd(&root, rel.as_path()) {
            Ok(()) => Ok(()),
            Err(error) => match crate::atomic::openat_no_follow_io(
                root.as_fd(),
                rel.as_path(),
                libc::O_RDONLY,
                0,
            ) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                _ => Err(Error::transport(format!(
                    "rmdir {}: {error}",
                    rel.display()
                ))),
            },
        }
    }

    /// The descriptor-relative NON-RECURSIVE directory removal: resolve the
    /// PARENT component-wise with `O_NOFOLLOW`, then `unlinkat(AT_REMOVEDIR)`
    /// the final name. `AT_REMOVEDIR` refuses a non-empty directory with
    /// `ENOTEMPTY`, so a child created after a removal walk enumerated the
    /// directory is never destroyed unnamed. A confirmed absence is success.
    #[cfg(unix)]
    fn remove_dir_confined(&self, rel: &RootedRelativePath) -> Result<()> {
        let Some(root) = self.root_dir(false)? else {
            return Ok(());
        };
        // The ONE guarded rmdir authority; a confirmed absence is success.
        crate::atomic::remove_dir_fd(&root, rel.as_path())
            .map_err(|e| Error::transport(format!("rmdir {}: {e}", rel.display())))
    }

    #[cfg(unix)]
    fn list_confined(&self, rel: &RootedRelativePath) -> Result<Vec<RemoteEntry>> {
        let Some(root) = self.root_dir(false)? else {
            return Ok(Vec::new());
        };
        let entries = match crate::atomic::read_dir_fd(&root, rel.as_path()) {
            Ok(entries) => entries,
            Err(error) => {
                // Preserve the absent-directory-enumerates-as-empty contract;
                // a MISSING entry or parent component (a genuine `NotFound`)
                // is empty, while EVERY other failure — including a symlink
                // component (`ELOOP`), which `read_dir_fd` refuses — is
                // propagated.
                return match crate::atomic::openat_no_follow_io(
                    root.as_fd(),
                    rel.as_path(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    0,
                ) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
                    _ => Err(Error::transport(format!(
                        "read_dir {}: {error}",
                        rel.display()
                    ))),
                };
            }
        };
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            let child = rel.join(&entry.name)?;
            let (is_dir, is_symlink) = match crate::atomic::path_kind_fd(&root, child.as_path())? {
                Some(crate::atomic::PathKind::Dir) => (true, false),
                Some(crate::atomic::PathKind::Symlink) => (false, true),
                Some(crate::atomic::PathKind::File) | Some(crate::atomic::PathKind::Other) => {
                    (false, false)
                }
                None => continue,
            };
            let name = entry.name.into_string().map_err(|_| {
                Error::transport(format!(
                    "read_dir {}: entry name is not valid UTF-8, so the listing cannot be compared byte-exactly (distinct names would both decode to U+FFFD); refusing: {}",
                    rel.display(),
                    child.display()
                ))
            })?;
            let (size, mode) = self.entry_size_mode_confined(&root, &child, is_symlink)?;
            out.push(RemoteEntry {
                name,
                is_dir,
                is_symlink,
                size,
                mode,
            });
        }
        Ok(out)
    }

    /// The size and mode of one live child. A FILE or DIRECTORY is opened
    /// `O_NOFOLLOW` relative to the pinned root and `fstat`ed through the SAME
    /// descriptor (no path re-resolution). A SYMLINK is classified without
    /// following it and its OWN size/mode come from a component-wise
    /// `fstatat(AT_SYMLINK_NOFOLLOW)` ([`LocalTransport::confined_lstat`]); it is
    /// never followed.
    #[cfg(unix)]
    fn entry_size_mode_confined(
        &self,
        root: &crate::atomic::RootDir,
        child: &RootedRelativePath,
        is_symlink: bool,
    ) -> Result<(u64, u32)> {
        if !is_symlink {
            let fd = crate::atomic::openat_no_follow(
                root.as_fd(),
                child.as_path(),
                libc::O_RDONLY | libc::O_NOFOLLOW,
                0,
            )?;
            let meta = std::fs::File::from(fd)
                .metadata()
                .map_err(|e| Error::transport(format!("fstat {}: {e}", child.display())))?;
            let remote = meta_to_remote(&meta);
            return Ok((remote.size, remote.mode));
        }
        let remote = self.confined_lstat(root, child)?.ok_or_else(|| {
            Error::transport(format!("lstat {}: the entry vanished", child.display()))
        })?;
        Ok((remote.size, remote.mode))
    }

    /// The metadata of the entry at `rel`, obtained from an
    /// `fstatat(AT_SYMLINK_NOFOLLOW)` whose parent directory is resolved
    /// COMPONENT-WISE with `openat(O_NOFOLLOW)`. The FINAL component is never
    /// opened and its link is never followed, so this is a pure, side-effect-free
    /// stat that cannot be redirected outside the pinned root by a symlink at any
    /// component. A missing final component OR a missing parent component is
    /// ABSENCE (`Ok(None)`), exactly matching the path-based
    /// `symlink_metadata` it replaces; every other filesystem error propagates.
    #[cfg(unix)]
    fn confined_lstat(
        &self,
        root: &crate::atomic::RootDir,
        rel: &RootedRelativePath,
    ) -> Result<Option<RemoteMeta>> {
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;
        let path = rel.as_path();
        let name = path
            .file_name()
            .ok_or_else(|| Error::transport(format!("lstat {}: no file name", rel.display())))?;
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
        let parent_fd = match parent {
            Some(parent) => match crate::atomic::openat_no_follow_io(
                root.as_fd(),
                parent,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                0,
            ) {
                Ok(fd) => fd,
                // A missing parent component names no entry: absence.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => {
                    return Err(Error::transport(format!("lstat {}: {e}", rel.display())));
                }
            },
            None => root
                .as_fd()
                .try_clone()
                .map_err(|e| Error::transport(format!("dup root dir: {e}")))?,
        };
        let name_c = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| Error::transport(format!("lstat {}: name with NUL", rel.display())))?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::fstatat(
                parent_fd.as_raw_fd(),
                name_c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(Error::transport(format!("lstat {}: {e}", rel.display())));
        }
        let file_type = st.st_mode & libc::S_IFMT;
        Ok(Some(RemoteMeta {
            is_dir: file_type == libc::S_IFDIR,
            is_symlink: file_type == libc::S_IFLNK,
            is_file: file_type == libc::S_IFREG,
            size: st.st_size.max(0) as u64,
            mode: st.st_mode as u32,
        }))
    }

    /// The path-based listing, used for the destination ROOT on Unix (the
    /// `read_dir_fd` helper refuses the empty root-relative path) and for
    /// EVERY path on the Windows port.
    fn list_path_based(&self, rel: &RootedRelativePath) -> Result<Vec<RemoteEntry>> {
        let dir = join(&self.base, rel);
        // An unprovisioned remote root has no directories yet; report an empty
        // listing rather than erroring so read-only inspection stays valid.
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(Error::transport(format!("read_dir {}: {e}", dir.display())));
            }
        };
        let mut out = Vec::new();
        for e in rd {
            let e = e.map_err(|e| Error::transport(format!("entry: {e}")))?;
            // A `RemoteEntry.name` must be the on-disk name EXACTLY: the
            // sync's listing check is BYTE-EXACT, and two distinct names that
            // are not valid UTF-8 both decode to U+FFFD under
            // `to_string_lossy` — the lossy listing would then report success
            // while the destination holds an entry no caller can address (and
            // `canonicalize_tree` would refuse the tree the run claimed to
            // have produced). Fail closed, naming the entry, instead of
            // handing any caller a lossy view.
            let path = e.path();
            let name = e.file_name().into_string().map_err(|_| {
                Error::transport(format!(
                    "read_dir {}: entry name is not valid UTF-8, so the listing cannot be compared byte-exactly (distinct names would both decode to U+FFFD); refusing: {}",
                    dir.display(),
                    path.display()
                ))
            })?;
            // `symlink_metadata` (not `metadata`) so a symlink is reported as a
            // symlink with its own mode rather than being followed to its target.
            let m = std::fs::symlink_metadata(e.path())
                .map_err(|e| Error::transport(format!("meta: {e}")))?;
            out.push(RemoteEntry {
                name,
                is_dir: m.is_dir(),
                is_symlink: m.file_type().is_symlink(),
                size: m.len(),
                mode: crate::platform::metadata_mode(&m),
            });
        }
        Ok(out)
    }
}

impl Remote for LocalTransport {
    fn root(&self) -> &Path {
        &self.base
    }

    fn is_local(&self) -> bool {
        true
    }

    fn provision_layout(&self) -> Result<()> {
        if !self.base.exists() {
            std::fs::create_dir_all(&self.base)
                .map_err(|e| Error::transport(format!("mkdir {}: {e}", self.base.display())))?;
        }
        // Provision the caller-supplied top-level layout.
        for d in &self.layout.bootstrap_dirs {
            let p = self.base.join(d);
            if !p.exists() {
                std::fs::create_dir_all(&p)
                    .map_err(|e| Error::transport(format!("mkdir {}: {e}", p.display())))?;
            }
        }
        // The IMMUTABLE receiver-id marker: the PHYSICAL identity of this
        // deploy_dir, created ONCE at provisioning and never changed (a
        // re-provisioning adopts the existing marker).
        if let Some(marker) = &self.layout.receiver_marker {
            provision_receiver_id(self, marker)?;
        }
        Ok(())
    }

    /// Read the bytes at `rel`, descriptor-relative on Unix: the parent is
    /// resolved COMPONENT-WISE with `openat(O_NOFOLLOW)` and the final component
    /// is opened `O_NOFOLLOW`, so a symlink at any component is REFUSED and the
    /// bytes can never be sourced from outside the pinned root. This is what
    /// makes the applier's content verification a verdict about the CONFINED
    /// object rather than a path that may have been swapped.
    #[cfg(unix)]
    fn read(&self, rel: &RootedRelativePath) -> Result<Vec<u8>> {
        let Some(root) = self.root_dir(false)? else {
            return Err(Error::transport(format!(
                "read {}: the destination root is absent",
                rel.display()
            )));
        };
        crate::atomic::read_fd(&root, rel.as_path())
            .map_err(|e| Error::transport(format!("read {}: {e}", rel.display())))
    }

    #[cfg(not(unix))]
    fn read(&self, rel: &RootedRelativePath) -> Result<Vec<u8>> {
        std::fs::read(join(&self.base, rel))
            .map_err(|e| Error::transport(format!("read {}: {e}", rel.display())))
    }

    #[cfg(unix)]
    fn write(&self, rel: &RootedRelativePath, data: &[u8], mode: u32) -> Result<()> {
        self.write_confined(rel, data, mode)
    }

    #[cfg(unix)]
    fn create_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
        self.create_dir_all_confined(rel)
    }

    #[cfg(unix)]
    fn set_mode(&self, rel: &RootedRelativePath, mode: u32) -> Result<()> {
        self.set_mode_confined(rel, mode)
    }

    #[cfg(unix)]
    fn list(&self, rel: &RootedRelativePath) -> Result<Vec<RemoteEntry>> {
        if rel.as_path().as_os_str().is_empty() {
            // The destination ROOT itself: `read_dir_fd` refuses the empty
            // path (it must name at least one normal component), so the pinned
            // root PATH is read directly. This is the ONE name read that is
            // not descriptor-relative (the manifest walk is path-based too),
            // and the residual root-swap race is the one the module documents.
            return self.list_path_based(rel);
        }
        self.list_confined(rel)
    }

    #[cfg(unix)]
    fn rename(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
        self.rename_confined(from, to)
    }

    #[cfg(unix)]
    fn symlink(&self, target: &Path, link: &RootedRelativePath) -> Result<()> {
        self.symlink_confined(target, link)
    }

    #[cfg(unix)]
    fn remove_file(&self, rel: &RootedRelativePath) -> Result<()> {
        self.remove_file_confined(rel)
    }

    #[cfg(unix)]
    fn remove_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
        self.remove_dir_all_confined(rel)
    }

    #[cfg(unix)]
    fn remove_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        self.remove_dir_confined(rel)
    }

    /// The sanctioned explicit-discard route for a LOCAL destination: the
    /// sync's own claim-aside (a residue spelling) is removed through the
    /// residue-sanctioning atomic primitive. Without this override the ordinary
    /// `remove_file` would refuse the strand once the residue authority joined
    /// the ONE gate (A1), breaking the engine's own `drop_claim`.
    fn remove_residue_file(&self, rel: &RootedRelativePath) -> Result<()> {
        let root = crate::atomic::RootDir::open(&self.base)
            .map_err(|e| Error::transport(format!("remove residue {}: {e}", rel.display())))?;
        match crate::atomic::remove_claim_file_fd(&root, rel.as_path()) {
            Ok(()) => Ok(()),
            Err(error) => match crate::atomic::path_kind_fd(&root, rel.as_path()) {
                Ok(None) => Ok(()),
                _ => Err(Error::transport(format!(
                    "remove residue {}: {error}",
                    rel.display()
                ))),
            },
        }
    }

    /// The sanctioned explicit-discard route for a LOCAL claim-aside DIRECTORY
    /// that the removal walk has already emptied (non-recursive `rmdir`).
    fn remove_residue_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        let root = crate::atomic::RootDir::open(&self.base)
            .map_err(|e| Error::transport(format!("rmdir residue {}: {e}", rel.display())))?;
        crate::atomic::remove_claim_dir_fd(&root, rel.as_path())
            .map_err(|e| Error::transport(format!("rmdir residue {}: {e}", rel.display())))
    }

    /// The sanctioned residue-movement rename for the sync's OWN claim-aside
    /// (either endpoint may carry a residue spelling). The public
    /// [`Remote::rename`] refuses a residue spelling.
    fn rename_aside(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
        let root = crate::atomic::RootDir::open(&self.base)
            .map_err(|e| Error::transport(format!("rename aside {}: {e}", from.display())))?;
        crate::atomic::rename_residue_paths(&root, from.as_path(), to.as_path()).map_err(|e| {
            Error::transport(format!(
                "rename aside {} -> {}: {e}",
                from.display(),
                to.display()
            ))
        })
    }

    #[cfg(not(unix))]
    fn write(&self, rel: &RootedRelativePath, data: &[u8], mode: u32) -> Result<()> {
        // R4: no direct `std::fs` mutation here any more. The path-based
        // Windows seam routes through the SAME guarded atomic funnel the Unix
        // port uses, so the Windows atomic guards are actually reached. The
        // mode chmod is inode-preserving and stays a best-effort path call.
        let root = crate::atomic::RootDir::open(&self.base)
            .map_err(|e| Error::transport(format!("write {}: {e}", rel.display())))?;
        if let Some(parent) = rel.parent()
            && !parent.as_path().as_os_str().is_empty()
        {
            crate::atomic::ensure_private_dir_fd(&root, parent.as_path())
                .map_err(|e| Error::transport(format!("mkdir {}: {e}", parent.display())))?;
        }
        crate::atomic::write_file_fd(&root, rel.as_path(), data)
            .map_err(|e| Error::transport(format!("write {}: {e}", rel.display())))?;
        if mode != 0 {
            crate::platform::chmod(&join(&self.base, rel), mode & 0o7777)
                .map_err(|e| Error::transport(format!("chmod {}: {e}", rel.display())))?;
        }
        Ok(())
    }

    fn create_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        // Now a guarded atomic operation on BOTH platforms (the Unix body used
        // to be a path-based `std::fs::create_dir` that bypassed both the
        // confinement and the lock-record guard).
        let root = crate::atomic::RootDir::open(&self.base)
            .map_err(|e| Error::transport(format!("mkdir {}: {e}", rel.display())))?;
        crate::atomic::create_dir_fd(&root, rel.as_path())
            .map_err(|e| Error::transport(format!("mkdir {}: {e}", rel.display())))
    }

    #[cfg(not(unix))]
    fn create_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
        let root = crate::atomic::RootDir::open(&self.base)
            .map_err(|e| Error::transport(format!("mkdir {}: {e}", rel.display())))?;
        crate::atomic::ensure_private_dir_fd(&root, rel.as_path())
            .map_err(|e| Error::transport(format!("mkdir {}: {e}", rel.display())))
    }

    #[cfg(not(unix))]
    fn set_mode(&self, rel: &RootedRelativePath, mode: u32) -> Result<()> {
        crate::platform::chmod(&join(&self.base, rel), mode & 0o7777)
            .map_err(|e| Error::transport(format!("chmod {}: {e}", rel.display())))
    }

    #[cfg(not(unix))]
    fn list(&self, rel: &RootedRelativePath) -> Result<Vec<RemoteEntry>> {
        self.list_path_based(rel)
    }

    #[cfg(not(unix))]
    fn rename(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
        let root = crate::atomic::RootDir::open(&self.base)
            .map_err(|e| Error::transport(format!("rename {}: {e}", from.display())))?;
        crate::atomic::renameat_paths(&root, from.as_path(), to.as_path()).map_err(|e| {
            Error::transport(format!(
                "rename {} -> {}: {e}",
                from.display(),
                to.display()
            ))
        })
    }

    #[cfg(not(unix))]
    fn symlink(&self, target: &Path, link: &RootedRelativePath) -> Result<()> {
        let root = crate::atomic::RootDir::open(&self.base)
            .map_err(|e| Error::transport(format!("symlink {}: {e}", link.display())))?;
        crate::atomic::symlink_fd(&root, target, link.as_path()).map_err(|e| {
            Error::transport(format!(
                "symlink {} -> {}: {e}",
                link.display(),
                target.display()
            ))
        })
    }

    /// Read the target of the symlink at `rel`, descriptor-relative on Unix:
    /// the parent is resolved COMPONENT-WISE with `openat(O_NOFOLLOW)` and the
    /// link is read with `readlinkat` on the pinned parent (never followed), so
    /// a symlink injected at any component is refused.
    #[cfg(unix)]
    fn read_link(&self, rel: &RootedRelativePath) -> Result<PathBuf> {
        let Some(root) = self.root_dir(false)? else {
            return Err(Error::transport(format!(
                "readlink {}: the destination root is absent",
                rel.display()
            )));
        };
        crate::atomic::read_link_fd(&root, rel.as_path())
            .map_err(|e| Error::transport(format!("readlink {}: {e}", rel.display())))
    }

    #[cfg(not(unix))]
    fn read_link(&self, rel: &RootedRelativePath) -> Result<PathBuf> {
        let p = join(&self.base, rel);
        std::fs::read_link(&p)
            .map_err(|e| Error::transport(format!("readlink {}: {e}", p.display())))
    }

    #[cfg(not(unix))]
    fn remove_file(&self, rel: &RootedRelativePath) -> Result<()> {
        // R4: route through the guarded atomic funnel (a missing entry is the
        // tolerated no-op).
        let root = crate::atomic::RootDir::open(&self.base)
            .map_err(|e| Error::transport(format!("remove {}: {e}", rel.display())))?;
        match crate::atomic::remove_file_fd(&root, rel.as_path()) {
            Ok(()) => Ok(()),
            // A confirmed absence is the tolerated no-op.
            Err(error) => match crate::atomic::path_kind_fd(&root, rel.as_path()) {
                Ok(None) => Ok(()),
                _ => Err(Error::transport(format!(
                    "remove {}: {error}",
                    rel.display()
                ))),
            },
        }
    }

    fn remove_file_if(&self, rel: &RootedRelativePath, expected: &[u8]) -> Result<RemoveIfVerdict> {
        // The sanctioned protocol may break EXACTLY the ONE record the layout
        // OWNS (see [`LocalTransport::guarded_mutation_target`]): the bare
        // `operation.lock`, a nested `snapshots/.001.operation.lock`, and any
        // other spelling are refused before any mutation, because claiming one
        // away would swap its inode and admit a second holder. The owned record
        // is serialized through the sidecar mutex so its compare-then-delete is
        // operation-atomic. The selection is IDENTITY-AWARE: a case alias that
        // resolves to the layout lock's OWN inode (macOS `state/OPERATION.LOCK`)
        // counts as the layout lock and takes the sidecar; a spelling that is a
        // DISTINCT on-disk entry (a trailing-dot alias, or a case alias on a
        // case-sensitive filesystem) is refused.
        let guarded = self.guarded_mutation_target(rel)?;
        if guarded.is_owned_lock_record() {
            return with_operation_lock_sidecar(&self.base, &self.layout.lock_sidecar, || {
                self.remove_file_if_inner(guarded, expected)
            });
        }
        self.remove_file_if_inner(guarded, expected)
    }

    fn try_write_new(&self, rel: &RootedRelativePath, data: &[u8]) -> Result<CreateNewVerdict> {
        let guarded = self.guarded_mutation_target(rel)?;
        if guarded.is_owned_lock_record() {
            return with_operation_lock_sidecar(&self.base, &self.layout.lock_sidecar, || {
                self.try_write_new_inner(guarded, data)
            });
        }
        self.try_write_new_inner(guarded, data)
    }

    fn try_write_new_with(
        &self,
        rel: &RootedRelativePath,
        data: &[u8],
        equivalence: ContentEquivalence,
    ) -> Result<CreateNewVerdict> {
        let guarded = self.guarded_mutation_target(rel)?;
        if guarded.is_owned_lock_record() {
            return with_operation_lock_sidecar(&self.base, &self.layout.lock_sidecar, || {
                self.try_write_new_with_inner(guarded, data, equivalence)
            });
        }
        self.try_write_new_with_inner(guarded, data, equivalence)
    }

    #[cfg(not(unix))]
    fn remove_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
        // R4: the Windows atomic guard (`refuse_lock_record_in_tree`) is now
        // reached through the funnel instead of being bypassed by a direct
        // `std::fs::remove_dir_all`. The funnel's own walk is iterative on
        // Windows (std), so the deep-tree guarantee is unchanged. A missing
        // entry is the idempotent no-op it always was.
        let root = crate::atomic::RootDir::open(&self.base)
            .map_err(|e| Error::transport(format!("rmdir {}: {e}", rel.display())))?;
        match crate::atomic::remove_dir_all_fd(&root, rel.as_path()) {
            Ok(()) => Ok(()),
            // A confirmed absence is the tolerated no-op.
            Err(error) => match crate::atomic::path_kind_fd(&root, rel.as_path()) {
                Ok(None) => Ok(()),
                _ => Err(Error::transport(format!(
                    "rmdir {}: {error}",
                    rel.display()
                ))),
            },
        }
    }

    #[cfg(not(unix))]
    fn remove_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        let root = crate::atomic::RootDir::open(&self.base)
            .map_err(|e| Error::transport(format!("rmdir {}: {e}", rel.display())))?;
        crate::atomic::remove_dir_fd(&root, rel.as_path())
            .map_err(|e| Error::transport(format!("rmdir {}: {e}", rel.display())))
    }

    fn fsync_tree(&self, rel: &RootedRelativePath) -> Result<()> {
        let root = join(&self.base, rel);
        // Every file is fsynced; directories are collected and fsynced
        // DEEPEST-FIRST (a parent's fsync runs only after every child's), so
        // the whole tree is durable before the atomic install rename.
        let mut dirs: Vec<PathBuf> = Vec::new();
        for entry in WalkDir::new(&root).into_iter() {
            let entry = entry.map_err(|e| Error::transport(format!("walk: {e}")))?;
            let p = entry.path();
            let meta = std::fs::symlink_metadata(p)
                .map_err(|e| Error::transport(format!("stat {}: {e}", p.display())))?;
            if meta.is_dir() {
                dirs.push(p.to_path_buf());
            } else if meta.is_file() {
                let f = std::fs::File::open(p)
                    .map_err(|e| Error::transport(format!("open {}: {e}", p.display())))?;
                f.sync_all()
                    .map_err(|e| Error::transport(format!("fsync {}: {e}", p.display())))?;
            }
        }
        dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
        for d in dirs {
            let f = std::fs::File::open(&d)
                .map_err(|e| Error::transport(format!("open dir {}: {e}", d.display())))?;
            f.sync_all()
                .map_err(|e| Error::transport(format!("fsync dir {}: {e}", d.display())))?;
        }
        Ok(())
    }

    fn fsync_parent(&self, rel: &RootedRelativePath) -> Result<()> {
        let p = join(&self.base, rel);
        let parent = p.parent().ok_or_else(|| {
            Error::transport(format!(
                "fsync parent of {}: no parent directory",
                p.display()
            ))
        })?;
        let dir = std::fs::File::open(parent)
            .map_err(|e| Error::transport(format!("open parent dir {}: {e}", parent.display())))?;
        dir.sync_all()
            .map_err(|e| Error::transport(format!("fsync parent dir {}: {e}", parent.display())))
    }

    /// The TRI-STATE existence check, descriptor-relative on Unix: `rel` is
    /// resolved component-wise with `O_NOFOLLOW` and the final component is
    /// `fstat`ed, so a symlink at any component is refused rather than followed.
    /// `bool` swallows the error by this trait's contract (callers that must
    /// distinguish a failure from absence use [`Remote::metadata_opt`], which is
    /// also descriptor-relative on Unix).
    #[cfg(unix)]
    fn exists(&self, rel: &RootedRelativePath) -> bool {
        match self.root_dir(false) {
            Ok(Some(root)) => self.confined_lstat(&root, rel).is_ok_and(|m| m.is_some()),
            _ => false,
        }
    }

    #[cfg(not(unix))]
    fn exists(&self, rel: &RootedRelativePath) -> bool {
        join(&self.base, rel).exists()
    }

    fn metadata(&self, rel: &RootedRelativePath) -> Result<RemoteMeta> {
        self.metadata_opt(rel)?.ok_or_else(|| {
            Error::NotFound(format!(
                "stat {}: not found",
                join(&self.base, rel).display()
            ))
        })
    }

    #[cfg(unix)]
    fn metadata_opt(&self, rel: &RootedRelativePath) -> Result<Option<RemoteMeta>> {
        let Some(root) = self.root_dir(false)? else {
            return Ok(None);
        };
        // A single component-wise `fstatat(AT_SYMLINK_NOFOLLOW)` — the FINAL
        // component is never opened and a link is never followed, so the size,
        // mode, and kind cannot be sourced from outside the pinned root.
        self.confined_lstat(&root, rel)
    }

    #[cfg(not(unix))]
    fn metadata_opt(&self, rel: &RootedRelativePath) -> Result<Option<RemoteMeta>> {
        let p = join(&self.base, rel);
        match std::fs::symlink_metadata(&p) {
            Ok(m) => Ok(Some(meta_to_remote(&m))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::transport(format!("stat {}: {e}", p.display()))),
        }
    }

    fn exec(&self, argv: &[String], timeout: Duration) -> Result<ExecOutcome> {
        if argv.is_empty() {
            return Err(Error::transport("empty command"));
        }
        // THE command-execution seam: production is the bounded child-runner
        // (spawn into an OWN process group, bounded wait, group termination,
        // mandatory reap before any outcome escapes); the deterministic
        // properties inject a scripted fake — same trait surface, no process.
        self.exec.exec(argv, timeout)
    }

    fn filesystem_bytes(&self) -> Result<FsBytes> {
        let mut cmd = std::process::Command::new("df");
        self.env.apply_to_command(&mut cmd);
        let out = cmd
            .args(["-k", self.base.to_string_lossy().as_ref()])
            .output()
            .map_err(|e| Error::transport(format!("df: {e}")))?;
        let text = String::from_utf8_lossy(&out.stdout);
        // Second line: Filesystem  blocks  used  avail  capacity  mount
        let line = text
            .lines()
            .nth(1)
            .ok_or_else(|| Error::transport("unexpected df output".to_string()))?;
        let cols: Vec<&str> = line.split_whitespace().collect();
        // blocks is the 2nd column and avail the 4th (1-indexed) on both
        // macOS and Linux; both are in 1024-byte units.
        let total_kb = cols
            .get(1)
            .and_then(|c| c.parse::<u64>().ok())
            .ok_or_else(|| Error::transport("could not parse df blocks".to_string()))?;
        let avail_kb = cols
            .get(3)
            .and_then(|c| c.parse::<u64>().ok())
            .ok_or_else(|| Error::transport("could not parse df avail".to_string()))?;
        Ok(FsBytes {
            total: total_kb * 1024,
            available: avail_kb * 1024,
        })
    }
}

impl LocalTransport {
    /// Mint the ONE capability every lock-record-breaking local mutation must
    /// present, through the guard's owned-lock-record constructor. It refuses
    /// every lock-record spelling EXCEPT the single layout lock the protocol
    /// OWNS, decided by IDENTITY (the layout lock's resolved device/inode) and
    /// not by a spelling fold, so a future `*_if`-style primitive cannot
    /// repeat the D1 hole: it either mints a capability (which runs the guard)
    /// or cannot call a mutation worker, whose argument is that capability.
    fn guarded_mutation_target<'a>(
        &self,
        rel: &'a RootedRelativePath,
    ) -> Result<crate::atomic::GuardedRel<'a>> {
        // The ownership authority is built from THIS transport's own layout,
        // never from the candidate path: the guard compares the candidate's
        // resolved (device, inode) against the layout lock's, so only the
        // record that IS the layout lock's on-disk entry is granted, and every
        // other lock-record spelling (including a case/dot alias that is a
        // distinct entry on this filesystem) is refused.
        let owned = crate::atomic::OwnedLockRecord::local(&self.base, &self.layout);
        crate::atomic::GuardedRel::new_for_owned_lock_record(rel.as_path(), &owned)
    }

    fn remove_file_if_inner(
        &self,
        guarded: crate::atomic::GuardedRel<'_>,
        expected: &[u8],
    ) -> Result<RemoveIfVerdict> {
        let p = self.base.join(guarded.as_path());
        // When already holding the sidecar (we are inside with_operation_lock_sidecar),
        // the mutation is already serialized, so a simple read-compare-unlink
        // keeps the record continuously visible for a mismatched remove (no
        // transient absence) and is safe from TOCTOU.
        if SIDECAR_DEPTH.with(|c| c.get() > 0) {
            let cur = match std::fs::read(&p) {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(RemoveIfVerdict::Absent);
                }
                Err(e) => return Err(Error::transport(format!("read {}: {e}", p.display()))),
            };
            if cur == expected {
                match std::fs::remove_file(&p) {
                    Ok(()) => return Ok(RemoveIfVerdict::Removed),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(RemoveIfVerdict::Absent);
                    }
                    Err(e) => return Err(Error::transport(format!("remove {}: {e}", p.display()))),
                }
            } else {
                return Ok(RemoveIfVerdict::Mismatch);
            }
        }
        use std::sync::atomic::{AtomicU64, Ordering};
        static CLAIM_COUNTER: AtomicU64 = AtomicU64::new(0);

        // Fallback claim path (when not under sidecar, e.g. non-lock paths
        // or direct calls): atomic rename claim, verify, delete or restore.
        // The atomic CLAIM target: a unique dot-prefixed name INSIDE the
        // destination's parent directory (same filesystem, same directory
        // namespace as the lock), exactly like durable_create_new's temps.
        // The marker is defined by the temp-name authority ([`crate::atomic`]),
        // so the claim temp and the classification of a claim temp as a TEMP
        // (rather than a reserved held-aside) can never disagree.
        let marker = crate::atomic::CLAIM_SUFFIX_MARKER;
        let suffix = format!(
            "{marker}{}.{}",
            std::process::id(),
            CLAIM_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let tmp = p.with_file_name(format!(
            ".{}{}",
            crate::atomic::bounded_temp_trunk(
                &p.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                &suffix,
            ),
            suffix,
        ));
        // CLAIM: rename the entry to the temp — atomic, so only ONE
        // contender can ever win the claim; every other breaker's rename
        // fails with NotFound (the slot was already claimed or free).
        match std::fs::rename(&p, &tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RemoveIfVerdict::Absent);
            }
            Err(e) => {
                return Err(Error::transport(format!("claim {}: {e}", p.display())));
            }
        }
        // VERIFY the claimed entry against the expectation.
        let content = match std::fs::read(&tmp) {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(Error::transport(format!("verify {}: {e}", tmp.display())));
            }
        };
        if content == expected {
            // MATCH: the claimed entry was EXACTLY the expected record —
            // delete it; the slot is now free.
            let _ = std::fs::remove_file(&tmp);
            return Ok(RemoveIfVerdict::Removed);
        }
        // MISMATCH: the entry changed under the reader (a successor's newer
        // generation). RESTORE it no-replace — the moved record is
        // re-created with the canonical final mode only while the path is
        // still free; a CONCURRENT install is never replaced (Conflict) and
        // the moved claim is discarded, never destroying the winner. Either
        // way a successor's lock survives untouched.
        let restored = durable_create_new(
            &self.base,
            guarded,
            &content,
            CreateNewOptions {
                mode: IMMUTABLE_RECORD_MODE,
                content: ContentEquivalence::Exact,
                fault: None,
            },
        );
        let _ = std::fs::remove_file(&tmp);
        match restored {
            // Created (restored), AlreadyPresent (a concurrent identical
            // restore), or Conflict (a different winner is in place): the
            // lock is intact — the compare failed, never a delete.
            Ok(_) => Ok(RemoveIfVerdict::Mismatch),
            // A transport failure on the no-replace restore propagates
            // EXPLICITLY (the moved claim was the only thing lost; the slot
            // is not blocked — the lease is the backstop).
            Err(e) => Err(e),
        }
    }

    fn try_write_new_inner(
        &self,
        guarded: crate::atomic::GuardedRel<'_>,
        data: &[u8],
    ) -> Result<CreateNewVerdict> {
        self.try_write_new_with_inner(guarded, data, ContentEquivalence::Exact)
    }

    fn try_write_new_with_inner(
        &self,
        guarded: crate::atomic::GuardedRel<'_>,
        data: &[u8],
        equivalence: ContentEquivalence,
    ) -> Result<CreateNewVerdict> {
        durable_create_new(
            &self.base,
            guarded,
            data,
            CreateNewOptions {
                mode: IMMUTABLE_RECORD_MODE,
                content: equivalence,
                fault: None,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    /// Mint the guard proof for an ordinary test path — the `durable_create_new`
    /// worker accepts only a [`crate::atomic::GuardedRel`], so tests present the
    /// capability just like production callers.
    fn guarded(rel: &RootedRelativePath) -> crate::atomic::GuardedRel<'_> {
        crate::atomic::GuardedRel::new(rel.as_path())
            .expect("an ordinary test path is not a lock record")
    }

    /// W1 — the LOCAL producer of the typed timeout cause, PINNED. A real child
    /// that outlives its deadline is killed and reaped by [`ChildRunner`], and
    /// [`Exec for ChildRunner`] (driven here through the REAL
    /// [`LocalTransport::exec`] entry point, i.e. the production
    /// [`ChildRunner`] the transport builds) must report `-1` WITH the typed
    /// [`TimeoutCause::CommandStillRunning`] cause. The mapping used to be
    /// unpinned: inverting it (or dropping the cause) left the suite green
    /// because no test ever asserted a producer's `Some(_)` cause. The local
    /// runner's post-exit drain failure is an ERROR, not an outcome, so
    /// `CommandStillRunning` is the ONLY cause this producer can emit.
    #[cfg(unix)]
    #[test]
    fn local_exec_deadline_kill_reports_the_typed_cause() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let base = dir.path().join("remote");
        std::fs::create_dir_all(&base).unwrap();
        let t = LocalTransport::new(&SysEnv::from_process(), base, Layout::empty()).unwrap();
        let deadline = std::time::Duration::from_millis(100);
        let out = t
            .exec(
                &["sh".into(), "-c".into(), "exec sleep 30".into()],
                deadline,
            )
            .expect("a stalled child must surface a timeout outcome, not an error");
        assert_eq!(
            out.exit_code, -1,
            "the deadline outcome keeps the -1 sentinel"
        );
        assert_eq!(
            out.timeout_cause,
            Some(TimeoutCause::CommandStillRunning),
            "the local runner's TimedOut must map to CommandStillRunning"
        );
    }

    /// DEFECT 1 (local half): a directory holding a name that is not valid
    /// UTF-8 must make `list` an ERROR, never a lossy `Ok`. Pre-fix
    /// `file_name().to_string_lossy()` mapped every non-UTF-8 name to U+FFFD,
    /// so two distinct on-disk names became one indistinguishable
    /// `RemoteEntry.name`; the byte-exact listing comparison then matched an
    /// intended entry while the destination held an extra, unaddressable one
    /// and `canonicalize_tree` refused the tree the run claimed to have
    /// produced.
    ///
    /// PLATFORM: a non-UTF-8 name cannot be created on APFS, so this SKIPS on
    /// macOS (announcing `STOREKIT_SKIP`); the reproduction requires a
    /// Linux/BSD filesystem.
    #[test]
    fn local_list_refuses_a_non_utf8_entry_name() {
        use std::os::unix::ffi::OsStringExt;
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let base = dir.path().join("remote");
        let tree = base.join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        let t = LocalTransport::new(&SysEnv::from_process(), base, Layout::empty()).unwrap();
        let root = RootedRelativePath::parse(Path::new("tree")).unwrap();

        // Two DIFFERENT names that both decode to U+FFFD under
        // `to_string_lossy` (0xff and 0xfe are both invalid standalone).
        let bad_a = std::ffi::OsString::from_vec(vec![0xff]);
        let bad_b = std::ffi::OsString::from_vec(vec![0xfe]);
        if let Err(e) = std::fs::write(tree.join(&bad_a), b"a") {
            crate::test_support::announce_skip(&format!(
                "the filesystem refuses a non-UTF-8 file name ({e}), so the lossy-listing reproduction cannot run here; run it on Linux"
            ));
            return;
        }
        std::fs::write(tree.join(&bad_b), b"b").unwrap();

        let err = t
            .list(&root)
            .expect_err("a non-UTF-8 entry name must make the listing an error, never a lossy Ok");
        let msg = err.to_string();
        assert!(
            msg.contains("not valid UTF-8"),
            "the error must name the reason (not valid UTF-8), got: {msg}"
        );
        assert!(
            msg.contains("tree"),
            "the error must name the entry/directory, got: {msg}"
        );
    }

    /// Control for the refusal above: an ordinary UTF-8 directory still lists
    /// faithfully (the fail-closed change must not refuse valid names).
    #[test]
    fn local_list_still_lists_ordinary_names() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let base = dir.path().join("remote");
        let tree = base.join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("a b"), b"x").unwrap();
        std::fs::write(tree.join(".hidden"), b"x").unwrap();
        let t = LocalTransport::new(&SysEnv::from_process(), base, Layout::empty()).unwrap();
        let mut names: Vec<String> = t
            .list(&RootedRelativePath::parse(Path::new("tree")).unwrap())
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        names.sort();
        assert_eq!(names, vec![".hidden".to_string(), "a b".to_string()]);
    }

    /// DEFECT 2 control (local half): the LOCAL `read_link` is raw — a target
    /// that leads and/or trails with whitespace comes back verbatim. The SSH
    /// side must match these exact bytes (see `parse_readlink_output_strips_`
    /// `exactly_one_newline` in the ssh suite); the pre-fix `.trim()` there
    /// returned `"x"` for this local `"x "`.
    #[test]
    fn local_read_link_returns_the_target_bytes_verbatim() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let base = dir.path().join("remote");
        let tree = base.join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        let t = LocalTransport::new(&SysEnv::from_process(), base, Layout::empty()).unwrap();
        for (i, target) in [" x", "x ", " x ", "a b"].iter().enumerate() {
            let name = format!("link{i}");
            std::os::unix::fs::symlink(target, tree.join(&name)).unwrap();
            let rel = RootedRelativePath::parse(Path::new(&format!("tree/{name}"))).unwrap();
            assert_eq!(
                t.read_link(&rel).unwrap(),
                PathBuf::from(target),
                "the local read_link must return {target:?} verbatim"
            );
        }
    }

    /// R1 — the transport's symlink CANNOT destroy the lock record. Pre-fix
    /// `symlink_confined` removed any existing entry at the link path with a
    /// raw `unlinkat` and installed a symlink, so a caller could acquire the
    /// lock, symlink OVER the record, and acquire a SECOND lock with a
    /// different inode. Now the transport routes through the guarded
    /// `atomic::symlink_fd`, so the operation is refused and the record (and
    /// its inode) is untouched. PRE-FIX MESSAGE: the call returned `Ok(())`,
    /// the record was gone, and a second `FileLock::acquire` SUCCEEDED.
    #[cfg(unix)]
    #[test]
    fn symlink_over_the_lock_record_is_refused_and_leaves_the_record_intact() {
        use std::os::unix::fs::MetadataExt;
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let base = dir.path().join("remote");
        std::fs::create_dir_all(&base).unwrap();
        let record = base.join(crate::reserved::APPLICATION_LOCK_NAME);
        std::fs::write(&record, b"HELD").unwrap();
        let inode_before = std::fs::symlink_metadata(&record).unwrap().ino();
        let t = LocalTransport::new(&SysEnv::from_process(), base, Layout::empty()).unwrap();
        let rel =
            RootedRelativePath::parse(Path::new(crate::reserved::APPLICATION_LOCK_NAME)).unwrap();
        let err = t
            .symlink(Path::new("somewhere"), &rel)
            .expect_err("a symlink over the lock record must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("lock record"),
            "the refusal must name the lock record, got: {msg}"
        );
        let meta = std::fs::symlink_metadata(&record)
            .expect("the record must still exist after the refused symlink");
        assert!(
            !meta.file_type().is_symlink(),
            "the record must not be a symlink"
        );
        assert_eq!(
            meta.ino(),
            inode_before,
            "the record's inode must not change"
        );
        assert_eq!(std::fs::read(&record).unwrap(), b"HELD".to_vec());
    }

    /// The deploy_dir's IMMUTABLE receiver-id marker: `provision_layout`
    /// creates it ONCE (stored as `<id>\n`), a re-provisioning adopts the
    /// SAME identity (never a new one), and `read_receiver_id` reads it back.
    #[test]
    fn provision_layout_creates_immutable_receiver_id() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let marker = RootedRelativePath::parse(Path::new("receiver-marker")).unwrap();
        let layout = Layout {
            receiver_marker: Some(marker.clone()),
            ..Layout::empty()
        };
        let t = LocalTransport::new(
            &SysEnv::from_process(),
            dir.path().join("r"),
            layout.clone(),
        )
        .unwrap();
        t.provision_layout().unwrap();
        assert!(
            t.exists(&marker),
            "provisioning creates the receiver-id marker"
        );
        let first = read_receiver_id(&t, &marker).expect("the marker reads back");
        assert_eq!(
            first.as_str().len(),
            RECEIVER_ID_LEN,
            "the marker carries a 40-hex receiver id, got {:?}",
            first.as_str()
        );
        assert!(
            first
                .as_str()
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "the receiver id is lowercase hex, got {:?}",
            first.as_str()
        );
        // The wire form is `<id>\n`.
        assert_eq!(
            t.read(&marker).unwrap(),
            format!("{}\n", first.as_str()).into_bytes(),
            "the marker is stored as <id>\\n"
        );
        // Re-provisioning (a second push to the same deploy_dir) adopts the
        // SAME immutable identity — never a new one.
        t.provision_layout().unwrap();
        let second = read_receiver_id(&t, &marker).expect("the marker reads back");
        assert_eq!(
            first, second,
            "the receiver id is IMMUTABLE: re-provisioning adopts the existing marker"
        );
        // A pre-existing marker with DIFFERENT content is adopted too (the
        // first writer wins — the physical identity is whatever was created
        // first), and a malformed marker fails closed.
        let t2 = LocalTransport::new(
            &SysEnv::from_process(),
            dir.path().join("r2"),
            layout.clone(),
        )
        .unwrap();
        t2.provision_layout().unwrap();
        let foreign = ReceiverId::generate().expect("entropy for a receiver id");
        t2.write(&marker, &foreign.wire_bytes(), 0o644).unwrap();
        t2.provision_layout().unwrap();
        assert_eq!(
            read_receiver_id(&t2, &marker).expect("the existing marker is adopted"),
            foreign,
            "a re-provisioning never replaces the existing marker"
        );
        let t3 =
            LocalTransport::new(&SysEnv::from_process(), dir.path().join("r3"), layout).unwrap();
        t3.provision_layout().unwrap();
        t3.write(&marker, b"not-a-receiver-id", 0o644).unwrap();
        read_receiver_id(&t3, &marker).expect_err("a malformed marker fails closed");
    }

    /// A marker in the SOURCE TOOL's legacy format (`recv-<uuid-v7>`, written
    /// by `~/code/deploy`'s `ids.rs` before this crate's 40-hex format) fails
    /// closed, and the error is ACTIONABLE: it names the condition (not a
    /// 40-hex receiver id) and the likely cause (a marker that predates this
    /// crate's format), so an operator hitting it during a migration can
    /// diagnose it without reading this crate's source. The error class is
    /// unchanged (`transport`).
    #[test]
    fn a_legacy_recv_marker_fails_closed_with_an_actionable_error() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let marker = RootedRelativePath::parse(Path::new("receiver-marker")).unwrap();
        let layout = Layout {
            receiver_marker: Some(marker.clone()),
            ..Layout::empty()
        };
        let t = LocalTransport::new(&SysEnv::from_process(), dir.path().join("legacy"), layout)
            .unwrap();
        t.provision_layout().unwrap();
        // The source tool's spelling: `recv-` plus a UUID v7 (lowercase hex,
        // dashed).
        let legacy = b"recv-0190f3c2-7a1e-7b3c-8d4f-0123456789ab\n";
        t.write(&marker, legacy, 0o644).unwrap();
        let err = read_receiver_id(&t, &marker)
            .expect_err("a legacy recv-<uuid-v7> marker must fail closed");
        assert!(
            matches!(err, Error::Transport(_)),
            "the marker refusal keeps the transport error class, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("not a 40-character lowercase-hex receiver id"),
            "the error must name the condition, got: {msg}"
        );
        assert!(
            msg.contains("predates this crate") && msg.contains("recv-<uuid-v7>"),
            "the error must name the likely legacy cause, got: {msg}"
        );
        // A VALID marker still reads back (the actionable refusal did not
        // break the success path).
        let good = ReceiverId::generate().expect("entropy for a receiver id");
        t.write(&marker, &good.wire_bytes(), 0o644).unwrap();
        assert_eq!(
            read_receiver_id(&t, &marker).expect("a valid marker still reads"),
            good
        );
    }

    /// Concurrent readers must only ever observe the destination file fully
    /// written: installs happen by hard-linking a synced, complete temporary
    /// inode, so a partial record is unrepresentable.
    #[test]
    fn try_write_new_concurrent_readers_never_observe_partial_content() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};

        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let t = LocalTransport::new(
            &SysEnv::from_process(),
            dir.path().join("r"),
            Layout::empty(),
        )
        .unwrap();
        let markers = dir.path().join("r/markers");
        const PAYLOAD: &str =
            r#"{"committed":true,"generation":"gen-1","servers":["server-01","server-02"]}"#;

        // Set even if the writer panics (Drop runs during unwind), so the
        // readers always terminate instead of hanging the test binary.
        struct DoneGuard(Arc<AtomicBool>);
        impl Drop for DoneGuard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        std::thread::scope(|s| {
            let done = Arc::new(AtomicBool::new(false));
            let writer_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

            {
                let done = done.clone();
                let writer_error = writer_error.clone();
                s.spawn(move || {
                    let _done = DoneGuard(done);
                    for i in 0..100 {
                        let rel = RootedRelativePath::parse(
                            &Path::new("markers").join(format!("m{i}.json")),
                        )
                        .unwrap();
                        if let Err(e) = t.try_write_new(&rel, PAYLOAD.as_bytes()) {
                            *writer_error.lock().unwrap() = Some(e.to_string());
                            return;
                        }
                    }
                });
            }
            for _ in 0..2 {
                let done = done.clone();
                let markers = markers.clone();
                s.spawn(move || {
                    while !done.load(Ordering::SeqCst) {
                        let Ok(entries) = std::fs::read_dir(&markers) else {
                            continue;
                        };
                        for e in entries.flatten() {
                            // Temporary files are dot-prefixed precisely so that
                            // listing-based observers can skip them; a real
                            // reader of a marker path never touches them.
                            if e.file_name().to_string_lossy().starts_with('.') {
                                continue;
                            }
                            let data = std::fs::read(e.path()).unwrap_or_default();
                            assert_eq!(
                                String::from_utf8_lossy(&data).as_ref(),
                                PAYLOAD,
                                "partial marker observed by concurrent reader"
                            );
                        }
                    }
                });
            }

            // The writer must have completed every install successfully.
            assert_eq!(
                writer_error.lock().unwrap().as_deref(),
                None,
                "writer failed to install all markers"
            );
        });

        // Every marker installed exactly once with full content.
        for i in 0..100 {
            let data = std::fs::read(markers.join(format!("m{i}.json"))).unwrap();
            assert_eq!(String::from_utf8_lossy(&data).as_ref(), PAYLOAD);
        }
    }

    #[test]
    fn new_refuses_root_deploy_dir() {
        // The filesystem root (and any form that normalizes to it) is
        // refused at construction: a transport rooted at `/` would make the
        // deployment cleanup operate on the system root.
        for bad in ["/", "//", "/./", "/../"] {
            let err = LocalTransport::new(
                &SysEnv::from_process(),
                std::path::PathBuf::from(bad),
                Layout::empty(),
            )
            .err()
            .unwrap_or_else(|| panic!("root deploy_dir {bad:?} must be refused"));
            assert!(
                err.to_string()
                    .contains("at least one normal path component"),
                "error must name the rule, got: {err}"
            );
        }
        // A deploy_dir with at least one normal component below the root is
        // accepted (construction stays side-effect-free).
        for ok in ["/srv", "/srv/app/", "/srv//app"] {
            LocalTransport::new(
                &SysEnv::from_process(),
                std::path::PathBuf::from(ok),
                Layout::empty(),
            )
            .expect("a deploy_dir with a normal component below the root is accepted");
        }
    }

    #[test]
    fn symlink_rename_exists() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let t = LocalTransport::new(
            &SysEnv::from_process(),
            dir.path().join("r"),
            Layout::empty(),
        )
        .unwrap();
        t.create_dir_all(&RootedRelativePath::parse(Path::new("generations/gen1")).unwrap())
            .unwrap();
        t.symlink(
            Path::new("generations/gen1"),
            &RootedRelativePath::parse(Path::new(".tmp.x")).unwrap(),
        )
        .unwrap();
        assert!(
            t.exists(&RootedRelativePath::parse(Path::new(".tmp.x")).unwrap()),
            "symlink should exist"
        );
        t.rename(
            &RootedRelativePath::parse(Path::new(".tmp.x")).unwrap(),
            &RootedRelativePath::parse(Path::new("current")).unwrap(),
        )
        .unwrap();
        assert!(
            t.exists(&RootedRelativePath::parse(Path::new("current")).unwrap()),
            "current should exist after rename"
        );
        let target = t
            .read_link(&RootedRelativePath::parse(Path::new("current")).unwrap())
            .unwrap();
        assert_eq!(target, Path::new("generations/gen1"));
    }

    /// The `LocalTransport` operations the applier issues resolve
    /// COMPONENT-WISE with `openat(O_NOFOLLOW)` from an fd-pinned root: a
    /// symlink injected at a PARENT component is refused for every one of
    /// them, and the OUTSIDE tree is never touched. This is the same
    /// no-window guarantee the fd-confined `Side::Local` destination gives.
    #[cfg(unix)]
    #[test]
    fn local_transport_refuses_a_parent_component_symlink_for_every_mutation() {
        use std::os::unix::fs::symlink;
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let base = dir.path().join("r");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(outside.join("x"), b"OUTSIDE").unwrap();
        std::fs::create_dir_all(outside.join("sub")).unwrap();
        symlink(&outside, base.join("link")).unwrap();

        let t =
            LocalTransport::new(&SysEnv::from_process(), base.clone(), Layout::empty()).unwrap();
        let link = RootedRelativePath::parse(Path::new("link")).unwrap();
        let link_x = RootedRelativePath::parse(Path::new("link/x")).unwrap();
        let link_sub = RootedRelativePath::parse(Path::new("link/sub")).unwrap();
        let link_new = RootedRelativePath::parse(Path::new("link/new")).unwrap();

        assert!(t.list(&link).is_err(), "list must refuse a symlinked root");
        assert!(
            t.write(&link_new, b"nope", 0o644).is_err(),
            "write must refuse a symlinked parent"
        );
        assert!(
            t.create_dir_all(&link_sub).is_err(),
            "create_dir_all must refuse a symlinked parent"
        );
        assert!(
            t.set_mode(&link_x, 0o600).is_err(),
            "set_mode must refuse a symlinked parent"
        );
        assert!(
            t.symlink(Path::new("t"), &link_new).is_err(),
            "symlink must refuse a symlinked parent"
        );
        assert!(
            t.remove_file(&link_x).is_err(),
            "remove_file must refuse a symlinked parent"
        );
        assert!(
            t.remove_dir_all(&link_sub).is_err(),
            "remove_dir_all must refuse a symlinked parent"
        );
        assert!(
            t.rename(&link_x, &link_new).is_err(),
            "rename must refuse a symlinked parent"
        );

        // Nothing outside was created, changed, or destroyed, and the link is
        // still a link.
        assert_eq!(std::fs::read(outside.join("x")).unwrap(), b"OUTSIDE");
        assert!(outside.join("sub").is_dir());
        assert!(!outside.join("new").exists());
        assert!(
            std::fs::symlink_metadata(base.join("link"))
                .unwrap()
                .is_symlink()
        );
    }

    /// FINDING 4/5: the READS the applier verifies against are descriptor-relative
    /// too. Pre-fix `read`, `read_link`, `exists`, and `metadata_opt` were
    /// PATH-based (`std::fs::read`/`read_link`/`exists`/`symlink_metadata`), so a
    /// symlink injected at a PARENT component made them FOLLOW it: a content
    /// hash — and therefore an `applied` verdict — could be computed from an
    /// object OUTSIDE the pinned root. Each must now refuse a symlinked parent,
    /// and the outside bytes must never be returned.
    #[cfg(unix)]
    #[test]
    fn local_transport_refuses_a_parent_component_symlink_for_every_read() {
        use std::os::unix::fs::symlink;
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let base = dir.path().join("r");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(outside.join("planted"), b"OUTSIDE-CONTENT").unwrap();
        std::fs::create_dir_all(outside.join("sub")).unwrap();
        symlink("OUTSIDE-TARGET", outside.join("slink")).unwrap();
        symlink(&outside, base.join("link")).unwrap();

        let t =
            LocalTransport::new(&SysEnv::from_process(), base.clone(), Layout::empty()).unwrap();
        let link_planted = RootedRelativePath::parse(Path::new("link/planted")).unwrap();
        let link_slink = RootedRelativePath::parse(Path::new("link/slink")).unwrap();

        assert!(
            t.read(&link_planted).is_err(),
            "read must refuse a symlinked parent"
        );
        assert!(
            t.read_link(&link_slink).is_err(),
            "read_link must refuse a symlinked parent"
        );
        assert!(
            !t.exists(&link_planted),
            "exists must refuse a symlinked parent, never follow it"
        );
        assert!(
            t.metadata_opt(&link_planted).is_err(),
            "metadata_opt must refuse a symlinked parent"
        );
        assert!(
            t.metadata(&link_planted).is_err(),
            "metadata must refuse a symlinked parent"
        );
        // The outside file's bytes were never returned and it is untouched.
        assert_eq!(
            std::fs::read(outside.join("planted")).unwrap(),
            b"OUTSIDE-CONTENT"
        );
    }

    /// The busy-writer TOCTOU class check, re-run against the confinement fix: a
    /// writer thread continuously swaps the `d` component between a real
    /// directory and a symlink to an outside tree while the main thread issues
    /// every guarded operation. No write may land outside the root and no read
    /// may return outside content, whatever order the swap and the syscall
    /// interleave in.
    #[cfg(unix)]
    #[test]
    fn a_busy_component_swapper_never_redirects_a_confinement_guarded_operation() {
        use std::os::unix::fs::symlink;
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let base = dir.path().join("r");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(base.join("d")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("planted"), b"OUTSIDE-CONTENT").unwrap();

        let t =
            LocalTransport::new(&SysEnv::from_process(), base.clone(), Layout::empty()).unwrap();
        let rel_x = RootedRelativePath::parse(Path::new("d/x")).unwrap();
        let rel_planted = RootedRelativePath::parse(Path::new("d/planted")).unwrap();

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = {
            let stop = std::sync::Arc::clone(&stop);
            let base = base.clone();
            let outside = outside.clone();
            std::thread::spawn(move || {
                let mut swaps = 0usize;
                while !stop.load(std::sync::atomic::Ordering::SeqCst) && swaps < 200 {
                    let _ = std::fs::remove_dir_all(base.join("d"));
                    let _ = symlink(&outside, base.join("d"));
                    let _ = std::fs::remove_file(base.join("d"));
                    let _ = std::fs::create_dir_all(base.join("d"));
                    swaps += 1;
                }
            })
        };

        let mut ops = 0usize;
        while ops < 200 {
            let _ = t.write(&rel_x, b"IN-ROOT", 0o644);
            if let Ok(bytes) = t.read(&rel_planted) {
                assert_ne!(
                    bytes.as_slice(),
                    b"OUTSIDE-CONTENT",
                    "a read escaped the pinned root and returned OUTSIDE content"
                );
            }
            let _ = t.exists(&rel_planted);
            let _ = t.metadata_opt(&rel_planted);
            assert!(
                !outside.join("x").exists(),
                "a confinement-guarded write escaped the pinned root"
            );
            ops += 1;
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        writer.join().unwrap();
        assert_eq!(
            std::fs::read(outside.join("planted")).unwrap(),
            b"OUTSIDE-CONTENT",
            "the outside tree was never written through"
        );
    }

    /// The transport-level contract of the shared primitive: `try_write_new`
    /// reports `Ok(Created)` for a fresh DURABLE install, `Ok(AlreadyPresent)`
    /// for an identical retry (convergent — the winner is verified
    /// byte-and-mode identical, never replaced), and `Ok(Conflict)` for a
    /// different-content OR different-mode winner (the winner is never
    /// touched; the caller's read-back comparison decides the semantic
    /// verdict). The TYPED verdict survives the trait boundary — no bool
    /// collapse. The installed record carries the canonical final mode, not
    /// the process umask.
    #[test]
    fn try_write_new_durable_install_and_conflict_contract() {
        use std::os::unix::fs::MetadataExt;

        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let t = LocalTransport::new(
            &SysEnv::from_process(),
            dir.path().join("r"),
            Layout::empty(),
        )
        .unwrap();
        let rel = RootedRelativePath::parse(Path::new("state/op.json")).unwrap();
        let data = b"{\"op\":\"1\"}";

        assert_eq!(
            t.try_write_new(&rel, data).unwrap(),
            CreateNewVerdict::Created,
            "a fresh install wins"
        );
        let p = t.root().join(rel.as_path());
        assert_eq!(std::fs::read(&p).unwrap(), data, "exact bytes installed");
        assert_eq!(
            std::fs::metadata(&p).unwrap().mode() & 0o7777,
            IMMUTABLE_RECORD_MODE & 0o7777,
            "the record must carry the canonical final mode"
        );
        // Identical retry: convergent — AlreadyPresent, no error, no replace.
        assert_eq!(
            t.try_write_new(&rel, data).unwrap(),
            CreateNewVerdict::AlreadyPresent,
            "an identical retry converges to already-present"
        );
        assert_eq!(
            std::fs::read(&p).unwrap(),
            data,
            "the identical retry must not touch the winner"
        );
        // Different content: the conflict verdict — never replaced.
        assert!(
            matches!(
                t.try_write_new(&rel, b"other").unwrap(),
                CreateNewVerdict::Conflict(VerifiedExisting::ContentMismatch)
            ),
            "a different-content conflict is the verdict"
        );
        assert_eq!(
            std::fs::read(&p).unwrap(),
            data,
            "the conflict must NEVER replace the winner"
        );
    }

    /// The compare-and-delete primitive's contract: `Removed` for a
    /// byte-identical match (the entry is gone), `Mismatch` for different
    /// content (the winner is RESTORED — never removed, never replaced),
    /// and `Absent` for genuine absence. This is the primitive the mutation
    /// lock's stale-release/expired-break safety rests on.
    #[test]
    fn remove_file_if_compare_and_delete_verdicts() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let t = LocalTransport::new(
            &SysEnv::from_process(),
            dir.path().join("r"),
            Layout::empty(),
        )
        .unwrap();
        let rel = RootedRelativePath::parse(Path::new("state/op.lock")).unwrap();
        let data = b"{\"owner\":\"a\",\"token\":1}";

        // Absent: nothing to remove — the idempotent verdict.
        assert_eq!(
            t.remove_file_if(&rel, data).unwrap(),
            RemoveIfVerdict::Absent,
            "a genuinely absent entry is Absent, never an error"
        );
        // Match: the entry carried EXACTLY the expected bytes — removed.
        t.try_write_new(&rel, data).unwrap();
        assert_eq!(
            t.remove_file_if(&rel, data).unwrap(),
            RemoveIfVerdict::Removed,
            "a byte-identical match is removed"
        );
        assert!(
            t.metadata_opt(&rel).unwrap().is_none(),
            "the matched entry must be gone"
        );
        // Mismatch: different content — the winner is restored untouched,
        // NEVER removed, NEVER replaced.
        t.try_write_new(&rel, data).unwrap();
        assert_eq!(
            t.remove_file_if(&rel, b"{\"owner\":\"b\",\"token\":2}")
                .unwrap(),
            RemoveIfVerdict::Mismatch,
            "different content is a Mismatch, never a delete"
        );
        assert_eq!(
            t.read(&rel).unwrap(),
            data,
            "the mismatch must restore the winner byte-for-byte"
        );
    }

    /// D1 — the sanctioned lock protocol may break EXACTLY the record it OWNS.
    /// `remove_file_if` used to route through the sidecar only for the
    /// byte-exact layout lock and to fall back to the claim-by-rename path for
    /// every other spelling, so a caller could claim away `operation.lock` or
    /// `snapshots/.001.operation.lock`: the claim RENAMED the live record away
    /// and (on a mismatch) re-published it via `hard_link` under a NEW inode,
    /// splitting the holder. Each row below holds a `FileLock`, calls
    /// `remove_file_if`, and asserts the record's INODE is unchanged and a
    /// second `FileLock` is REFUSED. Pre-fix the inode assertion is the
    /// two-holder reproduction: the record is re-created under a fresh inode,
    /// or (on a byte-identical expectation) removed outright.
    #[cfg(unix)]
    #[test]
    fn remove_file_if_refuses_a_lock_record_it_does_not_own() {
        use crate::error::Error;
        use std::os::unix::fs::MetadataExt;

        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let base = dir.path().join("r");
        let t =
            LocalTransport::new(&SysEnv::from_process(), base.clone(), Layout::empty()).unwrap();

        for (label, rel_text) in [
            ("the bare application lock record", "operation.lock"),
            ("a nested sibling record", "snapshots/.001.operation.lock"),
        ] {
            let record = base.join(rel_text);
            let holder = crate::lock::FileLock::acquire(&record, "A")
                .unwrap_or_else(|e| panic!("{label}: acquire A: {e}"));
            let before = std::fs::metadata(&record)
                .unwrap_or_else(|e| panic!("{label}: stat before: {e}"))
                .ino();
            let rel = RootedRelativePath::parse(Path::new(rel_text)).unwrap();
            let current = std::fs::read(&record).unwrap();
            for expected in [b"wrong".as_slice(), current.as_slice()] {
                let verdict = t.remove_file_if(&rel, expected);
                let after = std::fs::metadata(&record).ok().map(|m| m.ino());
                assert_eq!(
                    after,
                    Some(before),
                    "{label}: remove_file_if on {rel_text:?} with expected {expected:?} must leave \
                     the record's inode unchanged — pre-fix the claim renamed the live record away \
                     and re-published it under a NEW inode (or removed it), admitting a second holder"
                );
                assert!(
                    verdict.is_err(),
                    "{label}: a lock record the protocol does not own must be REFUSED, got {verdict:?}"
                );
                let second = crate::lock::FileLock::acquire(&record, "B");
                assert!(
                    matches!(&second, Err(Error::LockContended(_))),
                    "{label}: a second FileLock::acquire on {rel_text:?} must stay contended"
                );
            }
            drop(holder);
        }
    }

    /// D1's sibling primitive: `try_write_new` shares the same guard gate, so it
    /// also refuses a lock record the layout does not own. Pre-fix it went
    /// straight to `durable_create_new`; the refusal keeps the protocol's reach
    /// at ONE record.
    #[cfg(unix)]
    #[test]
    fn try_write_new_refuses_a_lock_record_it_does_not_own() {
        use crate::error::Error;
        use std::os::unix::fs::MetadataExt;

        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let base = dir.path().join("r");
        let t =
            LocalTransport::new(&SysEnv::from_process(), base.clone(), Layout::empty()).unwrap();
        let record = base.join("operation.lock");
        let _holder = crate::lock::FileLock::acquire(&record, "A").unwrap();
        let before = std::fs::metadata(&record).unwrap().ino();
        let rel = RootedRelativePath::parse(Path::new("operation.lock")).unwrap();
        let verdict = t.try_write_new(&rel, b"x");
        assert!(
            verdict.is_err(),
            "a lock record the protocol does not own must be REFUSED, got {verdict:?}"
        );
        assert_eq!(
            std::fs::metadata(&record).unwrap().ino(),
            before,
            "the refused install must not touch the record's inode"
        );
        let second = crate::lock::FileLock::acquire(&record, "B");
        assert!(
            matches!(&second, Err(Error::LockContended(_))),
            "the record must stay locked"
        );
    }

    /// D2 (identity) — the owned-record selection is decided by IDENTITY, not
    /// by a spelling fold. Runs on macOS AND Linux with NO skip.
    ///
    /// * Where `state/OPERATION.LOCK` resolves to the SAME inode as
    ///   `state/operation.lock` (macOS APFS), the alias IS the owned record: the
    ///   mutation takes the sidecar route (a mismatch is a Mismatch, the inode
    ///   stays, a second holder is refused) and the sanctioned break works
    ///   through the alias.
    /// * Where it is a DISTINCT entry (any case-sensitive filesystem), the
    ///   mutation is REFUSED before anything runs, the owned record's inode is
    ///   unchanged, a second holder is refused, and the legitimate break of the
    ///   OWNED spelling still works. Pre-fix the fold granted ownership to the
    ///   distinct entry; `remove_file_if_grants_ownership_only_to_the_owned_inode`
    ///   additionally makes that distinct entry a live second holder.
    #[cfg(unix)]
    #[test]
    fn remove_file_if_decides_the_owned_record_by_identity_not_by_a_fold() {
        use crate::error::Error;
        use std::os::unix::fs::MetadataExt;

        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let base = dir.path().join("r");
        let t =
            LocalTransport::new(&SysEnv::from_process(), base.clone(), Layout::empty()).unwrap();
        let record = base.join("state/operation.lock");
        let holder = crate::lock::FileLock::acquire(&record, "A").unwrap();
        let before = std::fs::metadata(&record).unwrap().ino();
        let alias = base.join("state/OPERATION.LOCK");
        let same_entry = std::fs::metadata(&alias)
            .map(|m| m.ino())
            .is_ok_and(|ino| ino == before);
        let rel = RootedRelativePath::parse(Path::new("state/OPERATION.LOCK")).unwrap();
        if same_entry {
            // macOS: the alias IS the owned record (same inode) -> sidecar.
            assert_eq!(
                t.remove_file_if(&rel, b"not-the-record").unwrap(),
                RemoveIfVerdict::Mismatch,
                "the same-inode alias must be the owned record (sidecar route)"
            );
            assert_eq!(
                std::fs::metadata(&record).unwrap().ino(),
                before,
                "the mismatched compare must not touch the record's inode"
            );
            let second = crate::lock::FileLock::acquire(&record, "B");
            assert!(
                matches!(&second, Err(Error::LockContended(_))),
                "a second holder must stay contended"
            );
            let current = std::fs::read(&record).unwrap();
            assert_eq!(
                t.remove_file_if(&rel, &current).unwrap(),
                RemoveIfVerdict::Removed,
                "a matching alias removal is the sanctioned owned-record break"
            );
            assert!(!record.exists(), "the sanctioned break removes the record");
        } else {
            // Case-sensitive filesystem: the alias is a DISTINCT entry.
            let err = t
                .remove_file_if(&rel, b"not-the-record")
                .expect_err("a distinct on-disk entry must be REFUSED, never granted ownership");
            let msg = format!("{err}");
            assert!(
                msg.contains("lock record"),
                "the refusal must name the lock record, got: {msg}"
            );
            assert_eq!(
                std::fs::metadata(&record).unwrap().ino(),
                before,
                "the refused alias must not touch the owned record's inode"
            );
            let second = crate::lock::FileLock::acquire(&record, "B");
            assert!(
                matches!(&second, Err(Error::LockContended(_))),
                "the owned record must stay contended"
            );
            // The owned spelling is still the legitimate, sanctioned break.
            let current = std::fs::read(&record).unwrap();
            let owned_rel = RootedRelativePath::parse(Path::new("state/operation.lock")).unwrap();
            assert_eq!(
                t.remove_file_if(&owned_rel, &current).unwrap(),
                RemoveIfVerdict::Removed,
                "the legitimate break of the owned record still works"
            );
            assert!(!record.exists(), "the sanctioned break removes the record");
        }
        drop(holder);
    }

    /// F1 — ownership is granted by IDENTITY, not by a fold. For each lock-record
    /// alias that is a DISTINCT on-disk entry on this filesystem, make it a live
    /// second holder, then assert `remove_file_if` is REFUSED and neither entry's
    /// inode moves. For an alias that resolves to the owned record's OWN inode
    /// (macOS case aliases), assert the sidecar route still authorizes the break.
    ///
    /// Pre-fix, the fold granted ownership to every row, so the sidecar/claim
    /// route removed the DISTINCT alias entry — freeing the second holder's inode
    /// and admitting a third acquisition. Every assertion below fails pre-fix on
    /// macOS (trailing dot/space) and Linux (case and trailing dot/space alike).
    #[cfg(unix)]
    #[test]
    fn remove_file_if_grants_ownership_only_to_the_owned_inode() {
        use crate::error::Error;
        use std::os::unix::fs::MetadataExt;

        for (case, alias_text) in [
            ("trailing-dot", "state/operation.lock."),
            ("trailing-space", "state/operation.lock "),
            ("case", "state/OPERATION.LOCK"),
            ("dir-case", "STATE/operation.lock"),
        ] {
            let dir =
                crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
            let base = dir.path().join("r");
            let t = LocalTransport::new(&SysEnv::from_process(), base.clone(), Layout::empty())
                .unwrap();
            let record = base.join("state/operation.lock");
            let holder = crate::lock::FileLock::acquire(&record, "A").unwrap();
            let record_ino = std::fs::metadata(&record).unwrap().ino();
            let alias = base.join(alias_text);
            let alias_same_entry = std::fs::metadata(&alias)
                .map(|m| m.ino())
                .is_ok_and(|ino| ino == record_ino);
            let rel = RootedRelativePath::parse(Path::new(alias_text)).unwrap();
            if alias_same_entry {
                // The alias IS the owned entry: the sidecar route authorizes it.
                let before = std::fs::metadata(&record).unwrap().ino();
                assert_eq!(
                    t.remove_file_if(&rel, b"not-the-record").unwrap(),
                    RemoveIfVerdict::Mismatch,
                    "{case}: a same-inode alias is the owned record (sidecar route)"
                );
                assert_eq!(
                    std::fs::metadata(&record).unwrap().ino(),
                    before,
                    "{case}: the mismatched compare leaves the record's inode intact"
                );
                let second = crate::lock::FileLock::acquire(&record, "B");
                assert!(
                    matches!(&second, Err(Error::LockContended(_))),
                    "{case}: a second holder must stay contended"
                );
                let current = std::fs::read(&record).unwrap();
                assert_eq!(
                    t.remove_file_if(&rel, &current).unwrap(),
                    RemoveIfVerdict::Removed,
                    "{case}: the sanctioned break still works through the alias"
                );
                assert!(!record.exists(), "{case}: the sanctioned break removes it");
            } else {
                // A DISTINCT on-disk entry: make it a live second holder.
                let second_holder = crate::lock::FileLock::acquire(&alias, "B").unwrap();
                let alias_ino = std::fs::metadata(&alias).unwrap().ino();
                assert_ne!(
                    alias_ino, record_ino,
                    "{case}: the alias is a distinct entry"
                );
                let alias_content = std::fs::read(&alias).unwrap();
                for expected in [b"wrong".as_slice(), alias_content.as_slice()] {
                    let verdict = t.remove_file_if(&rel, expected);
                    assert!(
                        verdict.is_err(),
                        "{case}: remove_file_if on a DISTINCT lock-record entry must be REFUSED, \
                         got {verdict:?} (pre-fix the fold granted ownership and freed it)"
                    );
                    assert_eq!(
                        std::fs::metadata(&alias).unwrap().ino(),
                        alias_ino,
                        "{case}: the distinct alias entry's inode must be unchanged"
                    );
                }
                assert_eq!(
                    std::fs::metadata(&record).unwrap().ino(),
                    record_ino,
                    "{case}: the owned record's inode must be unchanged"
                );
                let alias_second = crate::lock::FileLock::acquire(&alias, "C");
                assert!(
                    matches!(&alias_second, Err(Error::LockContended(_))),
                    "{case}: the DISTINCT alias's holder must survive — a second acquire must be \
                     contended (pre-fix it succeeded, proving two holders)"
                );
                let owned_second = crate::lock::FileLock::acquire(&record, "D");
                assert!(
                    matches!(&owned_second, Err(Error::LockContended(_))),
                    "{case}: the owned record's holder must survive"
                );
                drop(second_holder);
            }
            drop(holder);
        }
    }

    /// D1/D2 — the LEGITIMATE case, on both platforms: the ONE record the
    /// layout OWNS is still breakable through the sidecar. A mismatch is a
    /// Mismatch (the record untouched) and a match is Removed (the sanctioned
    /// break). This is the behaviour the residual must preserve: guarding the
    /// foreign spellings must not guard the owned record.
    #[cfg(unix)]
    #[test]
    fn remove_file_if_still_breaks_the_owned_layout_lock() {
        use std::os::unix::fs::MetadataExt;

        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let base = dir.path().join("r");
        let t =
            LocalTransport::new(&SysEnv::from_process(), base.clone(), Layout::empty()).unwrap();
        let record = base.join("state/operation.lock");
        let holder = crate::lock::FileLock::acquire(&record, "A").unwrap();
        let before = std::fs::metadata(&record).unwrap().ino();
        let rel = RootedRelativePath::parse(Path::new("state/operation.lock")).unwrap();
        assert_eq!(
            t.remove_file_if(&rel, b"not-the-record").unwrap(),
            RemoveIfVerdict::Mismatch,
            "a mismatched compare against the owned record is a Mismatch, never a delete"
        );
        assert_eq!(
            std::fs::metadata(&record).unwrap().ino(),
            before,
            "the mismatched compare leaves the owned record's inode intact"
        );
        let current = std::fs::read(&record).unwrap();
        assert_eq!(
            t.remove_file_if(&rel, &current).unwrap(),
            RemoveIfVerdict::Removed,
            "a matching compare breaks the owned record by design"
        );
        assert!(!record.exists(), "the sanctioned break removes the record");
        drop(holder);
    }

    /// The durability property's scenario dimension: the healthy install, a
    /// one-shot crash/failure at one of the SEVEN stages, and the
    /// pre-existing-winner retry cases (identical / different content /
    /// different mode / published-before-parent-sync / the retry's parent
    /// fsync faulted).
    #[derive(Clone, Copy, Debug)]
    enum CreateNewScenario {
        Healthy,
        FailAt(CreateNewStep),
        PreExistingIdentical,
        PreExistingDifferent,
        PreExistingDifferentMode,
        /// A crash-simulated state: the entry EXISTS with the intended bytes
        /// and mode, but its parent directory was never fsync'd (a crash
        /// after publish, before the parent fsync).
        PublishedBeforeParentSync,
        /// The retry over an identical existing entry arms a one-shot
        /// ParentFsync fault: the AlreadyPresent branch must RUN the parent
        /// fsync, so the faulted retry propagates an error instead of
        /// claiming durability.
        IdenticalRetryParentFsyncFault,
    }

    fn create_new_scenario() -> impl Strategy<Value = CreateNewScenario> {
        prop_oneof![
            Just(CreateNewScenario::Healthy),
            Just(CreateNewScenario::PreExistingIdentical),
            Just(CreateNewScenario::PreExistingDifferent),
            Just(CreateNewScenario::PreExistingDifferentMode),
            Just(CreateNewScenario::PublishedBeforeParentSync),
            Just(CreateNewScenario::IdenticalRetryParentFsyncFault),
            Just(CreateNewScenario::FailAt(CreateNewStep::CreateTemp)),
            Just(CreateNewScenario::FailAt(CreateNewStep::Write)),
            Just(CreateNewScenario::FailAt(CreateNewStep::Chmod)),
            Just(CreateNewScenario::FailAt(CreateNewStep::FileFsync)),
            Just(CreateNewScenario::FailAt(CreateNewStep::Publish)),
            Just(CreateNewScenario::FailAt(CreateNewStep::Unlink)),
            Just(CreateNewScenario::FailAt(CreateNewStep::ParentFsync)),
        ]
    }

    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::RngSeed;

    proptest! {
        // THE DURABILITY CRASH/FAILURE MODEL — one property, every case:
        //
        // * `Ok(Created)` implies EXACT BYTES, the FINAL MODE, and a DURABLE
        //   DIRECTORY ENTRY — a fresh read of the destination directory (a
        //   simulated crash-after-return) still sees the entry, because the
        //   parent fsync established it;
        // * CONFLICT NEVER REPLACES: a destination pre-existing with
        //   DIFFERENT bytes (or a different mode over identical bytes) is
        //   never modified — the primitive returns the conflict verdict and
        //   the winner stays intact;
        // * RETRIES CONVERGE: after a one-shot failure at ANY of the seven
        //   stages, an IDENTICAL retry succeeds and leaves the destination
        //   EITHER the fully-written identical content OR absent — never a
        //   partial/torn record;
        // * FAILURE PROPAGATION: the faulted attempt is an `Err` naming the
        //   injected stage — never a swallowed `Ok` that claims durability.
        //
        // Bounded cases (full budget under `DEPLOY_FULL_TESTS=1`, fast
        // default), fixed seed 0x5EED_5EED (house style), no persistence, and
        // each case drives its OWN fixture (per-fixture one-shot fault,
        // structurally isolated).
        #![proptest_config(ProptestConfig {
            cases: crate::test_support::proptest_cases(64),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn durable_create_new_crash_failure_model(
            content in prop::collection::vec(any::<u8>(), 0..128),
            mode in prop_oneof![
                Just(0o600u32),
                Just(0o644u32),
                Just(0o755u32),
                Just(0o640u32),
            ],
            scenario in create_new_scenario(),
        ) {
            let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
            let root = dir.path().to_path_buf();
            let rel = RootedRelativePath::parse(Path::new("state/record.bin")).unwrap();
            let dest = root.join(rel.as_path());
            let dest_name = rel.file_name().unwrap().to_string_lossy().into_owned();

            match scenario {
                CreateNewScenario::Healthy => {
                    let verdict = durable_create_new(&root, guarded(&rel),
                        &content,
                        CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None },
                    )
                    .expect("the healthy install must succeed");
                    prop_assert_eq!(verdict, CreateNewVerdict::Created);
                    // Ok(Created) implies EXACT BYTES ...
                    prop_assert_eq!(
                        std::fs::read(&dest).expect("installed record must be readable"),
                        content,
                        "Ok(Created) must imply exact bytes"
                    );
                    // ... the FINAL MODE (never the process umask) ...
                    let meta = std::fs::metadata(&dest).expect("installed record must exist");
                    prop_assert_eq!(
                        meta.mode() & 0o7777,
                        mode & 0o7777,
                        "Ok(Created) must imply the final mode"
                    );
                    // ... and a DURABLE DIRECTORY ENTRY: the parent fsync
                    // established it, so a fresh directory read (a simulated
                    // crash-after-return) still sees the entry.
                    let names: Vec<String> = std::fs::read_dir(dest.parent().unwrap())
                        .expect("the parent must be readable")
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    prop_assert!(
                        names.contains(&dest_name),
                        "the parent fsync must have established the directory entry, dir has: {names:?}"
                    );
                }
                CreateNewScenario::FailAt(step) => {
                    let fault = CreateNewFault::new(step);
                    // FAILURE PROPAGATION: the faulted attempt is an Err
                    // naming the injected stage — never a swallowed Ok.
                    let err = durable_create_new(&root, guarded(&rel),
                        &content,
                        CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: Some(&fault) },
                    )
                    .expect_err("a failure at every stage must propagate as Err");
                    prop_assert!(
                        err.to_string().contains("forced to fail (once)"),
                        "the injected fault must be the propagated failure, got: {err}"
                    );
                    // RETRIES CONVERGE: an identical retry (the fault is
                    // one-shot, already consumed) must succeed and leave the
                    // destination EITHER the fully-written identical content
                    // OR absent — never a partial/torn file.
                    let retry = durable_create_new(&root, guarded(&rel),
                        &content,
                        CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None },
                    )
                    .expect("the identical retry must converge");
                    prop_assert!(
                        matches!(
                            retry,
                            CreateNewVerdict::Created | CreateNewVerdict::AlreadyPresent
                        ),
                        "the identical retry must converge, got: {retry:?}"
                    );
                    if dest.exists() {
                        prop_assert_eq!(
                            std::fs::read(&dest).expect("installed record must be readable"),
                            content,
                            "the destination must be the fully-written identical content, never partial"
                        );
                        let meta = std::fs::metadata(&dest).expect("installed record must exist");
                        prop_assert_eq!(
                            meta.mode() & 0o7777,
                            mode & 0o7777,
                            "the converged record must carry the intended final mode"
                        );
                    }
                }
                CreateNewScenario::PreExistingIdentical => {
                    // A previous successful publish (identical bytes + mode):
                    // the identical retry converges — AlreadyPresent, no
                    // error, no replace.
                    durable_create_new(&root, guarded(&rel), &content, CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None })
                        .expect("the first install must succeed");
                    let verdict =
                        durable_create_new(&root, guarded(&rel), &content, CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None })
                            .expect("an identical retry must converge, not error");
                    prop_assert_eq!(verdict, CreateNewVerdict::AlreadyPresent);
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        content,
                        "the identical retry must not touch the winner"
                    );
                }
                CreateNewScenario::PreExistingDifferent => {
                    // A concurrent winner with DIFFERENT content: a genuine
                    // conflict — the verdict, never a replace, and the
                    // winner's bytes stay intact. The winner is pre-created
                    // WITH THE INTENDED MODE: the verification's
                    // first-failure precedence checks the mode BEFORE the
                    // content (see [`verify_existing`] step 4 before step 5),
                    // so a winner left at `std::fs::write`'s umask-default
                    // mode would be reported as a MODE mismatch — this cell
                    // tests a CONTENT-only mismatch, where content must be
                    // the ONLY difference.
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    let other: Vec<u8> = if content.is_empty() {
                        vec![0u8]
                    } else {
                        content.iter().map(|b| b.wrapping_add(1)).collect()
                    };
                    prop_assert_ne!(&other, &content, "the winner must differ from the intent");
                    std::fs::write(&dest, &other).unwrap();
                    std::fs::set_permissions(
                        &dest,
                        std::fs::Permissions::from_mode(mode & 0o7777),
                    )
                    .unwrap();
                    let verdict = durable_create_new(&root, guarded(&rel),
                        &content,
                        CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None },
                    )
                    .expect("a conflict is a verdict, not an I/O error");
                    prop_assert!(matches!(
                        verdict,
                        CreateNewVerdict::Conflict(VerifiedExisting::ContentMismatch)
                    ));
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        other,
                        "the conflict must NEVER replace the winner"
                    );
                }
                CreateNewScenario::PreExistingDifferentMode => {
                    // Identical bytes but a DIFFERENT mode: still a genuine
                    // conflict (the mode is part of the record) — the verdict,
                    // never a replace.
                    durable_create_new(&root, guarded(&rel), &content, CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None })
                        .expect("the first install must succeed");
                    let other_mode = if (mode & 0o7777) == 0o600 { 0o644 } else { 0o600 };
                    std::fs::set_permissions(
                        &dest,
                        std::fs::Permissions::from_mode(other_mode),
                    )
                    .unwrap();
                    let verdict =
                        durable_create_new(&root, guarded(&rel), &content, CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None })
                            .expect("a mode mismatch is a verdict, not an I/O error");
                    let is_mode_mismatch = matches!(
                        verdict,
                        CreateNewVerdict::Conflict(VerifiedExisting::ModeMismatch { .. })
                    );
                    prop_assert!(is_mode_mismatch);
                    let meta = std::fs::metadata(&dest).unwrap();
                    prop_assert_eq!(
                        meta.mode() & 0o7777,
                        other_mode,
                        "the mode mismatch must never be replaced"
                    );
                }
                CreateNewScenario::PublishedBeforeParentSync => {
                    // A crash-simulated state: the entry EXISTS with the
                    // intended bytes and mode but its parent directory was
                    // NEVER fsync'd (a crash after publish, before the parent
                    // fsync). The identical retry must verify it as
                    // AlreadyPresent — and ESTABLISH the parent durability:
                    // the AlreadyPresent branch runs the parent fsync, so a
                    // fresh directory read (a simulated crash-after-return)
                    // still sees the entry.
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    std::fs::write(&dest, &content).unwrap();
                    std::fs::set_permissions(
                        &dest,
                        std::fs::Permissions::from_mode(mode & 0o7777),
                    )
                    .unwrap();
                    let verdict = durable_create_new(&root, guarded(&rel),
                        &content,
                        CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None },
                    )
                    .expect("the identical retry over a published-before-parent-sync entry must converge");
                    prop_assert_eq!(verdict, CreateNewVerdict::AlreadyPresent);
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        content,
                        "the winner must stay intact"
                    );
                    let meta = std::fs::metadata(&dest).unwrap();
                    prop_assert_eq!(
                        meta.mode() & 0o7777,
                        mode & 0o7777,
                        "the winner's mode must stay intact"
                    );
                    let names: Vec<String> = std::fs::read_dir(dest.parent().unwrap())
                        .expect("the parent must be readable")
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    prop_assert!(
                        names.contains(&dest_name),
                        "the AlreadyPresent retry must have established the parent durability, dir has: {names:?}"
                    );
                }
                CreateNewScenario::IdenticalRetryParentFsyncFault => {
                    // The retry's AlreadyPresent branch RUNS the parent fsync:
                    // arm the one-shot ParentFsync fault for a retry over an
                    // identical existing entry — the retry must return Err
                    // (the faulted parent fsync), never a false
                    // Ok(AlreadyPresent) that claims durability.
                    durable_create_new(&root, guarded(&rel), &content, CreateNewOptions { mode, content: ContentEquivalence::Exact, fault: None })
                        .expect("the first install must succeed");
                    let fault = CreateNewFault::new(CreateNewStep::ParentFsync);
                    let err = durable_create_new(&root, guarded(&rel),
                        &content,
                        CreateNewOptions {
                            mode,
                            content: ContentEquivalence::Exact,
                            fault: Some(&fault)},
                    )
                    .expect_err(
                        "the AlreadyPresent retry must run — and propagate the failure of — the parent fsync",
                    );
                    prop_assert!(
                        err.to_string().contains("forced to fail (once)"),
                        "the faulted parent fsync must be the propagated failure, got: {err}"
                    );
                }
            }
        }
    }

    /// A `Remote` wrapper that arms ONE one-shot stage fault inside
    /// `try_write_new` — the trait-level stage-failure model for
    /// `LocalTransport` (production `LocalTransport` never arms one; the
    /// fault is the same `CreateNewFault` the primitive proptest uses). Every
    /// other method delegates to the inner transport untouched.
    struct FaultyLocalRemote {
        inner: LocalTransport,
        fault: CreateNewFault,
    }

    impl Remote for FaultyLocalRemote {
        fn root(&self) -> &Path {
            self.inner.root()
        }

        fn is_local(&self) -> bool {
            true
        }

        fn read(&self, rel: &RootedRelativePath) -> Result<Vec<u8>> {
            self.inner.read(rel)
        }
        fn write(&self, rel: &RootedRelativePath, data: &[u8], mode: u32) -> Result<()> {
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &RootedRelativePath, data: &[u8]) -> Result<CreateNewVerdict> {
            durable_create_new(
                self.inner.root(),
                guarded(rel),
                data,
                CreateNewOptions {
                    mode: IMMUTABLE_RECORD_MODE,
                    content: ContentEquivalence::Exact,
                    fault: Some(&self.fault),
                },
            )
        }
        fn create_dir(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.create_dir(rel)
        }
        fn create_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.create_dir_all(rel)
        }
        fn set_mode(&self, rel: &RootedRelativePath, mode: u32) -> Result<()> {
            self.inner.set_mode(rel, mode)
        }
        fn list(&self, rel: &RootedRelativePath) -> Result<Vec<RemoteEntry>> {
            self.inner.list(rel)
        }
        fn rename(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
            self.inner.rename(from, to)
        }
        fn rename_aside(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
            self.inner.rename_aside(from, to)
        }
        fn symlink(&self, target: &Path, link: &RootedRelativePath) -> Result<()> {
            self.inner.symlink(target, link)
        }
        fn read_link(&self, rel: &RootedRelativePath) -> Result<PathBuf> {
            self.inner.read_link(rel)
        }
        fn remove_file(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.remove_file(rel)
        }
        fn remove_residue_file(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.remove_residue_file(rel)
        }
        fn remove_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.remove_dir_all(rel)
        }
        fn remove_dir(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.remove_dir(rel)
        }
        fn remove_residue_dir(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.remove_residue_dir(rel)
        }
        fn exists(&self, rel: &RootedRelativePath) -> bool {
            self.inner.exists(rel)
        }
        fn metadata(&self, rel: &RootedRelativePath) -> Result<RemoteMeta> {
            self.inner.metadata(rel)
        }
        fn exec(&self, argv: &[String], timeout: Duration) -> Result<ExecOutcome> {
            self.inner.exec(argv, timeout)
        }
        fn filesystem_bytes(&self) -> Result<FsBytes> {
            self.inner.filesystem_bytes()
        }
    }

    /// The trait-level verdict matrix for [`Remote::try_write_new`] on
    /// `LocalTransport` — the typed verdict survives the trait boundary, no
    /// bool collapse:
    ///
    /// * `Created` for a FRESH write (exact bytes, final mode, durable entry);
    /// * `AlreadyPresent` for an EXACT existing entry — the identical retry —
    ///   which must ESTABLISH the parent durability (the parent fsync runs on
    ///   the AlreadyPresent branch; a fresh directory read still sees the
    ///   entry);
    /// * `Conflict` for DIFFERENT BYTES and for a MODE MISMATCH over identical
    ///   bytes (the spec: "a mode mismatch must remain Conflict") — the
    ///   winner is never replaced or modified;
    /// * published-before-parent-sync: an existing entry whose parent was
    ///   never synced is verified as `AlreadyPresent` (bytes+mode match) and
    ///   the retry establishes the parent durability;
    /// * every STAGE FAILURE (via the one-shot fault through the trait)
    ///   propagates as an `Err` naming the injected stage — never a false
    ///   verdict — and the identical retry converges.
    #[derive(Clone, Copy, Debug)]
    enum TransportVerdictState {
        Fresh,
        ExactExisting,
        DifferentBytes,
        DifferentMode,
        PublishedBeforeParentSync,
        FailAt(CreateNewStep),
    }

    fn transport_verdict_state() -> impl Strategy<Value = TransportVerdictState> {
        prop_oneof![
            Just(TransportVerdictState::Fresh),
            Just(TransportVerdictState::ExactExisting),
            Just(TransportVerdictState::DifferentBytes),
            Just(TransportVerdictState::DifferentMode),
            Just(TransportVerdictState::PublishedBeforeParentSync),
            Just(TransportVerdictState::FailAt(CreateNewStep::CreateTemp)),
            Just(TransportVerdictState::FailAt(CreateNewStep::Write)),
            Just(TransportVerdictState::FailAt(CreateNewStep::Chmod)),
            Just(TransportVerdictState::FailAt(CreateNewStep::FileFsync)),
            Just(TransportVerdictState::FailAt(CreateNewStep::Publish)),
            Just(TransportVerdictState::FailAt(CreateNewStep::Unlink)),
            Just(TransportVerdictState::FailAt(CreateNewStep::ParentFsync)),
        ]
    }

    proptest! {
        // Bounded cases, fixed seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: crate::test_support::proptest_cases(64),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn try_write_new_verdict_matrix(
            content in prop::collection::vec(any::<u8>(), 0..128),
            state in transport_verdict_state(),
        ) {
            use std::os::unix::fs::PermissionsExt;

            let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
            let t = LocalTransport::new(&SysEnv::from_process(), dir.path().join("r"), Layout::empty()).unwrap();
            let rel = RootedRelativePath::parse(Path::new("state/record.bin")).unwrap();
            let dest = t.root().join(rel.as_path());
            let dest_name = rel.file_name().unwrap().to_string_lossy().into_owned();
            let final_mode = IMMUTABLE_RECORD_MODE & 0o7777;

            match state {
                TransportVerdictState::Fresh => {
                    let verdict = t
                        .try_write_new(&rel, &content)
                        .expect("the fresh install must succeed");
                    prop_assert_eq!(verdict, CreateNewVerdict::Created);
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        content,
                        "Ok(Created) must imply exact bytes"
                    );
                    let meta = std::fs::metadata(&dest).unwrap();
                    prop_assert_eq!(
                        meta.mode() & 0o7777,
                        final_mode,
                        "Ok(Created) must imply the final mode"
                    );
                    let names: Vec<String> = std::fs::read_dir(dest.parent().unwrap())
                        .unwrap()
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    prop_assert!(
                        names.contains(&dest_name),
                        "Ok(Created) must imply a durable directory entry, dir has: {names:?}"
                    );
                }
                TransportVerdictState::ExactExisting => {
                    // An EXACT existing entry (bytes AND mode identical): the
                    // identical retry converges — AlreadyPresent, and the
                    // parent durability is established (the parent fsync runs
                    // on this branch).
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    std::fs::write(&dest, &content).unwrap();
                    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(final_mode))
                        .unwrap();
                    let verdict = t
                        .try_write_new(&rel, &content)
                        .expect("an identical retry must converge, not error");
                    prop_assert!(matches!(verdict, CreateNewVerdict::AlreadyPresent));
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        content,
                        "the identical retry must not touch the winner"
                    );
                    let names: Vec<String> = std::fs::read_dir(dest.parent().unwrap())
                        .unwrap()
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    prop_assert!(
                        names.contains(&dest_name),
                        "the AlreadyPresent retry must leave the durable entry, dir has: {names:?}"
                    );
                }
                TransportVerdictState::DifferentBytes => {
                    // A winner with DIFFERENT bytes: Conflict, never replaced.
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    let other: Vec<u8> = if content.is_empty() {
                        vec![0u8]
                    } else {
                        content.iter().map(|b| b.wrapping_add(1)).collect()
                    };
                    prop_assert_ne!(&other, &content, "the winner must differ from the intent");
                    std::fs::write(&dest, &other).unwrap();
                    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(final_mode))
                        .unwrap();
                    let verdict = t
                        .try_write_new(&rel, &content)
                        .expect("a different-content winner is a verdict, not an I/O error");
                    prop_assert!(matches!(
                        verdict,
                        CreateNewVerdict::Conflict(VerifiedExisting::ContentMismatch)
                    ));
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        other,
                        "the conflict must NEVER replace the winner"
                    );
                }
                TransportVerdictState::DifferentMode => {
                    // Identical bytes but a DIFFERENT mode: still Conflict —
                    // the mode is part of the record, and a mode mismatch must
                    // remain Conflict (never a convergent AlreadyPresent).
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    std::fs::write(&dest, &content).unwrap();
                    let other_mode = if final_mode == 0o600 { 0o640 } else { 0o600 };
                    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(other_mode))
                        .unwrap();
                    let verdict = t
                        .try_write_new(&rel, &content)
                        .expect("a mode mismatch is a verdict, not an I/O error");
                    let is_mode_mismatch = matches!(
                        verdict,
                        CreateNewVerdict::Conflict(VerifiedExisting::ModeMismatch { .. })
                    );
                    prop_assert!(is_mode_mismatch);
                    let meta = std::fs::metadata(&dest).unwrap();
                    prop_assert_eq!(
                        meta.mode() & 0o7777,
                        other_mode,
                        "the mode mismatch must never be replaced"
                    );
                }
                TransportVerdictState::PublishedBeforeParentSync => {
                    // A crash-simulated state: the entry EXISTS with the
                    // intended bytes and mode, but its parent was never synced.
                    // The retry verifies it as AlreadyPresent AND establishes
                    // the parent durability.
                    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                    std::fs::write(&dest, &content).unwrap();
                    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(final_mode))
                        .unwrap();
                    let verdict = t
                        .try_write_new(&rel, &content)
                        .expect("the retry over a published-before-parent-sync entry must converge");
                    prop_assert_eq!(verdict, CreateNewVerdict::AlreadyPresent);
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        content,
                        "the winner must stay intact"
                    );
                    let names: Vec<String> = std::fs::read_dir(dest.parent().unwrap())
                        .unwrap()
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect();
                    prop_assert!(
                        names.contains(&dest_name),
                        "the AlreadyPresent retry must establish the parent durability, dir has: {names:?}"
                    );
                }
                TransportVerdictState::FailAt(step) => {
                    // EVERY STAGE FAILURE through the trait boundary: the
                    // faulted attempt propagates as Err naming the injected
                    // stage — never a false verdict — and the one-shot fault
                    // being consumed, the identical retry converges.
                    let w = FaultyLocalRemote {
                        inner: t,
                        fault: CreateNewFault::new(step)};
                    let err = w
                        .try_write_new(&rel, &content)
                        .expect_err("a failure at every stage must propagate as Err");
                    prop_assert!(
                        err.to_string().contains("forced to fail (once)"),
                        "the injected fault must be the propagated failure, got: {err}"
                    );
                    let retry = w
                        .try_write_new(&rel, &content)
                        .expect("the identical retry must converge");
                    prop_assert!(
                        matches!(
                            retry,
                            CreateNewVerdict::Created | CreateNewVerdict::AlreadyPresent
                        ),
                        "the identical retry must converge, got: {retry:?}"
                    );
                    if dest.exists() {
                        prop_assert_eq!(
                            std::fs::read(&dest).unwrap(),
                            content,
                            "the destination must be the fully-written identical content, never partial"
                        );
                    }
                }
            }
        }
    }

    /// The swap-at-every-boundary property of the descriptor-bound
    /// verification (the LOCAL leg): a REGULAR→SYMLINK / REGULAR→DIRECTORY /
    /// REGULAR→DIFFERENT-INODE swap is injected at EVERY boundary of the
    /// open→fstat→read sequence — BEFORE the `O_NOFOLLOW` open, BETWEEN the
    /// open and the fstat, BETWEEN the fstat and the read — and the verdict
    /// must NEVER mix two inodes' observations:
    ///
    /// * a swap BEFORE the open changes WHAT is opened: the verdict reflects
    ///   the SWAPPED entry consistently — a symlink →
    ///   NotRegularFile{Symlink} (the `O_NOFOLLOW` open NEVER follows, even
    ///   a symlink pointing at a regular file whose bytes+mode match the
    ///   intent), a directory → NotRegularFile{Directory}, a different-inode
    ///   regular file (mode AND content both differing from the intent) →
    ///   ModeMismatch naming the SWAPPED inode's mode — a REJECTION;
    /// * a swap AFTER the open (between open/fstat or fstat/read) is
    ///   HARMLESS: the descriptor pins the ORIGINAL inode, so the verdict is
    ///   AlreadyPresent with the ORIGINAL inode's mode AND content (the
    ///   symlink target / the different inode carry DIFFERENT content and
    ///   the directory is unreadable as a file — a path-following read or a
    ///   re-open would NOT yield AlreadyPresent, so the assertion catches
    ///   any metadata/content mix).
    ///
    /// Bounded cases, fixed seed 0x5EED_5EED (house style), no persistence.
    fn swap_case() -> impl Strategy<Value = (VerifySwapBoundary, VerifySwapKind)> {
        prop_oneof![
            Just((VerifySwapBoundary::BeforeOpen, VerifySwapKind::Symlink)),
            Just((VerifySwapBoundary::BeforeOpen, VerifySwapKind::Directory)),
            Just((
                VerifySwapBoundary::BeforeOpen,
                VerifySwapKind::DifferentInode
            )),
            Just((VerifySwapBoundary::AfterOpen, VerifySwapKind::Symlink)),
            Just((VerifySwapBoundary::AfterOpen, VerifySwapKind::Directory)),
            Just((
                VerifySwapBoundary::AfterOpen,
                VerifySwapKind::DifferentInode
            )),
            Just((VerifySwapBoundary::AfterFstat, VerifySwapKind::Symlink)),
            Just((VerifySwapBoundary::AfterFstat, VerifySwapKind::Directory)),
            Just((
                VerifySwapBoundary::AfterFstat,
                VerifySwapKind::DifferentInode
            )),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::test_support::proptest_cases(64),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn verify_existing_swap_at_every_boundary(
            (boundary, kind) in swap_case(),
        ) {
            use std::os::unix::fs::PermissionsExt;

            let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
            let root = dir.path().to_path_buf();
            let rel = RootedRelativePath::parse(Path::new("state/record.json")).unwrap();
            let dest = root.join(rel.as_path());
            let required = IMMUTABLE_RECORD_MODE & 0o7777;
            let wrong_mode = if required == 0o600 { 0o640 } else { 0o600 };
            let intended: &[u8] = br#"{"a":1,"b":2}"#;
            // The swapped-in observations differ from the original's: a
            // path-following read (or a metadata/content mix) is therefore
            // detectable — only the SAME-inode verdict passes the table.
            let swapped_content: &[u8] = br#"{"a":9,"b":9}"#;

            std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
            // The ORIGINAL entry: a regular file matching the intent (bytes
            // AND mode) — a no-swap verification would accept it.
            std::fs::write(&dest, intended).unwrap();
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(required)).unwrap();
            // The pre-staged swap entry: the symlink target AND the
            // different-inode regular file (a fresh inode with mode + content
            // both differing from the intent).
            let target = dest.with_file_name("record.json.swap-target");
            std::fs::write(&target, swapped_content).unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(wrong_mode)).unwrap();

            let swap = VerifySwap::new(boundary, kind, &target);
            let verified = verify_existing(
                || open_verify_local(&dest, Some(&swap)),
                intended,
                required,
                ContentEquivalence::Exact,
            )
            .expect("the descriptor-bound verification is a verdict, not an I/O error");
            let verdict = verified_to_verdict(verified);

            // THE INVARIANT: success (AlreadyPresent) ONLY when the metadata
            // AND the content came from the SAME OPENED INODE — the
            // fd-pinned ORIGINAL for a post-open swap, the SWAPPED entry
            // (consistently, as a rejection) for a pre-open swap.
            match boundary {
                VerifySwapBoundary::BeforeOpen => match kind {
                    VerifySwapKind::Symlink => prop_assert_eq!(
                        verdict,
                        CreateNewVerdict::Conflict(VerifiedExisting::NotRegularFile {
                            kind: NotRegularFileKind::Symlink}),
                        "a pre-open symlink swap must be rejected — the O_NOFOLLOW open never follows"
                    ),
                    VerifySwapKind::Directory => prop_assert_eq!(
                        verdict,
                        CreateNewVerdict::Conflict(VerifiedExisting::NotRegularFile {
                            kind: NotRegularFileKind::Directory}),
                        "a pre-open directory swap must be rejected"
                    ),
                    VerifySwapKind::DifferentInode => prop_assert_eq!(
                        verdict,
                        CreateNewVerdict::Conflict(VerifiedExisting::ModeMismatch {
                            actual: wrong_mode & 0o7777,
                            required}),
                        "a pre-open different-inode swap must be rejected with the SWAPPED inode's mode"
                    )},
                VerifySwapBoundary::AfterOpen | VerifySwapBoundary::AfterFstat => {
                    prop_assert_eq!(
                        verdict,
                        CreateNewVerdict::AlreadyPresent,
                        "a post-open swap is harmless: the descriptor pins the ORIGINAL inode, so the verdict must reflect ITS metadata AND content — never a mix"
                    );
                }
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::test_support::proptest_cases(64),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn wait_for_sidecar_flock_simulated_contention(
            hold_ms in prop_oneof![
                Just(0u64),
                Just(1u64),
                Just(1999u64),
                Just(2000u64),
                Just(2500u64),
                Just(3000u64),
                0u64..=3000u64,
            ],
        ) {
            let timeout = SIDECAR_WAIT_TIMEOUT;
            let interval = SIDECAR_RETRY_INTERVAL;
            let hold = Duration::from_millis(hold_ms);
            let start = Instant::now();
            let release_at = start + hold;
            let deadline = start + timeout;
            let simulated = std::cell::Cell::new(start);
            let sleeps = std::cell::RefCell::new(Vec::<Duration>::new());
            let try_count = std::cell::Cell::new(0usize);
            let last_now = std::cell::Cell::new(None::<Instant>);
            let path = Path::new("/tmp/sidecar.test");
            let res = wait_for_sidecar_flock(
                path,
                timeout,
                interval,
                || {
                    try_count.set(try_count.get() + 1);
                    last_now.set(Some(simulated.get()));
                    if simulated.get() > release_at { 0 } else { -1 }
                },
                || libc::EWOULDBLOCK,
                || simulated.get(),
                |d| {
                    sleeps.borrow_mut().push(d);
                    simulated.set(simulated.get() + d);
                },
            );
            if hold < timeout {
                prop_assert!(res.is_ok(), "hold {hold:?} < timeout {timeout:?} must succeed, got {res:?} sleeps={:?} try_count={}", sleeps.borrow(), try_count.get());
                // Success must have observed the release.
                prop_assert!(simulated.get() >= release_at, "simulated time must have reached release_at");
            } else {
                prop_assert!(res.is_err(), "hold {hold:?} >= timeout {timeout:?} must fail");
                let msg = res.unwrap_err().to_string();
                prop_assert!(msg.contains("remained contended for"), "timeout error must contain 'remained contended for', got: {msg}");
                // Failure happens only after deadline.
                let last = last_now.get().expect("at least one try");
                prop_assert!(last >= deadline, "failure must happen only after deadline: last_now={last:?} deadline={deadline:?}");
                // No sleep extends beyond deadline.
                for s in sleeps.borrow().iter() {
                    prop_assert!(*s <= interval, "every sleep <= interval, got {s:?}");
                }
                let elapsed = simulated.get().duration_since(start);
                prop_assert!(elapsed <= timeout + interval, "total elapsed {elapsed:?} must be <= timeout+interval {:?}", timeout + interval);
                // Also no sleep took us beyond deadline+interval: simulated never beyond deadline+epsilon.
                prop_assert!(simulated.get() <= deadline + interval, "simulated {:?} must not exceed deadline+interval", simulated.get());
            }
            // Every sleep is bounded by interval and by remaining time (checked above for interval, and elapsed bound covers deadline).
            for s in sleeps.borrow().iter() {
                prop_assert!(*s <= interval);
            }
        }
    }

    #[test]
    fn wait_for_sidecar_flock_non_contention_fails_immediately() {
        let timeout = SIDECAR_WAIT_TIMEOUT;
        let interval = SIDECAR_RETRY_INTERVAL;
        let start = Instant::now();
        let simulated = std::cell::Cell::new(start);
        let try_count = std::cell::Cell::new(0usize);
        let sleeps = std::cell::RefCell::new(Vec::<Duration>::new());
        let path = Path::new("/tmp/sidecar.test");
        let res = wait_for_sidecar_flock(
            path,
            timeout,
            interval,
            || {
                try_count.set(try_count.get() + 1);
                -1
            },
            || libc::EIO,
            || simulated.get(),
            |d| {
                sleeps.borrow_mut().push(d);
                simulated.set(simulated.get() + d);
            },
        );
        assert!(res.is_err(), "EIO must fail");
        assert_eq!(
            try_count.get(),
            1,
            "non-contention error must fail immediately (one try)"
        );
        assert!(sleeps.borrow().is_empty(), "no sleeps on immediate failure");
        assert!(
            !res.unwrap_err()
                .to_string()
                .contains("remained contended for")
        );
    }

    #[test]
    fn wait_for_sidecar_flock_eintr_retries_without_sleep() {
        let timeout = SIDECAR_WAIT_TIMEOUT;
        let interval = SIDECAR_RETRY_INTERVAL;
        let start = Instant::now();
        let simulated = std::cell::Cell::new(start);
        let sleeps = std::cell::RefCell::new(Vec::<Duration>::new());
        let calls = std::cell::Cell::new(0usize);
        let path = Path::new("/tmp/sidecar.test");
        let res = wait_for_sidecar_flock(
            path,
            timeout,
            interval,
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 1 { -1 } else { 0 }
            },
            || if calls.get() == 1 { libc::EINTR } else { 0 },
            || simulated.get(),
            |d| {
                sleeps.borrow_mut().push(d);
                simulated.set(simulated.get() + d);
            },
        );
        assert!(res.is_ok(), "EINTR then success must retry and succeed");
        assert_eq!(calls.get(), 2, "should have retried once after EINTR");
        assert!(
            sleeps.borrow().is_empty(),
            "EINTR must retry without sleeping"
        );
    }

    /// FIDELITY SCOPE PINS.
    ///
    /// `crate::manifest`'s "Fidelity scope" section is the authoritative
    /// statement of what a sync carries: name, kind, mode INCLUDING the
    /// setuid/setgid/sticky bits, content, and symlink target ARE carried;
    /// ownership, xattrs, ACLs, timestamps, file flags, and sparseness are
    /// SILENTLY dropped; hard links are REFUSED. `Remote::copy_tree` has TWO
    /// implementations with DIFFERENT fidelity, so the carried and the
    /// not-carried axes are pinned per path here.
    ///
    /// WHICH IS WHICH:
    /// * `copy_tree_*_carries_special_mode_bits` are BEHAVIOUR pins of the
    ///   CARRIED set: they pin ALREADY-CORRECT behaviour (so they cannot fail
    ///   pre-fix either) and protect against a FUTURE regression that starts
    ///   dropping something currently kept.
    /// * `copy_tree_default_walk_drops_*` and `copy_tree_ssh_cp_a_*` are
    ///   CHARACTERIZATION tests of a DOCUMENTED LIMITATION: they pin the
    ///   current behaviour of an intentional omission and so cannot fail
    ///   pre-fix either; a later change that starts carrying (or refuses to
    ///   carry) one of these must be an explicit, test-visible act. Each
    ///   announces a `STOREKIT_SKIP` with its reason when the
    ///   filesystem/tool cannot set up the fixture (xattrs, a foreign gid),
    ///   rather than failing the suite on an environment that cannot support
    ///   it.
    #[cfg(unix)]
    mod fidelity {
        use super::*;
        use std::collections::BTreeMap;
        use std::ffi::{CString, OsString};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::path::{Path, PathBuf};

        /// The environment variable the shim reads to find its "remote"
        /// working directory (the directory a remote login shell would start
        /// in).
        const SHIM_WORK_VAR: &str = "STOREKIT_SSH_SHIM_WORK";

        /// Test-only `ssh` shim: it never opens a network connection. It
        /// reproduces the far side by running the transport's final argument
        /// (the remote command string `bash -c '<script>'`) in
        /// `$STOREKIT_SSH_SHIM_WORK` with stdin/stdout/stderr connected
        /// exactly as the real operation connects them.
        const SHIM_SCRIPT: &str = r#"#!/bin/sh
set -u
work=${STOREKIT_SSH_SHIM_WORK:?the shim work directory is not configured}
last=''
for arg in "$@"; do last="$arg"; done
cd "$work" || exit 125
exec /bin/sh -c "$last"
"#;

        fn rooted(p: &str) -> RootedRelativePath {
            RootedRelativePath::parse(Path::new(p)).expect("parse the rooted relative path")
        }

        // ---- unix xattr syscalls (libc is a direct dependency; the
        // platform signatures differ: macOS carries position/options, Linux
        // only flags) ---------------------------------------------------

        #[cfg(target_os = "macos")]
        unsafe fn raw_setxattr(
            path: *const libc::c_char,
            name: *const libc::c_char,
            value: *const libc::c_void,
            size: libc::size_t,
        ) -> libc::c_int {
            unsafe { libc::setxattr(path, name, value, size, 0, 0) }
        }

        #[cfg(not(target_os = "macos"))]
        unsafe fn raw_setxattr(
            path: *const libc::c_char,
            name: *const libc::c_char,
            value: *const libc::c_void,
            size: libc::size_t,
        ) -> libc::c_int {
            unsafe { libc::setxattr(path, name, value, size, 0) }
        }

        #[cfg(target_os = "macos")]
        unsafe fn raw_getxattr(
            path: *const libc::c_char,
            name: *const libc::c_char,
            value: *mut libc::c_void,
            size: libc::size_t,
        ) -> libc::ssize_t {
            unsafe { libc::getxattr(path, name, value, size, 0, 0) }
        }

        #[cfg(not(target_os = "macos"))]
        unsafe fn raw_getxattr(
            path: *const libc::c_char,
            name: *const libc::c_char,
            value: *mut libc::c_void,
            size: libc::size_t,
        ) -> libc::ssize_t {
            unsafe { libc::getxattr(path, name, value, size) }
        }

        fn cstr(path: &Path) -> CString {
            CString::new(path.as_os_str().as_bytes()).expect("path has no interior NUL")
        }

        fn set_xattr(path: &Path, name: &str, value: &[u8]) -> std::io::Result<()> {
            let p = cstr(path);
            let n = CString::new(name).expect("xattr name has no interior NUL");
            let rc =
                unsafe { raw_setxattr(p.as_ptr(), n.as_ptr(), value.as_ptr().cast(), value.len()) };
            if rc == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }

        fn has_xattr(path: &Path, name: &str) -> bool {
            let p = cstr(path);
            let n = CString::new(name).expect("xattr name has no interior NUL");
            let rc = unsafe { raw_getxattr(p.as_ptr(), n.as_ptr(), std::ptr::null_mut(), 0) };
            rc >= 0
        }

        /// Whether a `user.*` xattr can be set on `dir`'s filesystem. On
        /// failure this ANNOUNCES a skip (with the reason) and returns false,
        /// so the xattr half of a test is skipped rather than failing on a
        /// filesystem/tool that cannot support it.
        fn xattrs_available(dir: &Path) -> bool {
            let probe = dir.join(".storekit-xattr-probe");
            std::fs::write(&probe, b"x").expect("write the xattr probe file");
            match set_xattr(&probe, "user.storekit.probe", b"1") {
                Ok(()) => true,
                Err(e) => {
                    crate::test_support::announce_skip(&format!(
                        "this filesystem/tool cannot set a user extended attribute on {} ({e}), \
                         so xattr fidelity cannot be asserted here",
                        dir.display()
                    ));
                    false
                }
            }
        }

        fn chgrp(path: &Path, gid: u32) -> std::io::Result<()> {
            let p = cstr(path);
            let rc = unsafe { libc::chown(p.as_ptr(), !0 as libc::uid_t, gid) };
            if rc == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }

        /// A supplementary group of the current process different from its
        /// effective gid, or `None` when there is none. Used to build a
        /// source entry whose group the transferring account can set but whose
        /// value the DEFAULT walk does not reproduce.
        fn supplementary_gid() -> Option<u32> {
            let egid = unsafe { libc::getegid() };
            let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
            if n <= 0 {
                return None;
            }
            let mut buf = vec![0 as libc::gid_t; n as usize];
            let got = unsafe { libc::getgroups(n, buf.as_mut_ptr()) };
            if got <= 0 {
                return None;
            }
            buf.truncate(got as usize);
            buf.into_iter().find(|&g| g != egid)
        }

        /// The shim harness: a shim bin dir, a "remote" working directory,
        /// and the destination root inside it.
        struct SshHarness {
            tmp: tempfile::TempDir,
            work: PathBuf,
            root: PathBuf,
        }

        impl SshHarness {
            fn new() -> SshHarness {
                let tmp = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env())
                    .expect("create the harness tempdir");
                let work = tmp.path().join("work");
                std::fs::create_dir_all(&work).expect("create the shim work dir");
                let bin = tmp.path().join("bin");
                std::fs::create_dir_all(&bin).expect("create the shim bin dir");
                // The shared helper (a short-lived process, never an
                // `fs::write` in this test process) keeps the shim's write fd
                // out of the descriptor table, so a sibling test's fork cannot
                // inherit it and make a later exec of the shim fail ETXTBSY.
                crate::test_support::write_executable(&bin.join("ssh"), SHIM_SCRIPT.as_bytes());
                let root = work.join("dst");
                std::fs::create_dir_all(&root).expect("create the destination root");
                SshHarness { tmp, work, root }
            }

            fn env(&self) -> SysEnv {
                let bin = self.tmp.path().join("bin");
                let mut vars: BTreeMap<OsString, OsString> = BTreeMap::new();
                vars.insert(
                    OsString::from("PATH"),
                    OsString::from(format!(
                        "{}:{}",
                        bin.display(),
                        std::env::var("PATH").unwrap_or_default()
                    )),
                );
                vars.insert(
                    OsString::from(SHIM_WORK_VAR),
                    self.work.as_os_str().to_os_string(),
                );
                SysEnv::from_map(vars)
            }

            fn transport(&self) -> SshTransport {
                let env = self.env();
                SshTransport::new(
                    "deploy",
                    "shim.invalid",
                    2222,
                    &self.root,
                    Layout::empty(),
                    Some(Path::new("/dev/null")),
                    None,
                    &self.tmp.path().join("knownhosts"),
                    &env,
                    false,
                )
                .expect("construct the shimmed ssh transport")
            }
        }

        /// Create a source tree exercising the CARRIED metadata axis — the
        /// three special mode bits, a read-only directory and file, file
        /// content, and a symlink target — and return `(rel path, mode)` pairs.
        fn build_carried_tree(root: &Path) -> Vec<(&'static str, u32)> {
            std::fs::create_dir_all(root.join("ro")).expect("mkdir ro");
            std::fs::write(root.join("ro/inside"), b"x").expect("write ro/inside");
            std::fs::write(root.join("setuid"), b"u").expect("write setuid");
            std::fs::write(root.join("setgid"), b"g").expect("write setgid");
            std::fs::write(root.join("plain"), b"content").expect("write plain");
            std::fs::create_dir_all(root.join("sticky")).expect("mkdir sticky");
            std::fs::write(root.join("sticky/child"), b"c").expect("write sticky/child");
            std::os::unix::fs::symlink("plain", root.join("link")).expect("symlink link -> plain");
            let modes: [(&'static str, u32); 6] = [
                ("ro", 0o555),
                ("ro/inside", 0o444),
                ("setuid", 0o4755),
                ("setgid", 0o2755),
                ("sticky", 0o1777),
                ("sticky/child", 0o644),
            ];
            // Directory modes LAST: a 0555 directory cannot be written into.
            for (rel, mode) in &modes {
                std::fs::set_permissions(root.join(rel), std::fs::Permissions::from_mode(*mode))
                    .unwrap_or_else(|e| panic!("chmod {rel} {mode:o}: {e}"));
            }
            modes.to_vec()
        }

        /// Copy `src` to `dest` through `transport` and assert the CARRIED set
        /// survived: every special mode bit, the read-only directory's
        /// content, the file content, and the symlink target.
        fn assert_carried_set(
            transport: &impl Remote,
            src: &str,
            dest: &str,
            expected: &[(&str, u32)],
        ) {
            transport
                .copy_tree(&rooted(src), &rooted(dest))
                .expect("copy_tree");
            let dest_root = transport.root().join(Path::new(dest));
            for (rel, mode) in expected {
                let p = dest_root.join(rel);
                let actual = std::fs::symlink_metadata(&p)
                    .unwrap_or_else(|e| panic!("stat copied {rel}: {e}"))
                    .permissions()
                    .mode()
                    & 0o7777;
                assert_eq!(
                    actual, *mode,
                    "the CARRIED set: copied {rel} must keep mode {mode:o}, got {actual:o}"
                );
            }
            assert_eq!(
                std::fs::read(dest_root.join("plain")).expect("read copied plain"),
                b"content",
                "the CARRIED set: file content must round-trip"
            );
            let link = dest_root.join("link");
            assert!(
                std::fs::symlink_metadata(&link)
                    .expect("stat copied link")
                    .file_type()
                    .is_symlink(),
                "the CARRIED set: a symlink must stay a symlink"
            );
            assert_eq!(
                std::fs::read_link(&link).expect("read copied link target"),
                Path::new("plain"),
                "the CARRIED set: the symlink target must round-trip"
            );
        }

        /// BEHAVIOUR PIN (local half): a tree with setuid/setgid/sticky and a
        /// read-only directory round-trips through the DEFAULT walk with every
        /// bit intact.
        #[test]
        fn copy_tree_default_walk_carries_special_mode_bits() {
            let dir =
                crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
            let base = dir.path().join("remote");
            let src = base.join("src");
            std::fs::create_dir_all(&src).unwrap();
            let expected = build_carried_tree(&src);
            let t = LocalTransport::new(&SysEnv::from_process(), base, Layout::empty()).unwrap();
            assert_carried_set(&t, "src", "dest", &expected);
        }

        /// BEHAVIOUR PIN (ssh half): the `cp -a` override — the OTHER
        /// implementation of the same operation — also carries every special
        /// mode bit and the read-only directory.
        #[test]
        fn copy_tree_ssh_cp_a_carries_special_mode_bits() {
            let h = SshHarness::new();
            let src = h.root.join("src");
            std::fs::create_dir_all(&src).unwrap();
            let expected = build_carried_tree(&src);
            let t = h.transport();
            assert_carried_set(&t, "src", "dest", &expected);
        }

        /// CHARACTERIZATION (not-carried half, local): the DEFAULT
        /// list/read/write walk documents that it DROPS xattrs and ownership.
        /// Cannot fail pre-fix — the behaviour already exists — so it exists
        /// to make a later change to the limitation deliberate and visible.
        #[test]
        fn copy_tree_default_walk_drops_xattrs_and_ownership() {
            let dir =
                crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
            let base = dir.path().join("remote");
            let src = base.join("src");
            std::fs::create_dir_all(&src).unwrap();
            let file = src.join("f");
            std::fs::write(&file, b"payload").unwrap();

            if xattrs_available(&src) {
                set_xattr(&file, "user.storekit.fidelity", b"present").unwrap();
                let t = LocalTransport::new(&SysEnv::from_process(), base.clone(), Layout::empty())
                    .unwrap();
                t.copy_tree(&rooted("src"), &rooted("dest")).unwrap();
                let dst = base.join("dest/f");
                assert!(dst.is_file(), "premise: the file was copied");
                assert!(
                    !has_xattr(&dst, "user.storekit.fidelity"),
                    "CHARACTERIZATION of a DOCUMENTED LIMITATION: the default list/read/write \
                     walk must DROP xattrs, but it carried user.storekit.fidelity; the \
                     documented fidelity scope is now wrong"
                );
            }

            let Some(gid) = supplementary_gid() else {
                crate::test_support::announce_skip(
                    "the current user has no supplementary group different from its effective \
                     gid, so a source entry the default walk cannot re-own cannot be built; \
                     ownership fidelity is unasserted here",
                );
                return;
            };
            let owned = src.join("owned");
            std::fs::write(&owned, b"o").unwrap();
            chgrp(&owned, gid).unwrap();
            assert_eq!(
                std::fs::symlink_metadata(&owned).unwrap().gid(),
                gid,
                "premise: the source group differs from the copier's effective gid"
            );
            let t = LocalTransport::new(&SysEnv::from_process(), base.clone(), Layout::empty())
                .unwrap();
            t.copy_tree(&rooted("src"), &rooted("owned-dest")).unwrap();
            let dst = base.join("owned-dest/owned");
            let egid = unsafe { libc::getegid() };
            assert_eq!(
                std::fs::symlink_metadata(&dst).unwrap().gid(),
                egid,
                "CHARACTERIZATION of a DOCUMENTED LIMITATION: the default walk must NOT carry \
                 ownership — the destination entry is owned by the transferring account"
            );
        }

        /// CHARACTERIZATION (divergence): the `cp -a` override documents the
        /// OPPOSITE of the default walk for xattrs and reproduces the source
        /// gid when the caller may set it. Cannot fail pre-fix.
        #[test]
        fn copy_tree_ssh_cp_a_preserves_xattrs_and_gid() {
            let h = SshHarness::new();
            let src = h.root.join("src");
            std::fs::create_dir_all(&src).unwrap();
            let file = src.join("f");
            std::fs::write(&file, b"payload").unwrap();

            let Some(gid) = supplementary_gid() else {
                crate::test_support::announce_skip(
                    "the current user has no supplementary group different from its effective \
                     gid, so the `cp -a` gid-reproduction half cannot be asserted here",
                );
                return;
            };
            chgrp(&file, gid).unwrap();
            let xattr = xattrs_available(&src);
            if xattr {
                set_xattr(&file, "user.storekit.fidelity", b"present").unwrap();
            }

            let t = h.transport();
            t.copy_tree(&rooted("src"), &rooted("dest")).unwrap();
            let dst = h.root.join("dest/f");

            if xattr {
                assert!(
                    has_xattr(&dst, "user.storekit.fidelity"),
                    "CHARACTERIZATION of the DOCUMENTED DIVERGENCE: the SshTransport `cp -a` \
                     override preserves xattrs (unlike the default walk), but it dropped \
                     user.storekit.fidelity"
                );
            }
            assert_eq!(
                std::fs::symlink_metadata(&dst).unwrap().gid(),
                gid,
                "CHARACTERIZATION of the DOCUMENTED DIVERGENCE: `cp -a` reproduces the source \
                 gid when the copier may set it (the default walk does not)"
            );
        }
    }
}
