//! Manifest production for both sides of a transfer, and the typed,
//! path-ordered diff between them.
//!
//! A transfer starts by describing each side as a [`TreeMetadata`] manifest.
//! The LOCAL side is canonicalized directly
//! ([`crate::manifest::canonicalize_tree`]). The REMOTE side branches on
//! [`Remote::is_local`] — the transport's DECLARED nature, never a local
//! filesystem probe of the root path (a probe would silently hash a
//! same-named local directory in place of the remote tree). A local remote is
//! canonicalized directly; a genuinely remote one is hashed ON THE FAR SIDE by
//! the perl verification script
//! ([`crate::manifest::remote_tree_verify_script`]) run through
//! [`Remote::exec`], and the printed per-entry hashes are assembled with
//! [`crate::manifest::canonicalize_remote_entries`], so only hashes cross the
//! link — never the tree bytes.
//!
//! [`diff_trees`] classifies every path in the union of the two manifests as
//! [`EntryDiff::Missing`], [`EntryDiff::Changed`], [`EntryDiff::Extraneous`],
//! or [`EntryDiff::Same`], sorted by path. [`apply_manifests`] produces the
//! pair of manifests [`crate::sync::apply`] actually diffs — the raw
//! primitives' result with the crate's reserved bookkeeping stripped, through
//! the crate's ONE reserved authority ([`crate::reserved`]) — so the diff of
//! THAT pair is the engine's TRANSFER decision surface; producing it reads no
//! content beyond what a manifest already holds.
//!
//! The RAW diff of [`remote_manifest`]/[`remote_destination_manifest`] is NOT
//! that surface. `apply` strips reserved paths BEFORE diffing (a stranded
//! destination `.sync-aside` is `residue`, never `Extraneous`; a source-side
//! one is a `ReservedName` conflict, never `Missing`), and it derives those,
//! plus the unsupported-destination preflight, from the RAW manifests. A
//! consumer that builds a status on the raw primitives MUST call
//! [`apply_manifests`] (and reproduce the extra decisions) or it risks
//! deleting a stranded original or writing into the crate's reserved
//! namespace.

use crate::error::{Error, Result, TransportKind};
use crate::manifest::{
    DestinationTree, TreeEntry, TreeMetadata, canonicalize_remote_entries_checked,
    canonicalize_remote_entries_destination_checked, canonicalize_tree,
    canonicalize_tree_destination, remote_tree_verify_script,
};
use crate::transport::{ExecOutcome, Remote, TimeoutCause};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

/// The exec deadline for the far-side tree hashing script. It bounds one perl
/// process walking the whole tree; 120 s mirrors the source crate's
/// verification timeout and is long enough for a large tree on a slow host
/// while still bounding a hung remote.
pub const REMOTE_MANIFEST_TIMEOUT: Duration = Duration::from_secs(120);

/// The entry kind.
///
/// Defined in [`crate::manifest`] and re-exported here because the kind is a
/// property of a manifest ENTRY, not of the diff: typing the field
/// ([`TreeEntry::entry_type`]) is what removes the "project the `type` string
/// into a kind" re-read at every consumer (API constraint #7). A policy keyed
/// on this kind sees the value the canonicalizer wrote without re-parsing it,
/// and the wire strings the two producers emit still agree by construction
/// (the `manifest` suite pins both the bytes and the accepted spellings).
pub use crate::manifest::EntryKind;

/// The classification of one path present in either manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryDiff {
    /// In the source, not in the destination: the entry must be created.
    Missing,
    /// Present on both sides, but kind, mode, or content hash differs.
    Changed,
    /// In the destination only. Reported; never deleted unless the caller
    /// explicitly asks.
    Extraneous,
    /// Present on both sides with identical metadata. Skipped with NO I/O.
    Same,
}

/// The typed, path-ordered diff between a source and a destination manifest.
///
/// `entries` is sorted by path, so the consuming walk creates each directory
/// before its children (a parent path is always a proper prefix, hence sorts
/// first) and the report is deterministic.
#[derive(Clone, Debug)]
pub struct TreeDiff {
    /// The source manifest (the side the content comes from).
    pub source: TreeMetadata,
    /// The destination manifest (the side the content goes to).
    pub dest: TreeMetadata,
    /// `(path, classification)` for every path in the union, sorted by path.
    pub entries: Vec<(String, EntryDiff)>,
}

impl TreeDiff {
    /// The classification for `path`, or `None` when the path is in neither
    /// manifest (impossible for a path taken from either manifest).
    pub fn classify(&self, path: &str) -> Option<EntryDiff> {
        self.entries
            .binary_search_by(|(p, _)| p.as_str().cmp(path))
            .ok()
            .map(|i| self.entries[i].1)
    }

    /// The number of entries with classification `kind`.
    pub fn count(&self, kind: EntryDiff) -> usize {
        self.entries.iter().filter(|(_, d)| *d == kind).count()
    }

    /// Whether the source and destination manifests are identical (no
    /// transfer of any kind is possible).
    pub fn is_empty(&self) -> bool {
        self.source == self.dest
    }
}

/// The canonical manifest of the local tree at `root`.
///
/// `root` must be a DIRECTORY: an ABSENT root is an error (`canonicalize`
/// fails), never an empty manifest, and a root that is not a directory is an
/// error too. A caller that wants an absent destination ROOT to read as the
/// empty tree is the sync's LOCAL DESTINATION (`LocalSide`), which decides
/// that explicitly before calling a canonicalizer; a caller that wants the
/// destination tolerant of an unrepresentable entry calls
/// [`crate::manifest::canonicalize_tree_destination`].
pub fn local_manifest(root: &Path) -> Result<TreeMetadata> {
    canonicalize_tree(root)
}

/// The canonical manifest of the tree at `remote`'s root, produced according
/// to the transport's DECLARED nature ([`Remote::is_local`]):
///
/// * a LOCAL remote is canonicalized in-process at `remote.root()` — no
///   subprocess, no bytes over any link;
/// * a genuinely REMOTE one is hashed on the far side by
///   [`remote_tree_verify_script`] and only the per-entry hashes come back.
///
/// A remote whose hashing script fails — most importantly a host with no
/// `perl`, which the script's `perl -e` invocation reports as a non-zero exit
/// or a transport error — is an ERROR, never an empty manifest. An empty
/// manifest would read as "the remote tree is empty" and drive a transfer
/// that deletes or rewrites a tree the far side never described. For the same
/// reason this PRIMITIVE reports an ABSENT or non-directory root as an error
/// on BOTH branches; it never describes one as empty. The sync entry points do
/// not rely on the caller: a PUSH calls `Remote::provision_layout`, which
/// creates the destination ROOT (and the caller's bootstrap directories)
/// before this manifest is read, so a fresh remote destination works through
/// the public API. A caller that invokes this primitive directly must create
/// the root or provision the layout first; [`remote_destination_manifest`] is
/// the tolerant destination-side form and still refuses an absent root.
///
/// This is the STRICT form and it describes the SOURCE side: an entry the
/// address-fidelity rules cannot represent (a hard link, an absolute or
/// escaping symlink) makes the whole manifest an ERROR. Use it for the tree
/// the content comes FROM. For the DESTINATION a caller must use
/// [`remote_destination_manifest`], which returns those entries in
/// [`DestinationTree::unsupported`] instead of refusing the tree; that is
/// exactly how the engine describes a destination, so a consumer that builds a
/// status for the destination side from THIS form will refuse a tree the
/// engine handles.
///
/// A consumer that builds a STATUS from this manifest and [`diff_trees`] must
/// first pass the pair through [`apply_manifests`] (and reproduce the engine's
/// reserved-conflict, residue, and unsupported-destination decisions): the raw
/// diff classifies a stranded `.sync-aside` as `Extraneous`/`Missing`, which
/// the engine never does. See the module doc.
///
/// Like the sync entry points, the primitive PREPARES the transport's own
/// host identity before its first remote request
/// ([`Remote::prepare_identity`]); a caller of this function does NOT have to
/// know about that separate step. For `SshTransport` it creates the
/// ControlMaster socket directory the request argv requires, so a fresh
/// transport can read the remote tree at all. The call is idempotent.
///
/// A non-zero exit is classified by LAYER ([`remote_manifest_failure`]): the
/// remote command is `ssh … exec -- perl -e <script> <root>`. `ssh` reserves
/// exit status 255 for its OWN failures, but a far-side `perl` `die` ALSO
/// exits 255: perl exits 255 when `$!` is 0, and the crate's own script
/// measures exactly that for a NON-NFC entry name and for a name (or symlink
/// target) whose diagnostic is hex-encoded (measured on macOS perl 5.34.1 and
/// Linux perl 5.40.1, invoked exactly as the crate invokes it). An ABSENT root
/// and a root that is not a directory both exit 2 instead: `perl -e`'s module
/// loading leaves `$!` = ENOENT, so the script's `absent:` / `not a
/// directory:` `die` propagates 2. They are told apart by the DIAGNOSTIC, not
/// the status: `absent:` maps to [`Error::NotFound`] and `not a directory:`
/// stays a script failure. Exit 255 alone therefore establishes nothing. The
/// layer is
/// attributed only from a POSITIVE diagnostic at the START of a stderr line
/// ([`transport_failed_before_the_command`], [`far_side_script_failed`]);
/// when neither the transport's markers nor the script's own closed `die`
/// vocabulary is present, the exit status and preserved stderr are reported
/// as an UNDETERMINED failure rather than being blamed on any layer. Only the
/// shell's "could not start perl" statuses (126/127) suggest that `perl` may
/// be absent, and even those are VETOED by a positive script `die` diagnostic:
/// on Linux 126/127 are real errno values (ENOKEY / EKEYEXPIRED) that a
/// far-side `die` propagates, so the script's own anchored words outrank the
/// bare status.
pub fn remote_manifest(remote: &dyn Remote) -> Result<TreeMetadata> {
    // SELF-PREPARE: the public primitive a consumer calls must not depend on an
    // undocumented extra caller step. The sync entry points already call
    // `prepare_identity` themselves before their first remote request; this
    // primitive does the same, so a fresh `SshTransport` (whose ControlMaster
    // socket directory has not been created) can read the remote tree. The
    // default is a no-op and a second call is idempotent.
    remote.prepare_identity()?;
    let root = remote.root();
    if remote.is_local() {
        // The transport declares the root LOCAL: canonicalize it in process,
        // but refuse an absent or non-directory root rather than synthesizing
        // an empty manifest from it. The synthesised-empty shortcut is what
        // would let a `delete_extraneous` sync read unreadable far-side state
        // as "nothing is there" and destroy it.
        return match std::fs::symlink_metadata(root) {
            Ok(meta) if meta.is_dir() => canonicalize_tree(root),
            Ok(_) => Err(Error::transport_kind(
                TransportKind::RootNotADirectory,
                format!(
                    "local remote root {} is not a directory; refusing to describe it as a tree",
                    root.display()
                ),
            )),
            // An ABSENT root is the TYPED absence condition, consistent with
            // the remote branch and `Remote::metadata_opt`; every other I/O
            // failure stays a transport error. An absent far side must not
            // read as "the far side described an empty tree".
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::not_found(format!(
                "local remote root {} does not exist; refusing to describe an absent root as a tree",
                root.display()
            ))),
            Err(e) => Err(Error::transport(format!(
                "local remote root {} cannot be described: {e}",
                root.display()
            ))),
        };
    }
    let argv = vec![
        "perl".to_string(),
        "-e".to_string(),
        remote_tree_verify_script().to_string(),
        root.to_string_lossy().into_owned(),
    ];
    let out = remote.exec(&argv, REMOTE_MANIFEST_TIMEOUT)?;
    if !out.success() {
        return Err(remote_manifest_failure(root, &out));
    }
    // The completeness precondition is ENFORCED at this call site: the checked
    // constructor refuses `exited_zero == false`, so the assembler can never
    // describe an incomplete walk as a (possibly empty) faithful tree.
    canonicalize_remote_entries_checked(&out.stdout, root, out.success())
}

/// The DESTINATION-side counterpart of [`remote_manifest`]: the same branch on
/// [`Remote::is_local`] and the same failure classification, but the manifest
/// is built TOLERANT of the address-fidelity refusals a destination may
/// legitimately hold (see [`canonicalize_tree_destination`] and
/// [`canonicalize_remote_entries_destination`]). The tolerated entries are
/// returned in [`DestinationTree::unsupported`] so the sync can classify them
/// as destination-only and let a caller-sanctioned
/// [`crate::sync::Extraneous::Delete`] remove them, and can REFUSE to write a
/// source entry over them.
///
/// AN ABSENT or non-directory root is still an error here, exactly as in
/// [`remote_manifest`]: tolerance covers an ENTRY the strict rules refuse, not
/// a root that cannot be described. A PUSH provisions its destination root
/// before reading this manifest (see `crate::sync::apply`), so a fresh
/// destination is a real directory by the time this runs.
///
/// This is the DESTINATION-side form and the ONE to use for the side content
/// goes TO; [`remote_manifest`] is the strict SOURCE-side form. It is
/// self-preparing exactly as [`remote_manifest`] is (see there).
///
/// As with [`remote_manifest`], a status built by diffing this result directly
/// must first pass the pair through [`apply_manifests`]; the raw diff would
/// report a stranded `.sync-aside` as `Extraneous` (deletable) where the
/// engine reports it as `residue`.
pub fn remote_destination_manifest(remote: &dyn Remote) -> Result<DestinationTree> {
    // SELF-PREPARE, exactly as the source-side primitive does: a consumer
    // calling this directly on a fresh transport must not need a separate
    // `prepare_identity` call.
    remote.prepare_identity()?;
    let root = remote.root();
    if remote.is_local() {
        return match std::fs::symlink_metadata(root) {
            Ok(meta) if meta.is_dir() => canonicalize_tree_destination(root),
            Ok(_) => Err(Error::transport_kind(
                TransportKind::RootNotADirectory,
                format!(
                    "local remote root {} is not a directory; refusing to describe it as a tree",
                    root.display()
                ),
            )),
            // An ABSENT root is the TYPED absence condition (see
            // [`remote_manifest`]); every other I/O failure stays a transport
            // error.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::not_found(format!(
                "local remote root {} does not exist; refusing to describe an absent root as a tree",
                root.display()
            ))),
            Err(e) => Err(Error::transport(format!(
                "local remote root {} cannot be described: {e}",
                root.display()
            ))),
        };
    }
    let argv = vec![
        "perl".to_string(),
        "-e".to_string(),
        remote_tree_verify_script().to_string(),
        root.to_string_lossy().into_owned(),
    ];
    let out = remote.exec(&argv, REMOTE_MANIFEST_TIMEOUT)?;
    if !out.success() {
        return Err(remote_manifest_failure(root, &out));
    }
    // Same enforced completeness precondition on the DESTINATION side.
    canonicalize_remote_entries_destination_checked(&out.stdout, root, out.success())
}

/// The pair of manifests `crate::sync::apply` actually DIFFS: the SOURCE with
/// every unaddressable path removed and the DESTINATION with its RESIDUE
/// removed, both through the crate's ONE reserved authority
/// ([`crate::reserved`]). `diff_trees(&source, &dest)` of the results is the
/// engine's transfer decision surface.
///
/// A consumer building a status from the RAW manifest primitives MUST apply
/// this first. Without it the raw diff classifies a stranded destination
/// `.sync-aside.<pid>.<n>` as [`EntryDiff::Extraneous`] — i.e. DELETABLE under
/// `Extraneous::Delete` — while the engine reports it as `residue` and never
/// deletes it, and it classifies a source-side `.sync-aside.<pid>.<n>` as
/// [`EntryDiff::Missing`] while the engine refuses it with a `ReservedName`
/// conflict. Acting on the raw list therefore risks destroying a stranded
/// original or writing into the crate's reserved namespace.
///
/// The two sides strip DIFFERENT sets on purpose (see [`crate::sync::apply`]):
/// a reserved-namespaced CRATE TEMP is stripped from the source so it is never
/// replicated, but LEFT in the destination so the diff reports it as
/// destination-only; a genuine stranded aside is stripped from BOTH so it is
/// never transferred or removed.
///
/// The diff alone is NOT the whole `apply` decision surface: `apply` also
/// derives source `ReservedName` conflicts, destination `residue`, and the
/// unsupported-destination preflight from the RAW manifests, and a consumer
/// reporting those must do the same ([`crate::reserved`] and
/// [`remote_destination_manifest`] are the authorities).
///
/// The tree digest is recomputed so each returned manifest stays
/// self-consistent.
///
/// The destination is a [`DestinationTree`], NOT a bare `&TreeMetadata`: the
/// destination side of a transfer is an OBSERVATION, and API constraint #7
/// keeps the two directions apart in the type. A `&TreeMetadata` in this
/// position no longer typechecks, so a caller cannot feed a canonical SOURCE
/// manifest where the destination is expected (see the `compile_fail` example
/// on [`DestinationTree`]).
pub fn apply_manifests(
    source: &TreeMetadata,
    dest: &DestinationTree,
) -> (TreeMetadata, DestinationTree) {
    let stripped_dest = strip_reserved(dest.meta.clone(), crate::reserved::is_residue_path);
    (
        strip_reserved(source.clone(), crate::reserved::is_unaddressable_path),
        DestinationTree {
            meta: stripped_dest,
            unsupported: dest.unsupported.clone(),
        },
    )
}

/// Strip every path matching `reserved` from a manifest, recomputing the tree
/// digest so the manifest stays self-consistent. The predicate is a PARAMETER
/// because the source and the destination strip DIFFERENT sets
/// ([`apply_manifests`]). `compute_tree_digest` hashes the serialized metadata
/// INCLUDING `tree_sha256`, so the field is BLANKED before recomputing:
/// otherwise the new digest would hash the old one in and depend on the
/// pre-strip value (non-canonical, non-idempotent). Every other producer of a
/// tree digest blanks the field first.
pub(crate) fn strip_reserved(mut meta: TreeMetadata, reserved: fn(&str) -> bool) -> TreeMetadata {
    meta.entries.retain(|entry| !reserved(&entry.path));
    meta.tree_sha256 = String::new();
    meta.tree_sha256 = crate::manifest::compute_tree_digest(&meta);
    meta
}

/// The error for a NON-ZERO exit of the far-side manifest command, classified
/// by the LAYER that failed.
///
/// The command is `ssh … exec -- perl -e <script> <root>`, so a non-zero exit
/// can come from any of several layers, and they are not interchangeable:
///
/// * the TRANSPORT failed before the command ran — the runner reports the
///   typed [`TimeoutCause::CommandStillRunning`] when it killed the child at
///   the deadline while the far-side command was still running (no far-side
///   exit status can be negative, and a signal-killed child also reports
///   `-1`, so the `-1` STATUS alone is not the authority — the typed cause
///   is); `ssh` also reserves exit status 255 for its own failures
///   (connection refused/timed out, authentication, host-key verification,
///   the `ControlMaster` control socket), but a far-side `perl` `die`
///   propagates 255 too, so 255 selects this branch ONLY with an
///   EVIDENCE-BACKED transport diagnostic at the start of a stderr line. Exit
///   255 alone names no layer and is never reported as transport;
/// * the far-side `perl` could not be STARTED — the remote shell's 126/127
///   ("found but not executable" / "not found"), which is the only layer that
///   is actually a statement about `perl`. A POSITIVE anchored script `die`
///   diagnostic OUTRANKS this bare status: on Linux 126/127 are real errno
///   values (ENOKEY / EKEYEXPIRED) that keyring-backed trees return, and the
///   script's `die` propagates `$!`, so a genuine script failure can carry
///   those statuses;
/// * `perl` ran and the script exited non-zero — recognised by the script's
///   OWN closed `die` prefix at the start of a stderr line (a missing root,
///   an unreadable directory, a name that cannot cross the wire, ...);
/// * the far-side command RAN and EXITED, but only its bounded post-exit
///   output DRAIN gave up (the typed [`TimeoutCause::OutputDrainGaveUp`]): a
///   process that outlived the command held a pipe open past the drain's
///   bound, so the exit status the reap HAD collected could not be reported.
///   The bound is the runner's post-exit drain bound, which is independent of
///   the caller's deadline, so this branch does NOT assert a deadline was
///   outlasted. It is NOT the transport-before-command layer — the command
///   started and finished;
/// * NONE of the above is established — the exit status and preserved stderr
///   are reported as UNDETERMINED, naming no layer. This is the honest
///   outcome for a status no rule covers (200, a signal-killed `137` with
///   empty stderr, a locally-generated outlier): an earlier version asserted
///   the far-side script here, which is a layer it cannot establish.
///
/// Pre-fix every non-zero exit appended "(is perl installed on the remote
/// host?)", so an `ssh` exit 255 — including the `unix_listener:` control-
/// socket bind failure — was mislabeled as a missing interpreter; the fix
/// after that made every exit 255 transport, which mislabeled the script's
/// own `die`-at-255 refusals; the fix after that DELETED `Permission denied`
/// from the transport markers on the stated grounds that the script prints it,
/// which mislabeled a real ssh authentication failure at 255 (the script's
/// own `Permission denied` path exits 13, so inside the 255 gate the phrase is
/// NOT the script). This version restores authentication recognition inside
/// the 255 gate and attributes the layer from EVIDENCE in stderr — anchored at
/// a line start — reporting an undetermined failure rather than asserting ssh,
/// connection, authentication, or the script.
fn remote_manifest_failure(root: &Path, out: &ExecOutcome) -> Error {
    let stderr = out.stderr.trim();
    let stderr = if stderr.is_empty() {
        "(no stderr)"
    } else {
        stderr
    };
    // The ABSENT root is a TYPED, distinguishable condition, not a transport
    // failure: the far-side script reports `absent: <root>` (distinct from
    // `not a directory: <root>`) and a consumer must not have to string-match
    // it apart from an unreachable host. `Error::NotFound` is the crate's
    // absence class, matching `Remote::metadata_opt` and the local branch.
    if stderr_line_starts_with(stderr, ABSENT_ROOT_PREFIX) {
        return Error::not_found(format!(
            "remote tree verification at {} found no root on the far side: the far-side manifest \
             script reported {:?}. An ABSENT root (this error) is distinct from an unreachable host \
             or a failed transport (a transport error) and from a root that exists but is not a \
             directory (a script failure); the caller may create the root or provision the layout \
             and retry",
            root.display(),
            stderr
        ));
    }
    // The typed cause is the authority, and this one is decisive: the command
    // RAN and EXITED, and only its bounded post-exit output drain gave up
    // (a pipe-holding process outlived the command). Naming the
    // transport-before-command layer here would be false — the exact
    // misclassification the bounded drain introduced when it gave the
    // runner's `-1` a second meaning. The message does NOT claim a deadline
    // was outlasted (the drain bound is independent of the deadline), and it
    // does NOT claim the status was never collected: the reap collected it,
    // and the `Background` error carries only the message, so the status was
    // discarded and `exit_code` is the `-1` sentinel.
    if out.timeout_cause == Some(TimeoutCause::OutputDrainGaveUp) {
        return Error::transport_kind(
            TransportKind::OutputDrainGaveUp,
            format!(
                "remote tree verification at {} could not report the far-side manifest command's \
                 output: the command ran and exited, but a process that outlived it held its output \
                 pipes open past the post-exit drain bound, so the runner gave up on the drain and the \
                 exit status it had already collected was discarded (the reported exit {} is the \
                 sentinel): {}",
                root.display(),
                out.exit_code,
                stderr
            ),
        );
    }
    // F1: the far-side script's own anchored `die` diagnostic is EVIDENCE
    // about the layer and VETOES the bare 126/127 STATUS (the veto lives in
    // [`perl_could_not_start`]): on Linux 126/127 are real errno values
    // (ENOKEY / EKEYEXPIRED) that keyring-backed trees return and the script's
    // `die` propagates `$!`. Verified in the `perl_could_not_start` branch
    // below, then reported by [`far_side_script_failed`] after the transport
    // rule (a script diagnostic is not transport evidence).
    if perl_could_not_start(out) {
        return Error::transport_kind(
            TransportKind::InterpreterMissing,
            format!(
                "remote tree verification at {} could not start the far-side `perl` (exit {}): {} \
                 (is perl installed on the remote host?)",
                root.display(),
                out.exit_code,
                stderr
            ),
        );
    }
    if transport_failed_before_the_command(out) {
        return Error::transport_kind(
            TransportKind::BeforeCommand,
            format!(
                "remote tree verification at {} could not run: the transport failed before the \
                 far-side command started (exit {}): {} (this is a transport-level failure — \
                 connection, authentication, host key, or the ssh control socket)",
                root.display(),
                out.exit_code,
                stderr
            ),
        );
    }
    if far_side_script_failed(out) {
        return Error::transport_kind(
            TransportKind::FarSideScript,
            format!(
                "remote tree verification at {} failed inside the far-side manifest script (exit {}): {}",
                root.display(),
                out.exit_code,
                stderr
            ),
        );
    }
    // No rule establishes the layer: report only what is KNOWN. Naming the
    // transport, the shell, or the script here would assert a layer the
    // evidence does not support — the defect this branch replaces.
    Error::transport_kind(
        TransportKind::Undetermined,
        format!(
            "remote tree verification at {} failed: the remote manifest command exited {} with {} \
             (the exit status and stderr are preserved verbatim; the available evidence does not \
             establish which layer produced this failure, so it is reported as undetermined rather \
             than attributed to one)",
            root.display(),
            out.exit_code,
            stderr
        ),
    )
}

/// Whether `out` reports that the far-side `perl` program itself could not be
/// started (as opposed to running and exiting non-zero).
fn perl_could_not_start(out: &ExecOutcome) -> bool {
    // F1 VETO: an anchored script `die` diagnostic means `perl` RAN, so the
    // not-started statuses below cannot be a statement about starting `perl`.
    // This is load-bearing on Linux, where 126/127 are real errno values
    // (ENOKEY / EKEYEXPIRED) that keyring-backed trees return and the script's
    // `die` propagates `$!`; the same stderr at any other status already
    // classifies as the script, so the STATUS is what would misroute it. The
    // veto lives HERE (the rule's own authority), not only in the caller's
    // branch order, so the rule cannot be broken by reordering.
    if far_side_script_failed(out) {
        return false;
    }
    // EVIDENCE-BACKED (POSIX shells; measured on macOS and Linux): 126 = found
    // but not executable, 127 = not found. The remote command is
    // `exec -- perl -e …`, so both statuses name the `perl` program. The
    // STATUS is the primary signal — a real shell that cannot find `perl`
    // exits 127 (`bash: perl: command not found`), which the anchored
    // diagnostic below deliberately does NOT match, because `bash: perl:` is
    // not the start of a line.
    if out.exit_code == 126 || out.exit_code == 127 {
        return true;
    }
    // Plausible-but-unverified secondary signal, ANCHORED at a line start: a
    // wrapper that prints the diagnostic but exits with a status of its own
    // (not 126/127). Anchoring is load-bearing: the far-side script echoes a
    // non-NFC name RAW, so a bare `contains` let a name `perl: command not
    // found` route a script failure to this branch.
    [
        "perl: command not found",
        "perl: not found",
        "perl: No such file",
    ]
    .iter()
    .any(|marker| stderr_line_starts_with(&out.stderr, marker))
}

/// Whether `out` reports a failure of the TRANSPORT layer, before the far-side
/// command could run at all.
///
/// Evidence, not a guess from the exit status: the runner's TYPED
/// [`TimeoutCause::CommandStillRunning`] is conclusive on its own (the deadline
/// killed a running child, so no far-side command produced the outcome), but
/// `ssh` exit status 255 is NOT, because a far-side `perl` `die` propagates the
/// same status (perl exits 255 when `$!` is 0) — the crate's own manifest
/// script does exactly that for a non-NFC name and for a hex-encoded
/// name/target refusal. Exit 255 therefore selects this branch only with a
/// positive transport diagnostic at the START of a stderr line. A bare
/// `exit_code == -1` selects nothing: the typed cause must say
/// `CommandStillRunning` (a signal-killed child also reports `-1`, and a
/// command whose bounded post-exit drain gave up is its own cause).
///
/// ANCHORING BOUND (measured with the real script): line-anchoring closes
/// every FAR-SIDE-TREE spoof. A non-NFC entry name is echoed raw, but always
/// AFTER the script's own closed `die` prefix (`entry name under …`), and a
/// name containing LF/CR/TAB is hex-encoded rather than echoed, so a crafted
/// ENTRY name — or a ROOT DIRECTORY named `Host key verification failed store`
/// — cannot place a marker at a line start.
///
/// The reachable at-255 residual is NOT far-side tree text: the script
/// interpolates `$dir` and `$p` into its own `die` lines (e.g.
/// `entry name under $dir is not NFC-normalized: $n`, `lstat $p: $!`), so a
/// ROOT DIRECTORY whose own name contains a raw LF can start a marker line.
/// MEASURED with the real script: a root directory named
/// `x\nssh: connect to host evil port 1: Connection refused\ny` holding any
/// non-NFC entry exits 255 and puts `ssh: connect to host evil port 1:
/// Connection refused` at the start of a line, which classifies as transport.
/// (The earlier documented example — `not a directory: $root` echoing the root
/// raw — was WRONG: measured, that spelling exits 2 and correctly lands in the
/// script branch, because `perl -e`'s module loading leaves `$!` = ENOENT.)
/// The root is chosen by the CALLER, never by the tree being described, and
/// [`crate::transport::SshTransport::new`] validates only ABSOLUTENESS and the
/// presence of a normal component below the filesystem root — it does not
/// reject a raw LF — so the crate RELIES ON THE CALLER for a root the wire can
/// represent. The severity is unchanged: caller-chosen, not far-side text.
fn transport_failed_before_the_command(out: &ExecOutcome) -> bool {
    // The TYPED cause is the authority for the `-1` cases. The bare
    // `exit_code == -1` sentinel is ambiguous after the post-exit drain was
    // bounded: the same status also covers a signal-killed child and a
    // command that exited while its output drain gave up.
    match out.timeout_cause {
        // The runner killed the child at the deadline while the far-side
        // command was still running, so no far-side command produced this
        // outcome. The typed cause needs no textual corroboration.
        Some(TimeoutCause::CommandStillRunning) => return true,
        // The command RAN and EXITED; only its bounded drain gave up. This is
        // NOT the transport-before-command layer (its own branch in
        // [`remote_manifest_failure`] reports it).
        Some(TimeoutCause::OutputDrainGaveUp) => return false,
        None => {}
    }
    // `ssh` exits 255 for its own failures, but the far-side perl `die` does
    // too, so 255 alone proves nothing. Require positive transport evidence.
    if out.exit_code != 255 {
        return false;
    }
    stderr_is_auth_failure(&out.stderr) || transport_marker_at_line_start(&out.stderr)
}

/// Whether any line of `stderr` begins with `marker`.
///
/// Line ANCHORING is deliberate and load-bearing. The far-side script echoes
/// a non-NFC entry NAME raw, and that name is far-side-chosen text; a bare
/// `contains` match let a name `ssh: connect to host …` (or a root directory
/// named `Host key verification failed store`) route a script failure to the
/// TRANSPORT branch. Requiring the marker at offset 0 or immediately after a
/// `\n` removes every such spoof: the script's raw-name line always begins
/// with the closed `die` prefix (`entry name under …`), never with an ssh
/// marker, and a name containing LF/CR/TAB is hex-encoded rather than echoed,
/// so it cannot start a line. See the residual bound on
/// [`transport_failed_before_the_command`].
fn stderr_line_starts_with(stderr: &str, marker: &str) -> bool {
    stderr.split('\n').any(|line| line.starts_with(marker))
}

/// Whether `stderr` carries an OpenSSH authentication failure at the start of
/// a line.
///
/// EVIDENCE-BACKED (OpenSSH 10.2p1, macOS and Linux): a rejected public-key
/// authentication prints `<user>@<host>: Permission denied (publickey).`,
/// whose line START is the `user@host` shape, so it cannot be matched by the
/// bare marker `Permission denied` at line start. The pattern is anchored
/// exactly as the real output is: a whitespace-free `something@something:`
/// target followed by `: Permission denied`, OR `Permission denied` alone at
/// the start of a line (PLAUSIBLE-BUT-UNVERIFIED as a bare spelling, kept
/// because at a 255 status the script cannot produce it: every script `die`
/// line starts with the closed vocabulary below). `Permission denied` is
/// accepted here ONLY inside the 255 gate: the crate's own unreadable-directory
/// path prints `opendir …: Permission denied` but exits 13, so at a non-255
/// status the phrase says nothing about the transport.
fn stderr_is_auth_failure(stderr: &str) -> bool {
    stderr.split('\n').any(|line| {
        line.starts_with("Permission denied")
            || line
                .split_once(": Permission denied")
                .is_some_and(|(who, _)| {
                    !who.is_empty() && who.contains('@') && !who.contains(char::is_whitespace)
                })
    })
}

/// EVIDENCE-BACKED OpenSSH diagnostics for a failure BEFORE the far-side
/// command ran, each at the START of a stderr line. Observed from real
/// OpenSSH 10.2p1 on macOS and Linux; the authentication shape is handled
/// separately by [`stderr_is_auth_failure`]. `unix_listener:` is the
/// `ControlMaster` control-socket bind failure; `kex_exchange_identification`
/// is a pre-auth key-exchange failure.
///
/// The four connect-stage spellings at the end are PLAUSIBLE-BUT-UNVERIFIED
/// as line starts: real OpenSSH prints them behind the `ssh: ` prefix
/// (`ssh: connect to host … port …: Connection refused`), which is already
/// matched, so they add no coverage today; they are kept, anchored, as
/// belt-and-braces for a wrapper or a build that drops the prefix.
fn transport_marker_at_line_start(stderr: &str) -> bool {
    const TRANSPORT_MARKERS: &[&str] = &[
        "ssh: ",
        "kex_exchange_identification",
        "Host key verification failed",
        "Connection closed by",
        "Received disconnect from",
        "Timeout, server ",
        "Too many authentication failures",
        "unix_listener:",
        "Connection refused",
        "Connection timed out",
        "No route to host",
        "Network is unreachable",
    ];
    TRANSPORT_MARKERS
        .iter()
        .any(|marker| stderr_line_starts_with(stderr, marker))
}

/// The far-side manifest script's own closed `die` vocabulary. Every entry is
/// the literal start of a stderr line the script writes before exiting
/// non-zero (see [`crate::manifest::remote_tree_verify_script`]); the
/// vocabulary is closed because the script has exactly one `die` per
/// condition and nothing else writes its stderr.
/// The far-side script's ABSENT-ROOT diagnostic, at the START of a stderr line
/// (see [`crate::manifest::remote_tree_verify_script`]). Distinct from
/// [`SCRIPT_DIE_PREFIXES`]'s `not a directory: ` on purpose: the first is the
/// typed [`crate::Error::NotFound`] condition, the second is a root that
/// exists but cannot be described.
const ABSENT_ROOT_PREFIX: &str = "absent: ";

const SCRIPT_DIE_PREFIXES: &[&str] = &[
    "absent: ",
    "not a directory: ",
    "entry name under ",
    "symlink target of ",
    "lstat ",
    "open ",
    "readlink ",
    "opendir ",
    "readdir ",
    "closedir ",
];

/// Whether the far-side `perl` RAN and its script exited non-zero, i.e. the
/// failure is inside the manifest script rather than the transport or the
/// shell. Recognised by the script's OWN closed `die` prefix at the start of
/// a stderr line — the only writer that can produce those lines. The exit
/// status alone is NOT used: the same statuses can come from a shell or a
/// signal (`137`, `200`), which is exactly the case the undetermined branch
/// exists for.
fn far_side_script_failed(out: &ExecOutcome) -> bool {
    SCRIPT_DIE_PREFIXES
        .iter()
        .any(|prefix| stderr_line_starts_with(&out.stderr, prefix))
}

/// The DIRECTION-TYPED diff: a canonical SOURCE manifest against a
/// [`DestinationTree`] observation, producing exactly [`diff_trees`]'s result.
///
/// [`diff_trees`] stays for two canonical manifests (a snapshot against a live
/// tree, say). This entry point exists so the destination position takes the
/// destination TYPE: a caller cannot pass the destination observation as the
/// source (that is a `compile_fail` example on [`DestinationTree`]), and cannot
/// accidentally diff a source manifest against another source manifest while
/// believing one side is the destination.
pub fn diff_source_and_destination(source: &TreeMetadata, dest: &DestinationTree) -> TreeDiff {
    diff_trees(source, &dest.meta)
}

/// Classify every path in the union of `source` and `dest`, sorted by path.
///
/// This is the RAW differ: it classifies exactly the manifests it is given, so
/// its result is the engine's transfer decision surface only when the
/// arguments are [`apply_manifests`]'s output. A `source`/`dest` straight from
/// [`remote_manifest`]/[`remote_destination_manifest`] still contains the
/// crate's reserved bookkeeping, which `apply` strips first; see the module
/// doc.
pub fn diff_trees(source: &TreeMetadata, dest: &TreeMetadata) -> TreeDiff {
    let source_map: BTreeMap<&str, &TreeEntry> = source
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect();
    let dest_map: BTreeMap<&str, &TreeEntry> =
        dest.entries.iter().map(|e| (e.path.as_str(), e)).collect();
    let paths: BTreeSet<&str> = source_map.keys().chain(dest_map.keys()).copied().collect();

    let mut entries = Vec::with_capacity(paths.len());
    for path in paths {
        let class = match (source_map.get(path), dest_map.get(path)) {
            (Some(_), None) => EntryDiff::Missing,
            (None, Some(_)) => EntryDiff::Extraneous,
            (Some(s), Some(d)) => {
                if manifest_entry_equal(s, d) {
                    EntryDiff::Same
                } else {
                    EntryDiff::Changed
                }
            }
            // Unreachable: `path` is a key of at least one of the two maps, so
            // both lookups cannot miss. A sync tool must not panic on
            // malformed input, so skip the (impossible) path instead of
            // aborting the process.
            (None, None) => continue,
        };
        entries.push((path.to_string(), class));
    }
    TreeDiff {
        source: source.clone(),
        dest: dest.clone(),
        entries,
    }
}

/// Whether two manifest entries at the SAME path describe identical
/// metadata: kind, mode, content hash, and symlink target. Any difference is
/// a [`EntryDiff::Changed`].
fn manifest_entry_equal(a: &TreeEntry, b: &TreeEntry) -> bool {
    a.path == b.path
        && a.entry_type == b.entry_type
        && a.mode == b.mode
        && a.content_sha256 == b.content_sha256
        && a.symlink_target == b.symlink_target
}

#[cfg(test)]
mod tests {
    // Helpers used only by `#[cfg(unix)]` tests are legitimately unused on
    // Windows; do not let them fail a `-D warnings` Windows gate.
    #![cfg_attr(not(unix), allow(dead_code))]
    use super::*;
    use crate::env::SysEnv;
    use crate::test_support::{announce_skip, fixture_tmpdir};
    use crate::transport::{
        CreateNewVerdict, FsBytes, Layout, LocalTransport, RemoteEntry, RemoteMeta,
        RootedRelativePath,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn write(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
    }

    /// A [`Remote`] that REFUSES to run a remote request before
    /// [`Remote::prepare_identity`] has been called — the trait's stated
    /// contract, made enforceable. Every other method delegates to an inner
    /// [`LocalTransport`]; `is_local` is `false` so the manifest primitives
    /// take their genuinely-REMOTE `exec` branch.
    struct IdentityProbe {
        inner: LocalTransport,
        prepared: AtomicBool,
        execs: AtomicUsize,
    }

    impl IdentityProbe {
        fn over(root: PathBuf) -> IdentityProbe {
            IdentityProbe {
                inner: LocalTransport::new(&SysEnv::from_process(), root, Layout::empty()).unwrap(),
                prepared: AtomicBool::new(false),
                execs: AtomicUsize::new(0),
            }
        }
    }

    impl Remote for IdentityProbe {
        fn root(&self) -> &Path {
            self.inner.root()
        }
        fn is_local(&self) -> bool {
            false
        }
        fn prepare_identity(&self) -> Result<()> {
            self.prepared.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn read(&self, rel: &RootedRelativePath) -> Result<Vec<u8>> {
            self.inner.read(rel)
        }
        fn write(&self, rel: &RootedRelativePath, data: &[u8], mode: u32) -> Result<()> {
            self.inner.write(rel, data, mode)
        }
        fn try_write_new(&self, rel: &RootedRelativePath, data: &[u8]) -> Result<CreateNewVerdict> {
            self.inner.try_write_new(rel, data)
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
        fn symlink(&self, target: &Path, link: &RootedRelativePath) -> Result<()> {
            self.inner.symlink(target, link)
        }
        fn read_link(&self, rel: &RootedRelativePath) -> Result<PathBuf> {
            self.inner.read_link(rel)
        }
        fn remove_file(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.remove_file(rel)
        }
        fn remove_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.remove_dir_all(rel)
        }
        fn remove_dir(&self, rel: &RootedRelativePath) -> Result<()> {
            self.inner.remove_dir(rel)
        }
        fn metadata(&self, rel: &RootedRelativePath) -> Result<RemoteMeta> {
            self.inner.metadata(rel)
        }
        fn exec(&self, _argv: &[String], _timeout: Duration) -> Result<ExecOutcome> {
            if !self.prepared.load(Ordering::SeqCst) {
                return Err(Error::transport(
                    "remote request before prepare_identity: the manifest primitive must self-prepare",
                ));
            }
            self.execs.fetch_add(1, Ordering::SeqCst);
            // An EMPTY successful listing: the primitives then assemble the
            // empty manifest, which is all this test needs to observe.
            Ok(ExecOutcome {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                timeout_cause: None,
            })
        }
        fn filesystem_bytes(&self) -> Result<FsBytes> {
            self.inner.filesystem_bytes()
        }
    }

    /// Gap 4: the RAW diff of the public primitives is NOT `apply`'s decision
    /// surface. A stranded SOURCE `.sync-aside` reads as `Missing` (the engine
    /// refuses it with a `ReservedName` conflict) and a stranded DESTINATION
    /// `.sync-aside` reads as `Extraneous` — i.e. DELETABLE — while the engine
    /// reports it as `residue` and never deletes it. [`apply_manifests`] is the
    /// public strip that makes the claim true: the same pair diffed after it
    /// contains neither reserved path, so a consumer cannot act on a
    /// syntactically-reserved name.
    #[test]
    fn apply_manifests_strips_the_reserved_trap_from_the_raw_primitives() {
        let dir = fixture_tmpdir(&SysEnv::from_process()).unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        write(&src.join("f"), b"same");
        write(&src.join(".sync-aside.7.0"), b"stranded-source");
        write(&dst.join("f"), b"same");
        write(&dst.join(".sync-aside.4242.0"), b"stranded-dest");

        let src_t =
            LocalTransport::new(&SysEnv::from_process(), src.clone(), Layout::empty()).unwrap();
        let dst_t =
            LocalTransport::new(&SysEnv::from_process(), dst.clone(), Layout::empty()).unwrap();
        let source = remote_manifest(&src_t).unwrap();
        let destination = remote_destination_manifest(&dst_t).unwrap();

        let raw = diff_source_and_destination(&source, &destination);
        assert_eq!(
            raw.classify(".sync-aside.7.0"),
            Some(EntryDiff::Missing),
            "the RAW source diff shows a reserved aside as content to install"
        );
        assert_eq!(
            raw.classify(".sync-aside.4242.0"),
            Some(EntryDiff::Extraneous),
            "the RAW destination diff shows a stranded aside as deletable"
        );

        let (source_stripped, dest_stripped) = apply_manifests(&source, &destination);
        let decision = diff_source_and_destination(&source_stripped, &dest_stripped);
        assert_eq!(
            decision.classify(".sync-aside.7.0"),
            None,
            "the engine's decision surface never names a reserved source path"
        );
        assert_eq!(
            decision.classify(".sync-aside.4242.0"),
            None,
            "the engine's decision surface never names a stranded destination aside"
        );
        assert_eq!(decision.classify("f"), Some(EntryDiff::Same));
    }

    /// D3: `remote_manifest` and `remote_destination_manifest` PREPARE the
    /// transport's host identity before their first remote request, exactly as
    /// the sync entry points do. Pre-fix they did not, so a fresh
    /// `SshTransport` failed a status-only read with
    /// `unix_listener: cannot bind to path .../dmux/...`. The probe refuses any
    /// `exec` before preparation, so the primitive's OWN call is the only thing
    /// that can make this pass.
    #[test]
    fn manifest_primitives_prepare_the_transport_identity() {
        let dir = fixture_tmpdir(&SysEnv::from_process()).unwrap();
        let root = dir.path().join("r");
        fs::create_dir_all(&root).unwrap();
        let probe = IdentityProbe::over(root);

        let manifest = remote_manifest(&probe)
            .expect("remote_manifest must prepare the transport identity before its request");
        assert!(probe.prepared.load(Ordering::SeqCst));
        assert_eq!(probe.execs.load(Ordering::SeqCst), 1);
        assert!(manifest.entries.is_empty());

        probe.prepared.store(false, Ordering::SeqCst);
        let destination = remote_destination_manifest(&probe).expect(
            "remote_destination_manifest must prepare the transport identity before its request",
        );
        assert!(probe.prepared.load(Ordering::SeqCst));
        assert_eq!(probe.execs.load(Ordering::SeqCst), 2);
        assert!(destination.entries().is_empty());
    }

    /// Build a tree containing one entry of EACH kind so the kind-string
    /// mapping can be checked against the canonicalizer that emits it.
    fn tree_with_every_kind(root: &Path) {
        fs::create_dir_all(root.join("dir")).unwrap();
        write(&root.join("dir/file"), b"payload");
        #[cfg(unix)]
        std::os::unix::fs::symlink("dir/file", root.join("link")).unwrap();
        #[cfg(windows)]
        crate::platform::symlink(Path::new("dir/file"), &root.join("link")).unwrap();
    }

    /// The mapping from manifest `type` string to [`EntryKind`] is derived
    /// from the canonicalizer, not guessed: canonicalize a tree with a file, a
    /// directory, and a symlink and assert each entry's VALIDATED kind equals
    /// [`EntryKind::as_str`].
    #[test]
    fn entry_kind_strings_match_the_canonicalizer() {
        let dir = fixture_tmpdir(&SysEnv::from_process()).unwrap();
        let root = dir.path().join("tree");
        tree_with_every_kind(&root);
        let meta = canonicalize_tree(&root).unwrap();
        let mut seen = BTreeSet::new();
        for entry in &meta.entries {
            let kind = entry.entry_type;
            let wire = serde_json::to_value(entry).unwrap();
            assert_eq!(wire["type"], kind.as_str());
            seen.insert(kind);
        }
        assert_eq!(
            seen,
            BTreeSet::from([EntryKind::File, EntryKind::Dir, EntryKind::Symlink]),
            "the fixture exercises every canonical entry kind"
        );
    }

    /// A manifest entry kind outside the canonical set is refused, and the
    /// refusal now lives at the WIRE boundary (`Deserialize`) rather than in a
    /// per-consumer projection: a JSON record naming an unknown kind cannot
    /// become a [`crate::manifest::TreeEntry`] at all.
    #[test]
    fn unknown_entry_type_is_refused_at_deserialization() {
        let json = r#"{"path":"x","type":"socket","mode":"0644"}"#;
        assert!(
            serde_json::from_str::<crate::manifest::TreeEntry>(json).is_err(),
            "a kind outside the canonical set must not deserialize"
        );
        let ok = r#"{"path":"x","type":"file","mode":"0644","content_sha256":"ab"}"#;
        let entry = serde_json::from_str::<crate::manifest::TreeEntry>(ok).unwrap();
        assert_eq!(entry.entry_type, EntryKind::File);
    }

    /// Every path in the union is classified, and the classes are:
    /// source-only -> Missing, dest-only -> Extraneous, identical -> Same,
    /// any metadata difference -> Changed.
    #[test]
    fn diff_classifies_every_path_and_is_path_ordered() {
        let dir = fixture_tmpdir(&SysEnv::from_process()).unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        write(&src.join("same"), b"same");
        write(&src.join("changed"), b"new");
        write(&src.join("missing"), b"only-source");
        write(&src.join("a/deep"), b"deep");
        write(&dst.join("same"), b"same");
        write(&dst.join("changed"), b"old");
        write(&dst.join("extra"), b"only-dest");
        write(&dst.join("a/deep"), b"deep");

        let source = canonicalize_tree(&src).unwrap();
        let dest = canonicalize_tree(&dst).unwrap();
        let diff = diff_trees(&source, &dest);

        assert_eq!(diff.classify("same"), Some(EntryDiff::Same));
        assert_eq!(diff.classify("changed"), Some(EntryDiff::Changed));
        assert_eq!(diff.classify("missing"), Some(EntryDiff::Missing));
        assert_eq!(diff.classify("extra"), Some(EntryDiff::Extraneous));
        assert_eq!(diff.classify("a/deep"), Some(EntryDiff::Same));
        assert_eq!(diff.classify("a"), Some(EntryDiff::Same));
        assert_eq!(diff.classify("nonexistent"), None);

        let paths: Vec<&str> = diff.entries.iter().map(|(p, _)| p.as_str()).collect();
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted, "the diff is ordered by path");
        assert_eq!(diff.count(EntryDiff::Missing), 1);
        assert_eq!(diff.count(EntryDiff::Extraneous), 1);
        assert_eq!(diff.count(EntryDiff::Changed), 1);
        assert_eq!(diff.count(EntryDiff::Same), 3);
    }

    /// A mode-only difference is `Changed` even though the content hash is
    /// identical.
    #[cfg(unix)]
    #[test]
    fn mode_only_difference_is_changed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fixture_tmpdir(&SysEnv::from_process()).unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        write(&src.join("f"), b"same");
        write(&dst.join("f"), b"same");
        fs::set_permissions(src.join("f"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(dst.join("f"), fs::Permissions::from_mode(0o600)).unwrap();

        let source = canonicalize_tree(&src).unwrap();
        let dest = canonicalize_tree(&dst).unwrap();
        assert_eq!(
            source.entries[0].content_sha256,
            dest.entries[0].content_sha256
        );
        assert_eq!(
            diff_trees(&source, &dest).classify("f"),
            Some(EntryDiff::Changed)
        );
    }

    /// A LOCAL remote is canonicalized directly — no exec is involved (the
    /// LocalTransport's exec would spawn a real process). An existing EMPTY
    /// directory is a genuinely empty tree; an ABSENT or non-directory root is
    /// an ERROR, never a synthesized empty manifest.
    #[test]
    fn remote_manifest_local_remote_errors_on_absent_or_non_directory_root() {
        let dir = fixture_tmpdir(&SysEnv::from_process()).unwrap();
        let root = dir.path().join("r");
        write(&root.join("f"), b"x");
        let t =
            LocalTransport::new(&SysEnv::from_process(), root.clone(), Layout::empty()).unwrap();
        assert_eq!(
            remote_manifest(&t).unwrap(),
            canonicalize_tree(&root).unwrap()
        );

        // An existing EMPTY directory still yields a genuinely empty manifest.
        let empty = dir.path().join("empty");
        fs::create_dir_all(&empty).unwrap();
        let te =
            LocalTransport::new(&SysEnv::from_process(), empty.clone(), Layout::empty()).unwrap();
        let empty_manifest = remote_manifest(&te).unwrap();
        assert!(empty_manifest.entries.is_empty());
        assert_eq!(empty_manifest, canonicalize_tree(&empty).unwrap());

        // An ABSENT root is an ERROR, never a synthesized empty manifest: an
        // absent far side must not read as "the far side described an empty
        // tree", which is what lets a `delete_extraneous` sync destroy data.
        // It is the TYPED absence condition (`Error::NotFound`), distinct from
        // an unreachable host or a transport failure.
        let absent = dir.path().join("absent");
        let ta =
            LocalTransport::new(&SysEnv::from_process(), absent.clone(), Layout::empty()).unwrap();
        assert!(
            matches!(remote_manifest(&ta), Err(Error::NotFound(_))),
            "an absent local remote root must be the typed absence error"
        );
        // ... and the destination-side form reports it the same way.
        assert!(
            matches!(remote_destination_manifest(&ta), Err(Error::NotFound(_))),
            "an absent local remote root must be NotFound on the destination form too"
        );

        // A non-directory root is refused, but NOT as absence: it exists.
        let file = dir.path().join("not-a-dir");
        write(&file, b"x");
        let tf = LocalTransport::new(&SysEnv::from_process(), file, Layout::empty()).unwrap();
        let err = remote_manifest(&tf).expect_err("a file root must be refused");
        assert!(
            matches!(err, Error::Transport { .. }),
            "a non-directory local remote root must be a transport error"
        );
        // ... and the TYPED reason names the condition, so a caller can tell
        // "the root is a file" from "the host is unreachable" without reading
        // the message.
        assert_eq!(
            err.transport_reason(),
            Some(TransportKind::RootNotADirectory),
            "a non-directory root is its OWN typed condition: {err:?}"
        );
    }

    /// Gap 5: the far side DISTINGUISHES an absent root from a root that is not
    /// a directory, and the classifier turns the absent diagnostic into the
    /// typed [`Error::NotFound`] instead of an undifferentiated transport
    /// error. The REAL script is run on an absent root; before the fix both
    /// cases printed `not a directory:` and a consumer had to string-match (or
    /// probe with `exec`) to tell an absent far side from an unreachable host.
    #[test]
    fn an_absent_remote_root_is_the_typed_not_found_condition() {
        if !perl_on_path() {
            announce_skip("perl is not on PATH, so the remote verification script cannot run");
            return;
        }
        let dir = fixture_tmpdir(&SysEnv::from_process()).unwrap();
        let absent = dir.path().join("absent");
        let out = real_script_outcome(&absent).expect("perl must run");
        assert!(
            out.stderr.starts_with("absent: "),
            "the far side must name ABSENCE distinctly, got: {out:?}"
        );
        assert!(
            !out.stderr.starts_with("not a directory: "),
            "an absent root must not be reported as a non-directory: {out:?}"
        );
        let err = remote_manifest_failure(Path::new("/srv/store"), &out);
        assert!(
            matches!(err, Error::NotFound(_)),
            "an absent far-side root must be NotFound, got: {err:?}"
        );
        // The DIAGNOSTIC is preserved so the caller can see the far side's own
        // words, and the root is named.
        let message = err.to_string();
        assert!(message.contains("/srv/store"), "{message}");
        assert!(
            message.contains("found no root on the far side"),
            "{message}"
        );

        // An UNREACHABLE host (the `unix_listener:` control-socket shape) is a
        // DIFFERENT class: a transport error, never NotFound.
        let unreachable = ExecOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: "unix_listener: cannot bind to path /tmp/dmux/mux-1: No such file or directory"
                .to_string(),
            timeout_cause: None,
        };
        let transport_err = remote_manifest_failure(Path::new("/srv/store"), &unreachable);
        assert!(
            matches!(transport_err, Error::Transport { .. }),
            "an unreachable host must stay a transport error: {transport_err:?}"
        );
    }

    /// F3: an `ssh`-level failure (exit 255, no far-side command) is reported
    /// as a TRANSPORT failure and is NOT blamed on a missing `perl`. Pre-fix
    /// every non-zero exit appended "(is perl installed on the remote host?)".
    #[test]
    fn an_ssh_level_failure_is_not_blamed_on_perl() {
        let out = ExecOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr:
                "unix_listener: cannot bind to path /tmp/dmux/mux-123: No such file or directory"
                    .to_string(),
            timeout_cause: None,
        };
        let msg = remote_manifest_failure(Path::new("/srv/store"), &out).to_string();
        assert!(
            msg.contains("transport-level failure"),
            "an ssh 255 must be reported as a transport failure: {msg}"
        );
        assert!(
            !msg.contains("is perl installed"),
            "an ssh 255 must not suggest perl is missing: {msg}"
        );
        assert!(msg.contains("/srv/store"), "the far side is named: {msg}");
        assert!(
            msg.contains("unix_listener"),
            "the ssh diagnostic is preserved: {msg}"
        );
    }

    /// F3: the perl-missing suggestion is reserved for the shell's "could not
    /// start perl" status (126/127).
    #[test]
    fn a_missing_perl_is_reported_as_the_perl_stage() {
        let out = ExecOutcome {
            exit_code: 127,
            stdout: String::new(),
            stderr: "perl: command not found".to_string(),
            timeout_cause: None,
        };
        let msg = remote_manifest_failure(Path::new("/srv/store"), &out).to_string();
        assert!(
            msg.contains("is perl installed on the remote host?"),
            "a 127 must suggest perl may be absent: {msg}"
        );
    }

    /// F4: `perl`'s `die` exits 255 when `$! == 0` (perl's documented rule),
    /// and the crate's OWN far-side script reaches that arm for a NON-NFC name
    /// and for a root that EXISTS but is not a directory. Exit 255 therefore
    /// establishes no layer: with the script's own stderr the failure must
    /// stay a far-side script failure, naming the exit status and preserved
    /// stderr.
    ///
    /// The three inputs are REAL script output, measured identically on macOS
    /// perl 5.34.1 and Linux perl 5.40.1 (see
    /// `real_script_statuses_classify_as_the_far_side_script`, which produces
    /// them from the script itself):
    /// * the non-NFC and LF/TAB inputs are the script's NFC and
    ///   hex-encoding refusals, both confirmed at 255;
    /// * `not a directory: <root>` at 255 is SYNTHESIZED. The shape is real,
    ///   but the crate's invocation (`perl -e <script> <root>`) exits 2 for
    ///   ANY non-directory root — existing or absent — because `use
    ///   Digest::SHA` / `use Unicode::Normalize` leave `$!` = ENOENT and
    ///   `-d`'s successful `stat` does not clear it. The synthesized 255 keeps
    ///   the branch independent of the exit status (a `die` with `$!` = 0 also
    ///   exits 255, exactly as the non-NFC input does), and the real 2 is
    ///   pinned by `a_script_level_failure_is_reported_as_the_far_side_script`
    ///   and by the real-script test.
    ///
    /// PRE-FIX MISCLASSIFICATION (probe, before the fix): the inputs returned
    /// "the transport failed before the far-side command started (exit 255): …
    /// (this is a transport-level failure — connection, authentication, host
    /// key, or the ssh control socket)".
    #[test]
    fn a_far_side_perl_die_at_255_is_not_a_transport_failure() {
        for stderr in [
            "not a directory: /srv/store",
            "entry name under /srv/store is not NFC-normalized: e\u{301}",
            // The real script's diagnostic for a far-side name `a<TAB>b`:
            // the name is hex-encoded, so it carries no transport marker.
            "entry name under /srv/store contains a tab, newline, carriage return, or NUL \
             (the manifest wire refuses NUL/LF/CR/TAB): 610962",
        ] {
            let out = ExecOutcome {
                exit_code: 255,
                stdout: String::new(),
                stderr: stderr.to_string(),
                timeout_cause: None,
            };
            let msg = remote_manifest_failure(Path::new("/srv/store"), &out).to_string();
            assert!(
                msg.contains("failed inside the far-side manifest script"),
                "a perl `die` at 255 with script stderr must be a far-side script \
                 failure, got: {msg}"
            );
            assert!(
                !msg.contains("transport-level failure"),
                "exit 255 with no transport marker must not name the transport layer: {msg}"
            );
            assert!(
                !msg.contains("is perl installed"),
                "exit 255 is not the `perl` not-started stage: {msg}"
            );
            assert!(
                msg.contains("exit 255") && msg.contains(stderr),
                "the message must report what is known — the exit status and the preserved \
                 stderr: {msg}"
            );
        }
    }

    /// F1: the crate's own script prints `opendir <dir>: $!` and exits 13 for an
    /// unreadable far-side directory, so `Permission denied` in stderr is NOT
    /// transport evidence (it is ambiguous — ssh authentication failures say it
    /// too, but those still exit 255). Exit 13 with this stderr is a far-side
    /// script failure.
    ///
    /// PRE-FIX MISCLASSIFICATION (probe, before the fix): the input returned
    /// "the transport failed before the far-side command started (exit 13):
    /// opendir /srv/store/sub: Permission denied (this is a transport-level
    /// failure — connection, authentication, host key, or the ssh control
    /// socket)".
    #[test]
    fn a_script_eacces_with_permission_denied_is_not_a_transport_failure() {
        let out = ExecOutcome {
            exit_code: 13,
            stdout: String::new(),
            stderr: "opendir /srv/store/sub: Permission denied".to_string(),
            timeout_cause: None,
        };
        let msg = remote_manifest_failure(Path::new("/srv/store"), &out).to_string();
        assert!(
            msg.contains("failed inside the far-side manifest script"),
            "an EACCES script refusal must be a far-side script failure, got: {msg}"
        );
        assert!(
            !msg.contains("transport-level failure"),
            "`Permission denied` must not select the transport branch: {msg}"
        );
        assert!(
            msg.contains("exit 13") && msg.contains("Permission denied"),
            "the exit status and preserved stderr must survive: {msg}"
        );
    }

    /// F1: the transport branch is retained for exit 255 that DOES carry a
    /// strong, unambiguous transport diagnostic. This guards against
    /// overcorrecting the "255 alone is not transport" rule into "255 is never
    /// transport". (This assertion also holds pre-fix, which is the point: the
    /// fix must not lose the genuine case.)
    #[test]
    fn an_exit_255_with_a_strong_transport_marker_is_transport() {
        for stderr in [
            "kex_exchange_identification: read: Connection reset by peer",
            // The reviewer's real-sshd ground truth for a genuinely closed
            // port: exit 255 AND this exact ssh diagnostic, which must still
            // route to transport.
            "ssh: connect to host 127.0.0.1 port 22: Connection refused",
        ] {
            let out = ExecOutcome {
                exit_code: 255,
                stdout: String::new(),
                stderr: stderr.to_string(),
                timeout_cause: None,
            };
            let msg = remote_manifest_failure(Path::new("/srv/store"), &out).to_string();
            assert!(
                msg.contains("transport-level failure"),
                "an exit 255 with a strong ssh marker is transport: {msg}"
            );
            assert!(
                msg.contains(stderr.trim()),
                "the ssh diagnostic is preserved: {msg}"
            );
        }
    }

    /// F1: the only branch that is a statement about `perl` itself is the
    /// remote shell's 126/127 ("found but not executable" / "not found"), with
    /// or without the wrapper's not-found diagnostic.
    ///
    /// PRE-FIX BEHAVIOUR: this already classified correctly (the pre-fix
    /// classifier reached the `perl` stage for 126/127 and for the diagnostic
    /// spellings); the test pins that the fix did not move it.
    #[test]
    fn perl_could_not_start_is_the_perl_stage() {
        for (code, stderr) in [
            (126, ""),
            (127, ""),
            (127, "perl: command not found"),
            (126, "bash: perl: No such file or directory"),
        ] {
            let out = ExecOutcome {
                exit_code: code,
                stdout: String::new(),
                stderr: stderr.to_string(),
                timeout_cause: None,
            };
            let msg = remote_manifest_failure(Path::new("/srv/store"), &out).to_string();
            assert!(
                msg.contains("is perl installed on the remote host?"),
                "exit {code} with {stderr:?} must be the perl stage: {msg}"
            );
            assert!(
                !msg.contains("transport-level failure"),
                "the perl stage is not a transport failure: {msg}"
            );
        }
    }

    /// F3: a script-level failure (perl ran and exited non-zero) is reported as
    /// the far-side script failure — neither a transport fault nor a missing
    /// interpreter.
    #[test]
    fn a_script_level_failure_is_reported_as_the_far_side_script() {
        let out = ExecOutcome {
            exit_code: 2,
            stdout: String::new(),
            stderr: "not a directory: /srv/store".to_string(),
            timeout_cause: None,
        };
        let msg = remote_manifest_failure(Path::new("/srv/store"), &out).to_string();
        assert!(
            msg.contains("failed inside the far-side manifest script"),
            "a script exit must be reported as the script failure: {msg}"
        );
        assert!(!msg.contains("is perl installed"), "{msg}");
        assert!(!msg.contains("transport-level failure"), "{msg}");
    }

    // -----------------------------------------------------------------------
    // F1: real OpenSSH transport evidence, and the undetermined fallback.
    // -----------------------------------------------------------------------

    /// F1: the REAL OpenSSH authentication/transport shapes observed on this
    /// fleet, each at the START of a stderr line, must be attributed to the
    /// TRANSPORT — not to the far-side script (the regression this change
    /// fixes) and not to `perl`.
    ///
    /// EVIDENCE: OpenSSH 10.2p1 on macOS and Linux (`ssh -o BatchMode=yes …
    /// nonexistentuser@localhost true`) prints the first shape; the others are
    /// OpenSSH's spellings for a disconnect, an unresponsive server, and too
    /// many authentication attempts. The leading `Warning:` line in the second
    /// case proves the auth match is LINE-ANCHORED rather than a substring of
    /// the first line.
    ///
    /// PRE-FIX MISCLASSIFICATION (probe, before the fix): the first shape
    /// returned "remote tree verification at /srv/store failed inside the
    /// far-side manifest script (exit 255): nonexistentuser@localhost:
    /// Permission denied (publickey)." — a transport failure blamed on the
    /// script.
    #[test]
    fn real_ssh_auth_failure_shapes_are_transport() {
        for stderr in [
            "nonexistentuser@localhost: Permission denied (publickey).",
            "Warning: Permanently added 'localhost' (ED25519) to the list of known hosts.\n\
             nonexistentuser@localhost: Permission denied (publickey).",
            "Received disconnect from 127.0.0.1 port 22:2: disconnected by user",
            "Timeout, server 127.0.0.1 not responding.",
            "Too many authentication failures",
        ] {
            let out = ExecOutcome {
                exit_code: 255,
                stdout: String::new(),
                stderr: stderr.to_string(),
                timeout_cause: None,
            };
            let msg = remote_manifest_failure(Path::new("/srv/store"), &out).to_string();
            assert!(
                msg.contains("transport-level failure"),
                "a real ssh 255 ({stderr:?}) is transport, got: {msg}"
            );
            assert!(
                !msg.contains("failed inside the far-side manifest script"),
                "a transport failure must not be blamed on the script: {msg}"
            );
            assert!(
                !msg.contains("is perl installed") && msg.contains("exit 255"),
                "the transport branch names neither perl nor a lost status: {msg}"
            );
        }
    }

    /// F1: a genuine ssh failure produced by the REAL `ssh` binary on this
    /// host is classified as TRANSPORT. This is the end-to-end ground-truth
    /// probe: macOS (no local sshd) prints `ssh: connect to host localhost
    /// port 22: Connection refused`; Linux (sshd running) prints
    /// `nonexistentuser@localhost: Permission denied (publickey).` — both at
    /// 255, so both must be transport.
    #[cfg(unix)]
    #[test]
    fn a_real_ssh_failure_is_transport() {
        if !ssh_on_path() {
            announce_skip("ssh is not on PATH, so the real-ssh transport probe cannot run");
            return;
        }
        let Some(out) = bounded_ssh_failure(std::time::Duration::from_secs(30)) else {
            announce_skip("the real ssh probe could not be spawned or produced no status");
            return;
        };
        if out.exit_code == 0 {
            announce_skip(
                "the probe target unexpectedly authenticated, so no real ssh failure was produced",
            );
            return;
        }
        let msg = remote_manifest_failure(Path::new("/srv/store"), &out).to_string();
        assert!(
            msg.contains("transport-level failure"),
            "a REAL ssh failure (exit {}, stderr {:?}) must be transport, got: {msg}",
            out.exit_code,
            out.stderr
        );
        assert!(
            !msg.contains("failed inside the far-side manifest script")
                && !msg.contains("is perl installed"),
            "a real ssh failure must not be blamed on the script or perl: {msg}"
        );
    }

    /// F1: a status no rule classifies must NOT be blamed on any layer — the
    /// message reports the KNOWN exit status and stderr and says the layer is
    /// undetermined. The previous fallback asserted "failed inside the
    /// far-side manifest script" for exactly these inputs, which is a layer it
    /// cannot establish.
    ///
    /// PRE-FIX MISCLASSIFICATION (probe, before the fix): every input returned
    /// "… failed inside the far-side manifest script (exit N): …" — a
    /// confident wrong layer.
    #[test]
    fn an_unclassified_exit_names_no_layer() {
        for (code, stderr) in [
            (200, ""),
            (137, ""),
            (1, "some unrelated wrapper diagnostic"),
            (137, "Killed"),
            // 255 alone establishes no layer: without a transport marker it is
            // not transport, and without the script's `die` vocabulary it is
            // not the script either.
            (255, ""),
        ] {
            let out = ExecOutcome {
                exit_code: code,
                stdout: String::new(),
                stderr: stderr.to_string(),
                timeout_cause: None,
            };
            let msg = remote_manifest_failure(Path::new("/srv/store"), &out).to_string();
            assert!(
                msg.contains("undetermined") && msg.contains(&format!("exited {code}")),
                "an unclassified exit {code} must report the known status and say the layer \
                 is undetermined: {msg}"
            );
            for forbidden in [
                "transport-level failure",
                "failed inside the far-side manifest script",
                "is perl installed",
                "ssh",
                "connection",
                "authentication",
            ] {
                assert!(
                    !msg.contains(forbidden),
                    "an unclassified exit must not name {forbidden:?}: {msg}"
                );
            }
            let expected = if stderr.is_empty() {
                "(no stderr)"
            } else {
                stderr
            };
            assert!(
                msg.contains(expected),
                "the stderr (or its absence) survives: {msg}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // F2: line anchoring closes the far-side-text spoof.
    // -----------------------------------------------------------------------

    /// F2: marker and `perl`-not-found matches are LINE-ANCHORED, so a raw
    /// non-NFC entry name cannot spoof a layer. Each name below is exactly the
    /// text the script would echo raw after its own `die` prefix; before
    /// anchoring, every one of them routed the failure to the transport (or
    /// the perl) branch.
    ///
    /// EVIDENCE: the script's `entry name under $dir is not NFC-normalized:
    /// $n` line, with `$n` measured echoed raw on both platforms (see
    /// `real_script_raw_non_nfc_name_does_not_spoof_transport`, which feeds
    /// the script's OWN output).
    #[test]
    fn a_raw_non_nfc_name_cannot_spoof_a_marker() {
        for name in [
            "e\u{301} ssh: connect to host 127.0.0.1 port 22: Connection refused",
            "e\u{301} Host key verification failed.",
            "e\u{301} kex_exchange_identification: boom",
            "e\u{301} unix_listener: cannot bind to path /tmp/dmux/mux-123",
            "e\u{301} Received disconnect from 127.0.0.1 port 22:2: bye",
            "e\u{301} Timeout, server 127.0.0.1 not responding.",
            "e\u{301} Too many authentication failures",
            "e\u{301} Connection closed by 127.0.0.1 port 22",
            "e\u{301} Permission denied (publickey).",
            "e\u{301} x@y: Permission denied (publickey).",
            "e\u{301} perl: command not found",
        ] {
            let stderr = format!("entry name under /srv/store is not NFC-normalized: {name}");
            let out = ExecOutcome {
                exit_code: 255,
                stdout: String::new(),
                stderr,
                timeout_cause: None,
            };
            let msg = remote_manifest_failure(Path::new("/srv/store"), &out).to_string();
            assert!(
                msg.contains("failed inside the far-side manifest script"),
                "a raw non-NFC name ({name:?}) must stay a script failure: {msg}"
            );
            assert!(
                !msg.contains("transport-level failure") && !msg.contains("is perl installed"),
                "a raw non-NFC name must not spoof transport or perl: {msg}"
            );
        }
    }

    /// F2: a marker-shaped string appearing in a path the script PRINTS (here
    /// the root directory's own name) is not at a line start, so it cannot
    /// spoof the transport branch even with no crafted entry name at all.
    #[test]
    fn a_marker_named_root_directory_cannot_spoof_transport() {
        let stderr = "entry name under /tmp/Host key verification failed store is not \
                      NFC-normalized: e\u{301}";
        let out = ExecOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: stderr.to_string(),
            timeout_cause: None,
        };
        let msg =
            remote_manifest_failure(Path::new("/tmp/Host key verification failed store"), &out)
                .to_string();
        assert!(
            msg.contains("failed inside the far-side manifest script"),
            "a marker inside the printed root must not select transport: {msg}"
        );
        assert!(!msg.contains("transport-level failure"), "{msg}");
    }

    // -----------------------------------------------------------------------
    // F4: the classifier pinned to the REAL script's own emissions.
    // -----------------------------------------------------------------------

    /// Whether `perl` can run at all (the real-script probes need it).
    fn perl_on_path() -> bool {
        std::process::Command::new("perl")
            .args(["-e", "exit 0"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    /// Whether `ssh` can be spawned (the real-ssh probe needs it).
    fn ssh_on_path() -> bool {
        std::process::Command::new("ssh")
            .arg("-V")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok()
    }

    /// Run a real `ssh` against a target that cannot authenticate and return
    /// its bounded outcome, or `None` when it could not be spawned / did not
    /// finish before `deadline`.
    ///
    /// The child's stdout/stderr are redirected to FILES rather than pipes so
    /// the wait loop can poll `try_wait` and kill at the deadline without any
    /// pipe-buffer deadlock. The target is `nonexistentuser@localhost`: macOS
    /// (no sshd) fails at connect, Linux (sshd) fails at authentication — both
    /// transport-layer outcomes at exit 255.
    #[cfg(unix)]
    fn bounded_ssh_failure(deadline: std::time::Duration) -> Option<ExecOutcome> {
        use std::process::{Command, Stdio};
        let dir = fixture_tmpdir(&SysEnv::from_process()).ok()?;
        let out_path = dir.path().join("stdout");
        let err_path = dir.path().join("stderr");
        let out_file = std::fs::File::create(&out_path).ok()?;
        let err_file = std::fs::File::create(&err_path).ok()?;
        let mut child = Command::new("ssh")
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=5",
                "nonexistentuser@localhost",
                "true",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::from(out_file))
            .stderr(Stdio::from(err_file))
            .spawn()
            .ok()?;
        let start = std::time::Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if start.elapsed() > deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(_) => break None,
            }
        }?;
        Some(ExecOutcome {
            exit_code: status.code().unwrap_or(-1),
            stdout: std::fs::read_to_string(&out_path).unwrap_or_default(),
            stderr: std::fs::read_to_string(&err_path).unwrap_or_default(),
            timeout_cause: None,
        })
    }

    /// Run the REAL far-side script on `root` and return its raw outcome.
    fn real_script_outcome(root: &Path) -> Option<ExecOutcome> {
        let out = std::process::Command::new("perl")
            .args(["-e", remote_tree_verify_script()])
            .arg(root)
            .output()
            .ok()?;
        Some(ExecOutcome {
            exit_code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            timeout_cause: None,
        })
    }

    /// Assert that `out` — the REAL script's own output — classifies as the
    /// far-side script layer and neither transport nor perl.
    fn assert_script_layer(out: &ExecOutcome) {
        let msg = remote_manifest_failure(Path::new("/srv/store"), out).to_string();
        assert!(
            msg.contains("failed inside the far-side manifest script"),
            "real script output {out:?} must be the script layer, got: {msg}"
        );
        assert!(
            !msg.contains("transport-level failure") && !msg.contains("is perl installed"),
            "real script output must not be transport or perl: {msg}"
        );
    }

    /// F4: the classifier is pinned to the [status, stderr] the REAL far-side
    /// script emits, measured identically on macOS perl 5.34.1 and Linux perl
    /// 5.40.1 under the crate's own `perl -e <script> <root>` invocation:
    ///
    /// * root EXISTS but is not a directory -> 2 (`not a directory: …`);
    /// * root is ABSENT                    -> 2 (`absent: …`, a DISTINCT
    ///   diagnostic the classifier maps to `Error::NotFound`);
    /// * a directory the walk cannot open  -> 13  (`opendir …: Permission
    ///   denied`), when this filesystem actually refuses the read;
    /// * a non-NFC entry name              -> 255 (name echoed RAW);
    /// * an entry name with LF             -> 255 (name HEX-encoded);
    /// * an empty directory                -> 0   (the empty manifest).
    ///
    /// This corrects the module's earlier claim that the script's
    /// non-directory-root refusal "exits 255": under the invocation the crate
    /// actually uses it exits 2 (`perl -e`'s module loading leaves `$!` =
    /// ENOENT). Only a `perl <file>` invocation (never used here) exits 255 for
    /// that refusal — the source of the original mistake.
    #[test]
    fn real_script_statuses_classify_as_the_far_side_script() {
        if !perl_on_path() {
            announce_skip("perl is not on PATH, so the remote verification script cannot run");
            return;
        }
        let dir = fixture_tmpdir(&SysEnv::from_process()).unwrap();

        // An EXISTING regular file as the root: measured 2, NOT 255. `perl -e`
        // loads Digest::SHA/Unicode::Normalize first, leaving `$!` = ENOENT;
        // `-d`'s successful `stat` does not clear it, so `die` propagates 2.
        let file = dir.path().join("plain.txt");
        write(&file, b"content");
        let out = real_script_outcome(&file).unwrap();
        assert_eq!(
            out.exit_code, 2,
            "an existing non-directory root exits 2 under `perl -e`: {out:?}"
        );
        assert!(
            out.stderr.starts_with("not a directory: "),
            "the script names the rule: {out:?}"
        );
        assert_script_layer(&out);

        // An ABSENT root: measured 2 (`-e`/`-d` set ENOENT), but with a
        // DISTINCT `absent:` diagnostic so the caller can report
        // `Error::NotFound` instead of string-matching it apart from a
        // non-directory root or an unreachable host.
        let absent = dir.path().join("absent");
        let out = real_script_outcome(&absent).unwrap();
        assert_eq!(out.exit_code, 2, "an absent root exits 2: {out:?}");
        assert!(out.stderr.starts_with("absent: "), "{out:?}");
        assert!(
            matches!(
                remote_manifest_failure(Path::new("/srv/store"), &out),
                Error::NotFound(_)
            ),
            "an absent root is the typed NotFound condition: {out:?}"
        );

        // An existing EMPTY directory: measured 0 with empty stdout — the empty
        // manifest, not a refusal.
        let empty = dir.path().join("empty");
        fs::create_dir_all(&empty).unwrap();
        let out = real_script_outcome(&empty).unwrap();
        assert_eq!(out.exit_code, 0, "an empty directory exits 0: {out:?}");
        assert!(
            out.stdout.is_empty(),
            "an empty directory prints an empty listing: {out:?}"
        );

        // A non-NFC entry name: measured 255 with the name echoed RAW.
        let nfc = dir.path().join("nfc");
        fs::create_dir_all(&nfc).unwrap();
        fs::create_dir(nfc.join("e\u{301}")).unwrap();
        let out = real_script_outcome(&nfc).unwrap();
        assert_eq!(out.exit_code, 255, "a non-NFC name exits 255: {out:?}");
        assert!(
            out.stderr.contains("is not NFC-normalized: e\u{301}"),
            "the non-NFC name is echoed RAW: {out:?}"
        );
        assert_script_layer(&out);

        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::fs::PermissionsExt;

            // An LF entry name: measured 255 with the name HEX-encoded.
            let lf = dir.path().join("lf");
            fs::create_dir_all(&lf).unwrap();
            fs::create_dir(lf.join(OsStr::from_bytes(b"a\nb"))).unwrap();
            let out = real_script_outcome(&lf).unwrap();
            assert_eq!(out.exit_code, 255, "an LF name exits 255: {out:?}");
            assert!(
                out.stderr.contains("610a62"),
                "the LF name is hex-encoded (`a\\nb` = 61 0a 62): {out:?}"
            );
            assert_script_layer(&out);

            // A directory the walk cannot open: measured 13 (`opendir`
            // EACCES), when this process/filesystem really refuses the read.
            let unread = dir.path().join("unread");
            fs::create_dir_all(unread.join("sub")).unwrap();
            write(&unread.join("sub/inside"), b"x");
            fs::set_permissions(unread.join("sub"), fs::Permissions::from_mode(0o000)).unwrap();
            let refused = fs::read_dir(unread.join("sub")).is_err();
            if refused {
                let out = real_script_outcome(&unread).unwrap();
                fs::set_permissions(unread.join("sub"), fs::Permissions::from_mode(0o755)).unwrap();
                assert_eq!(out.exit_code, 13, "an unreadable dir exits 13: {out:?}");
                assert!(out.stderr.starts_with("opendir "), "{out:?}");
                assert_script_layer(&out);
            } else {
                fs::set_permissions(unread.join("sub"), fs::Permissions::from_mode(0o755)).unwrap();
                announce_skip(
                    "this process can still enumerate a mode-0o000 directory, so the EACCES \
                     premise is untestable here",
                );
            }
        }
    }

    /// F2 end-to-end: the REAL script's output for a non-NFC entry whose name
    /// is a transport marker must still classify as the far-side script. This
    /// feeds the script's OWN bytes, not a reconstructed string, so it is the
    /// strongest available measurement that anchoring closes the spoof.
    #[test]
    fn real_script_raw_non_nfc_name_does_not_spoof_transport() {
        if !perl_on_path() {
            announce_skip("perl is not on PATH, so the remote verification script cannot run");
            return;
        }
        let dir = fixture_tmpdir(&SysEnv::from_process()).unwrap();
        let root = dir.path().join("spoof");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir(
            root.join("e\u{301} ssh: connect to host 127.0.0.1 port 22: Connection refused"),
        )
        .unwrap();
        let out = real_script_outcome(&root).unwrap();
        assert_eq!(out.exit_code, 255, "{out:?}");
        assert!(
            out.stderr.contains("Connection refused"),
            "the raw name is echoed verbatim: {out:?}"
        );
        assert_script_layer(&out);
    }

    // -----------------------------------------------------------------------
    // F1: the 126/127 status is ambiguous and must not outrank the script's
    // own anchored `die` vocabulary.
    // -----------------------------------------------------------------------

    /// F1: a genuine far-side SCRIPT failure whose `$!` is 126/127 is reported
    /// as the far-side script, not as a missing interpreter. On Linux 127 =
    /// EKEYEXPIRED and 126 = ENOKEY are REAL errno values that keyring-backed
    /// trees (fscrypt, AFS) return, and the script's `die` propagates `$!`, so
    /// the bare status proves nothing about starting `perl`. The decisive
    /// cross-check is that the SAME stderr at exit 5 already classified as the
    /// script — the STATUS ALONE was the misrouting signal.
    ///
    /// PRE-FIX MISCLASSIFICATION (probe, before the fix): the 127/126 inputs
    /// returned "remote tree verification at /srv/store could not start the
    /// far-side `perl` (exit 127): open /srv/store/x: Key has expired (is perl
    /// installed on the remote host?)".
    #[test]
    fn f1_a_script_die_that_propagates_126_or_127_is_the_far_side_script() {
        for (code, stderr) in [
            (127, "open /srv/store/x: Key has expired"),
            (126, "open /srv/store/x: Required key not available"),
        ] {
            let out = ExecOutcome {
                exit_code: code,
                stdout: String::new(),
                stderr: stderr.to_string(),
                timeout_cause: None,
            };
            let msg = remote_manifest_failure(Path::new("/srv/store"), &out).to_string();
            assert!(
                msg.contains("failed inside the far-side manifest script"),
                "a script `die` at {code} must be the script layer, got: {msg}"
            );
            assert!(
                !msg.contains("is perl installed"),
                "exit {code} must not suggest perl is missing when the script ran: {msg}"
            );
            assert!(
                !msg.contains("transport-level failure"),
                "a script `die` is not transport: {msg}"
            );
            assert!(
                msg.contains(&format!("exit {code}")) && msg.contains(stderr),
                "the status and stderr survive: {msg}"
            );
        }
        // The decisive cross-check: the SAME stderr at exit 5 is the script, so
        // only the status could have misrouted the 126/127 cases above.
        let out = ExecOutcome {
            exit_code: 5,
            stdout: String::new(),
            stderr: "open /srv/store/x: Key has expired".to_string(),
            timeout_cause: None,
        };
        let msg = remote_manifest_failure(Path::new("/srv/store"), &out).to_string();
        assert!(
            msg.contains("failed inside the far-side manifest script"),
            "the same stderr at exit 5 is the script: {msg}"
        );
    }

    /// F1 ground truth from the REAL interpreter, not from reasoning: perl's
    /// `die` propagates `$!` as the exit status, so `$! = 127` exits 127 with
    /// the script's own `open …` diagnostic on stderr. Measured on macOS perl
    /// 5.34.1 (`open /srv/store/x: 127`, no errno string) and Linux perl
    /// 5.40.1 (`open /srv/store/x: Key has expired`); BOTH start with the
    /// script's `open ` die prefix, so both must classify as the script.
    #[test]
    fn f1_a_real_interpreter_die_at_127_is_the_far_side_script() {
        if !perl_on_path() {
            announce_skip("perl is not on PATH, so the real `$!`-propagation probe cannot run");
            return;
        }
        let out = std::process::Command::new("perl")
            .args(["-e", "$!=shift; die qq{open /srv/store/x: $!\\n}", "127"])
            .output()
            .expect("perl must run");
        let outcome = ExecOutcome {
            exit_code: out.status.code().unwrap_or(-1),
            stdout: String::new(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            timeout_cause: None,
        };
        assert_eq!(
            outcome.exit_code, 127,
            "the interpreter must propagate `$!` as the exit status: {outcome:?}"
        );
        assert!(
            outcome.stderr.starts_with("open "),
            "the script's own `open ` die prefix must be preserved: {outcome:?}"
        );
        let msg = remote_manifest_failure(Path::new("/srv/store"), &outcome).to_string();
        assert!(
            msg.contains("failed inside the far-side manifest script"),
            "real interpreter output at 127 must be the script, got: {msg}"
        );
        assert!(!msg.contains("is perl installed"), "{msg}");
    }

    /// F1: the veto is safe only because the script's closed `die` vocabulary
    /// and the perl-not-found markers are DISJOINT. Every die prefix is a bare
    /// word (`open `, `lstat `, …); every not-found marker begins `perl:`, so
    /// neither appears at the start of the other's line. The enumeration is
    /// the verification of the reordering claim, not a hand-wave.
    #[test]
    fn the_script_die_vocabulary_and_the_perl_not_found_markers_do_not_collide() {
        const PERL_NOT_FOUND: &[&str] = &[
            "perl: command not found",
            "perl: not found",
            "perl: No such file",
        ];
        for prefix in SCRIPT_DIE_PREFIXES {
            assert!(
                !prefix.starts_with("perl:"),
                "a die prefix must not begin `perl:` (it would collide with the not-found markers): {prefix:?}"
            );
            for marker in PERL_NOT_FOUND {
                assert!(
                    !marker.starts_with(prefix),
                    "the not-found marker {marker:?} must not start with the die prefix {prefix:?}"
                );
                assert!(
                    !prefix.starts_with(marker),
                    "the die prefix {prefix:?} must not start with the not-found marker {marker:?}"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // F2: the runner's `-1` is ambiguous, so the TYPED cause is the authority.
    // -----------------------------------------------------------------------

    /// F2: the classifier must read the typed [`TimeoutCause`], never the bare
    /// `exit_code == -1` (which a signal-killed child also produces). The drain
    /// case must NOT be blamed on the transport-before-command layer.
    ///
    /// PRE-FIX MISCLASSIFICATION (probe, before the fix): the drain input
    /// returned "remote tree verification at /srv/store could not run: the
    /// transport failed before the far-side command started (exit -1): … left
    /// processes holding its output pipes open (this is a transport-level
    /// failure — connection, …)"; the bare `-1` input returned the same
    /// transport-before-command message.
    #[test]
    fn f2_the_typed_cause_not_the_status_alone_classifies_the_deadline() {
        // (a) The deadline killed a RUNNING command: transport-before-command.
        let killed = ExecOutcome {
            exit_code: -1,
            stdout: String::new(),
            stderr: "timed out after 200ms".to_string(),
            timeout_cause: Some(TimeoutCause::CommandStillRunning),
        };
        let msg = remote_manifest_failure(Path::new("/srv/store"), &killed).to_string();
        assert!(
            msg.contains("transport failed before the far-side command started"),
            "a deadline kill while running is the transport-before-command layer: {msg}"
        );

        // (b) The command RAN and EXITED; only its drain outlasted: NOT that
        // layer, and it must name what actually happened.
        let drained = ExecOutcome {
            exit_code: -1,
            stdout: String::new(),
            stderr: "command [\"perl\", …] left processes holding its output pipes open"
                .to_string(),
            timeout_cause: Some(TimeoutCause::OutputDrainGaveUp),
        };
        let msg = remote_manifest_failure(Path::new("/srv/store"), &drained).to_string();
        assert!(
            msg.contains("the command ran and exited"),
            "the drain case must say the command ran and exited: {msg}"
        );
        assert!(
            !msg.contains("failed before the far-side command started")
                && !msg.contains("transport-level failure"),
            "the drain case must not assert the transport-before-command layer: {msg}"
        );
        assert!(!msg.contains("is perl installed"), "{msg}");
        // W3: the drain bound is NOT the caller's deadline, and the exit status
        // WAS collected by the reap (then discarded by the `Background` error),
        // so the message must not claim either the opposite.
        assert!(
            !msg.contains("outlasted the deadline")
                && !msg.contains("outlasted the runner's deadline"),
            "the drain message must not claim a deadline was outlasted: {msg}"
        );
        assert!(
            !msg.contains("no exit status was collected"),
            "the drain message must not claim the status was never collected (it was, then \
             discarded): {msg}"
        );
        assert!(
            msg.contains("sentinel"),
            "the drain message must identify the reported exit -1 as a sentinel: {msg}"
        );

        // (c) `-1` with NO typed cause is a signal-killed local child, not a
        // deadline: the layer is undetermined, never transport.
        let signalled = ExecOutcome {
            exit_code: -1,
            stdout: String::new(),
            stderr: String::new(),
            timeout_cause: None,
        };
        let msg = remote_manifest_failure(Path::new("/srv/store"), &signalled).to_string();
        assert!(
            msg.contains("undetermined"),
            "a bare -1 is undetermined, not the transport layer: {msg}"
        );
        assert!(
            !msg.contains("transport failed before the far-side command started"),
            "a bare -1 must not name the transport layer: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // F3: the reachable at-255 spoof vector is a ROOT name carrying a raw LF.
    // -----------------------------------------------------------------------

    /// F3: the documented residual is NOT `not a directory: $root` (measured:
    /// that spelling exits 2 and lands in the script branch). The reachable
    /// at-255 vector is the script interpolating `$dir` into its own `die`
    /// line: a ROOT DIRECTORY whose name embeds an LF and an ssh marker starts
    /// a marker line once `$dir` is interpolated, and any non-NFC entry makes
    /// the run exit 255. This test drives the REAL script on exactly that root
    /// and pins both the status and the classification.
    #[cfg(unix)]
    #[test]
    fn f3_the_real_at_255_spoof_vector_is_a_root_name_containing_a_raw_lf() {
        if !perl_on_path() {
            announce_skip("perl is not on PATH, so the real at-255 vector cannot be measured");
            return;
        }
        let dir = fixture_tmpdir(&SysEnv::from_process()).unwrap();
        let root = dir
            .path()
            .join("x\nssh: connect to host evil port 1: Connection refused\ny");
        fs::create_dir_all(&root).unwrap();
        // Any non-NFC entry triggers the `entry name under $dir …` die, whose
        // `$dir` carries the root's LF.
        fs::create_dir(root.join("e\u{301}")).unwrap();
        let out = real_script_outcome(&root).unwrap();
        assert_eq!(out.exit_code, 255, "the vector must reach 255: {out:?}");
        assert!(
            out.stderr
                .lines()
                .any(|line| line == "ssh: connect to host evil port 1: Connection refused"),
            "the root's raw LF must put the ssh marker at a LINE START: {out:?}"
        );
        let msg = remote_manifest_failure(Path::new("/srv/store"), &out).to_string();
        assert!(
            msg.contains("transport-level failure"),
            "the documented residual: a CALLER-chosen root can start a marker line and \
             classify as transport: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Constraint #4: every condition a caller must branch on is a TYPED value.
    // The manifest-failure classifier has several layers, and the tests above
    // tell them apart by MESSAGE SUBSTRING. These tests branch on the typed
    // `Error::transport_reason()` instead, which is what a consumer can do
    // without depending on message shape, and they prove the kinds are
    // PAIRWISE DISTINCT.
    // -----------------------------------------------------------------------

    /// Each manifest-failure layer is its own `TransportKind`, asserted by
    /// branching on the typed reason. No message text is consulted.
    #[test]
    fn manifest_failure_layers_are_typed_kinds() {
        let cases: Vec<(TransportKind, ExecOutcome)> = vec![
            (
                TransportKind::InterpreterMissing,
                ExecOutcome {
                    exit_code: 127,
                    stdout: String::new(),
                    stderr: "perl: command not found".to_string(),
                    timeout_cause: None,
                },
            ),
            (
                TransportKind::FarSideScript,
                ExecOutcome {
                    exit_code: 2,
                    stdout: String::new(),
                    stderr: "not a directory: /srv/store".to_string(),
                    timeout_cause: None,
                },
            ),
            (
                TransportKind::BeforeCommand,
                ExecOutcome {
                    exit_code: 255,
                    stdout: String::new(),
                    stderr: "unix_listener: cannot bind to path /tmp/dmux/mux-1: No such file or \
                         directory"
                        .to_string(),
                    timeout_cause: None,
                },
            ),
            (
                TransportKind::OutputDrainGaveUp,
                ExecOutcome {
                    exit_code: -1,
                    stdout: String::new(),
                    stderr: "command [\"perl\"] left processes holding its output pipes open"
                        .to_string(),
                    timeout_cause: Some(TimeoutCause::OutputDrainGaveUp),
                },
            ),
            (
                TransportKind::Undetermined,
                ExecOutcome {
                    exit_code: -1,
                    stdout: String::new(),
                    stderr: String::new(),
                    timeout_cause: None,
                },
            ),
        ];
        for (expected, out) in cases {
            let err = remote_manifest_failure(Path::new("/srv/store"), &out);
            assert_eq!(
                err.transport_reason(),
                Some(expected),
                "the layer must be the typed {expected:?}, got: {err:?}"
            );
        }
        // An ABSENT root is not a transport failure at all, so it carries no
        // transport kind — the distinction the consumer audit needed.
        let absent = ExecOutcome {
            exit_code: 2,
            stdout: String::new(),
            stderr: "absent: /srv/store".to_string(),
            timeout_cause: None,
        };
        let err = remote_manifest_failure(Path::new("/srv/store"), &absent);
        assert!(matches!(err, Error::NotFound(_)), "{err:?}");
        assert_eq!(err.transport_reason(), None, "absent root is not transport");
    }

    /// THE MUTATION CONTROL. The layer kinds must be PAIRWISE DISTINCT and none
    /// may be `Unclassified`: collapsing two layers onto one kind (the
    /// mutation this control detects) fails here while every message-substring
    /// test above would still pass. The first case is the exact doctrine
    /// defect — an unreachable host reported as a far-side script failure.
    #[test]
    fn manifest_failure_layer_kinds_are_pairwise_distinct() {
        let outcomes = [
            ExecOutcome {
                exit_code: 127,
                stdout: String::new(),
                stderr: "perl: command not found".to_string(),
                timeout_cause: None,
            },
            ExecOutcome {
                exit_code: 2,
                stdout: String::new(),
                stderr: "not a directory: /srv/store".to_string(),
                timeout_cause: None,
            },
            ExecOutcome {
                exit_code: 255,
                stdout: String::new(),
                stderr: "kex_exchange_identification: read: Connection reset by peer".to_string(),
                timeout_cause: None,
            },
            ExecOutcome {
                exit_code: -1,
                stdout: String::new(),
                stderr: "command [\"perl\"] left processes holding its output pipes open"
                    .to_string(),
                timeout_cause: Some(TimeoutCause::OutputDrainGaveUp),
            },
            ExecOutcome {
                exit_code: -1,
                stdout: String::new(),
                stderr: String::new(),
                timeout_cause: None,
            },
        ];
        let kinds: Vec<TransportKind> = outcomes
            .iter()
            .map(|out| {
                remote_manifest_failure(Path::new("/srv/store"), out)
                    .transport_reason()
                    .expect("every layer above carries a typed kind")
            })
            .collect();
        let mut deduped = kinds.clone();
        deduped.sort_by_key(|k| format!("{k:?}"));
        deduped.dedup();
        assert_eq!(
            deduped.len(),
            kinds.len(),
            "each manifest-failure layer must have its OWN kind; a collapse is the mutation this \
             control detects: {kinds:?}"
        );
        assert!(
            !kinds.contains(&TransportKind::Unclassified),
            "no classified layer may be Unclassified: {kinds:?}"
        );
        assert!(
            kinds.contains(&TransportKind::BeforeCommand)
                && kinds.contains(&TransportKind::FarSideScript),
            "the unreachable host and the far-side script must be separate kinds: {kinds:?}"
        );
    }
}
