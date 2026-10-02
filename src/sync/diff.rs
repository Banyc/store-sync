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
//! or [`EntryDiff::Same`], sorted by path. The diff is the WHOLE decision
//! surface for [`crate::sync::apply`]; producing it reads no content beyond
//! what a manifest already holds.

use crate::error::{Error, Result};
use crate::manifest::{
    TreeEntry, TreeMetadata, canonicalize_remote_entries, canonicalize_tree,
    remote_tree_verify_script,
};
use crate::transport::{ExecOutcome, Remote};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

/// The exec deadline for the far-side tree hashing script. It bounds one perl
/// process walking the whole tree; 120 s mirrors the source crate's
/// verification timeout and is long enough for a large tree on a slow host
/// while still bounding a hung remote.
pub const REMOTE_MANIFEST_TIMEOUT: Duration = Duration::from_secs(120);

/// The entry kind, projected from the canonical manifest's `type` string.
///
/// The three strings are the ones [`crate::manifest::canonicalize_tree`] and
/// [`crate::manifest::canonicalize_remote_entries`] write for the local walk
/// and the remote assembler respectively; the two producers agree by
/// construction (there is a `manifest` test asserting it), so a policy keyed
/// on this kind sees the same value no matter which side produced the
/// manifest. The mapping is not guessed: the `sync` suite canonicalizes a
/// fixture containing each kind and asserts the strings match
/// [`EntryKind::as_str`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
}

impl EntryKind {
    /// The canonical manifest `type` string for this kind.
    pub fn as_str(self) -> &'static str {
        match self {
            EntryKind::File => "file",
            EntryKind::Dir => "dir",
            EntryKind::Symlink => "symlink",
        }
    }

    /// Project a manifest entry-kind string. A value outside the canonical set
    /// is an integrity failure — the canonicalizers never emit one, so seeing
    /// one means the manifest was tampered with or produced by a divergent
    /// producer.
    pub fn from_manifest(entry_type: &str) -> Result<EntryKind> {
        match entry_type {
            "file" => Ok(EntryKind::File),
            "dir" => Ok(EntryKind::Dir),
            "symlink" => Ok(EntryKind::Symlink),
            other => Err(Error::integrity(format!(
                "unknown manifest entry type {other:?}: expected one of \"file\", \"dir\", \"symlink\""
            ))),
        }
    }

    /// The kind of a manifest entry.
    pub fn of(entry: &TreeEntry) -> Result<EntryKind> {
        EntryKind::from_manifest(&entry.entry_type)
    }
}

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
/// reason an ABSENT or non-directory root is an error on BOTH branches: a
/// caller pushing to a fresh destination creates the destination root (or
/// provisions the layout) first; it is never silently described as empty.
///
/// A non-zero exit is classified by LAYER ([`remote_manifest_failure`]): the
/// remote command is `ssh … exec -- perl -e <script> <root>`. `ssh` reserves
/// exit status 255 for its OWN failures, but a far-side `perl` `die` ALSO
/// exits 255 (perl exits 255 when `$!` is 0, which is exactly what the
/// crate's own script does for a non-directory root or a non-NFC name), so
/// exit 255 ALONE establishes nothing: a positive transport diagnostic in
/// stderr is required before the failure is named as transport, and otherwise
/// the command is reported as a far-side script failure. Only the shell's
/// "could not start perl" statuses (126/127) suggest that `perl` may be
/// absent.
pub fn remote_manifest(remote: &dyn Remote) -> Result<TreeMetadata> {
    let root = remote.root();
    if remote.is_local() {
        // The transport declares the root LOCAL: canonicalize it in process,
        // but refuse an absent or non-directory root rather than synthesizing
        // an empty manifest from it. The synthesised-empty shortcut is what
        // would let a `delete_extraneous` sync read unreadable far-side state
        // as "nothing is there" and destroy it.
        return match std::fs::symlink_metadata(root) {
            Ok(meta) if meta.is_dir() => canonicalize_tree(root),
            Ok(_) => Err(Error::transport(format!(
                "local remote root {} is not a directory; refusing to describe it as a tree",
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
    canonicalize_remote_entries(&out.stdout, root)
}

/// The error for a NON-ZERO exit of the far-side manifest command, classified
/// by the LAYER that failed.
///
/// The command is `ssh … exec -- perl -e <script> <root>`, so a non-zero exit
/// can come from any of three layers, and they are not interchangeable:
///
/// * the TRANSPORT failed before the command ran — the runner reports `-1`
///   when it killed the child at the deadline (no far-side exit status can be
///   negative, so `-1` is conclusive on its own); `ssh` also reserves exit
///   status 255 for its own failures (connection refused/timed out,
///   authentication, host-key verification, the `ControlMaster` control
///   socket), but a far-side `perl` `die` propagates 255 too, so 255 selects
///   this branch ONLY with a positive transport diagnostic in stderr. Exit
///   255 alone names no layer and is never reported as transport;
/// * the far-side `perl` could not be STARTED — the remote shell's 126/127
///   ("found but not executable" / "not found"), which is the only layer that
///   is actually a statement about `perl`;
/// * `perl` ran and the script exited non-zero (a missing root, an unreadable
///   directory, a name that cannot cross the wire, ...).
///
/// Pre-fix every non-zero exit appended "(is perl installed on the remote
/// host?)", so an `ssh` exit 255 — including the `unix_listener:` control-
/// socket bind failure — was mislabeled as a missing interpreter; the fix
/// after that made every exit 255 transport, which mislabeled the script's
/// own `die`-at-255 refusals. This version attributes the layer from the
/// EVIDENCE in stderr and, when the layer cannot be established, reports what
/// is known (the exit status and preserved stderr) instead of asserting ssh,
/// connection, or authentication.
fn remote_manifest_failure(root: &Path, out: &ExecOutcome) -> Error {
    let stderr = out.stderr.trim();
    let stderr = if stderr.is_empty() {
        "(no stderr)"
    } else {
        stderr
    };
    if perl_could_not_start(out) {
        return Error::transport(format!(
            "remote tree verification at {} could not start the far-side `perl` (exit {}): {} \
             (is perl installed on the remote host?)",
            root.display(),
            out.exit_code,
            stderr
        ));
    }
    if transport_failed_before_the_command(out) {
        return Error::transport(format!(
            "remote tree verification at {} could not run: the transport failed before the \
             far-side command started (exit {}): {} (this is a transport-level failure — \
             connection, authentication, host key, or the ssh control socket)",
            root.display(),
            out.exit_code,
            stderr
        ));
    }
    Error::transport(format!(
        "remote tree verification at {} failed inside the far-side manifest script (exit {}): {}",
        root.display(),
        out.exit_code,
        stderr
    ))
}

/// Whether `out` reports that the far-side `perl` program itself could not be
/// started (as opposed to running and exiting non-zero).
fn perl_could_not_start(out: &ExecOutcome) -> bool {
    // 126 = found but not executable; 127 = not found. The remote command is
    // `exec -- perl -e …`, so both statuses name the `perl` program.
    if out.exit_code == 126 || out.exit_code == 127 {
        return true;
    }
    // A shell that reports the not-found status through a wrapper prints the
    // diagnostic instead; accept that spelling as the same stage.
    out.stderr.contains("perl: command not found")
        || out.stderr.contains("perl: not found")
        || out.stderr.contains("perl: No such file")
}

/// Whether `out` reports a failure of the TRANSPORT layer, before the far-side
/// command could run at all.
///
/// Evidence, not a guess from the exit status: the runner's own timeout
/// sentinel is conclusive on its own, but `ssh` exit status 255 is NOT,
/// because a far-side `perl` `die` propagates the same status (perl exits 255
/// when `$!` is 0) — the crate's own manifest script refuses a non-directory
/// root and a non-NFC name exactly that way. Exit 255 therefore selects this
/// branch only with a positive transport diagnostic in stderr.
fn transport_failed_before_the_command(out: &ExecOutcome) -> bool {
    // The runner's timeout/no-status sentinel: THIS process killed the child
    // at the deadline, so no far-side command produced the outcome. No
    // far-side process can exit with a negative status, so -1 is conclusive
    // by construction and needs no textual corroboration.
    if out.exit_code == -1 {
        return true;
    }
    // `ssh` exits 255 for its own failures, but the far-side perl `die` does
    // too, so 255 alone proves nothing. Require a positive transport marker.
    if out.exit_code != 255 {
        return false;
    }
    // The markers below were each observed from a real `ssh` (OpenSSH) or from
    // the crate's own script; `Permission denied` is deliberately ABSENT — it
    // is ambiguous, because the crate's own script prints it (from `opendir
    // $dir: $!`, exit 13) for an unreadable far-side directory. The connect-
    // stage spellings (`Connection refused`, `Connection timed out`, `No
    // route to host`, `Network is unreachable`) are additionally subsumed by
    // the `ssh: ` prefix in real output and are kept as belt-and-braces.
    const TRANSPORT_MARKERS: &[&str] = &[
        "ssh: ",
        "kex_exchange_identification",
        "Host key verification failed",
        "Connection closed by",
        "Connection refused",
        "Connection timed out",
        "No route to host",
        "Network is unreachable",
        "unix_listener:",
    ];
    TRANSPORT_MARKERS
        .iter()
        .any(|marker| out.stderr.contains(marker))
}

/// Classify every path in the union of `source` and `dest`, sorted by path.
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
    use super::*;
    use crate::env::SysEnv;
    use crate::test_support::fixture_tmpdir;
    use crate::transport::{Layout, LocalTransport};
    use std::fs;

    fn write(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
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
    /// directory, and a symlink and assert each entry's string projects back
    /// to the kind and equals [`EntryKind::as_str`].
    #[test]
    fn entry_kind_strings_match_the_canonicalizer() {
        let dir = fixture_tmpdir(&SysEnv::from_process()).unwrap();
        let root = dir.path().join("tree");
        tree_with_every_kind(&root);
        let meta = canonicalize_tree(&root).unwrap();
        let mut seen = BTreeSet::new();
        for entry in &meta.entries {
            let kind = EntryKind::of(entry).unwrap();
            assert_eq!(entry.entry_type, kind.as_str());
            seen.insert(kind);
        }
        assert_eq!(
            seen,
            BTreeSet::from([EntryKind::File, EntryKind::Dir, EntryKind::Symlink]),
            "the fixture exercises every canonical entry kind"
        );
    }

    /// A manifest entry kind outside the canonical set is refused.
    #[test]
    fn unknown_entry_type_is_refused() {
        assert!(EntryKind::from_manifest("socket").is_err());
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
        let absent = dir.path().join("absent");
        let ta =
            LocalTransport::new(&SysEnv::from_process(), absent.clone(), Layout::empty()).unwrap();
        assert!(
            matches!(remote_manifest(&ta), Err(Error::Transport(_))),
            "an absent local remote root must be a transport error"
        );

        // A non-directory root is refused the same way (not described as empty).
        let file = dir.path().join("not-a-dir");
        write(&file, b"x");
        let tf = LocalTransport::new(&SysEnv::from_process(), file, Layout::empty()).unwrap();
        assert!(
            matches!(remote_manifest(&tf), Err(Error::Transport(_))),
            "a non-directory local remote root must be a transport error"
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
        };
        let msg = remote_manifest_failure(Path::new("/srv/store"), &out).to_string();
        assert!(
            msg.contains("is perl installed on the remote host?"),
            "a 127 must suggest perl may be absent: {msg}"
        );
    }

    /// F1: `perl`'s `die` exits 255 when `$! == 0` (perl's documented rule),
    /// and the crate's OWN far-side script refuses a non-directory root and a
    /// non-NFC name exactly that way. Exit 255 ALONE therefore establishes no
    /// layer: with the script's own stderr the failure must stay a far-side
    /// script failure, naming the exit status and preserved stderr.
    ///
    /// PRE-FIX MISCLASSIFICATION (probe, before the fix): both inputs returned
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
        };
        let msg = remote_manifest_failure(Path::new("/srv/store"), &out).to_string();
        assert!(
            msg.contains("failed inside the far-side manifest script"),
            "a script exit must be reported as the script failure: {msg}"
        );
        assert!(!msg.contains("is perl installed"), "{msg}");
        assert!(!msg.contains("transport-level failure"), "{msg}");
    }
}
