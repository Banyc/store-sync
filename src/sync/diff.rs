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
use crate::transport::Remote;
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
        return Err(Error::transport(format!(
            "remote tree verification at {} failed (exit {}): {} (is perl installed on the remote host?)",
            root.display(),
            out.exit_code,
            out.stderr.trim()
        )));
    }
    canonicalize_remote_entries(&out.stdout, root)
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
}
