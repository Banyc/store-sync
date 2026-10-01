//! Canonical tree metadata: the manifest.
//!
//! The canonical tree objects ([`canonicalize_tree`], [`compute_tree_digest`],
//! [`entry_paths`]) lead this module; they define the one canonical format for
//! a tree of bytes.
//!
//! The canonical format is a cross-module contract: the store verifies objects
//! against it, recovery re-hashes with it, and the SSH transport must preserve
//! exactly these bytes on upload. Any module that serializes or transfers tree
//! bytes diverging from this format silently breaks digest equality for every
//! other verifier.

use crate::digest::sha256_bytes;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;
use walkdir::WalkDir;

/// One entry in a canonical tree object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntry {
    /// NFC-normalized, UTF-8 relative path within the artifact root.
    pub path: String,
    /// `file`, `dir`, or `symlink`.
    #[serde(rename = "type")]
    pub entry_type: String,
    /// Octal mode string, e.g. `"0755"`.
    pub mode: String,
    /// For files: SHA-256 of contents. For symlinks: SHA-256 of the target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
    /// For symlinks: the (relative, in-root) link target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
}

/// Canonical tree metadata (the `tree.json` payload). `tree_schema_version`
/// is `TREE_SCHEMA_VERSION`; readers refuse any other value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeMetadata {
    pub tree_schema_version: u32,
    pub hash_algorithm: String,
    pub tree_sha256: String,
    pub entries: Vec<TreeEntry>,
}

/// [`canonicalize_tree`] emits exactly this value and every reader of a tree
/// record refuses any other version (fail closed).
pub const TREE_SCHEMA_VERSION: u32 = 1;

fn fmt_mode(m: u32) -> String {
    format!("{:04o}", m & 0o7777)
}

/// Lexically normalize a path, collapsing `.` and `..`, returning `None` if it
/// escapes the base directory.
fn normalize_lexical(base: &Path, rel: &Path) -> Option<PathBuf> {
    let mut out = base.to_path_buf();
    for comp in rel.components() {
        use std::path::Component::*;
        match comp {
            Prefix(_) | RootDir => return None,
            CurDir => {}
            ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Normal(c) => out.push(c),
        }
    }
    Some(out)
}

/// Canonicalize a directory into a [`TreeMetadata`] and compute its digest.
///
/// `root` must be a directory: an absent root is an error (the lexical
/// `canonicalize` fails), and a root that is not a directory (a regular
/// file, a symlink to one) is an error too — NEVER an empty manifest. An
/// existing EMPTY directory is a legitimate tree and canonicalizes to a
/// manifest with no entries.
///
/// Rejects absolute paths, `..`, NUL bytes, newline/tab filenames (the
/// remote verification wire format is line- and tab-separated, so the two
/// verification paths must agree), duplicate normalized paths,
/// escaping/absolute symbolic links, devices, sockets, FIFOs, and hard
/// links.
pub fn canonicalize_tree(root: &Path) -> Result<TreeMetadata> {
    let mut entries: Vec<TreeEntry> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    let root_c = root
        .canonicalize()
        .map_err(|e| Error::materialization(format!("canonicalize {}: {e}", root.display())))?;
    if !root_c.is_dir() {
        return Err(Error::materialization(format!(
            "canonicalize_tree root is not a directory: {}",
            root.display()
        )));
    }

    for entry in WalkDir::new(root).min_depth(1).into_iter() {
        let entry = entry.map_err(|e| Error::materialization(format!("walk {e}")))?;
        let path = entry.path();
        let rel_os = path
            .strip_prefix(root)
            .map_err(|e| Error::materialization(format!("{e}")))?;

        // Unicode NFC normalization and reject NUL bytes.
        let rel_str = rel_os.to_string_lossy();
        if rel_str.contains('\0') {
            return Err(Error::materialization(format!(
                "path contains NUL bytes: {}",
                path.display()
            )));
        }
        // Newline/tab filenames are refused here (at staging) so the local
        // and remote verification paths agree: the remote script's output is
        // line- and tab-separated, so such a filename would mangle the wire
        // format and make the tree unverifiable on a remote. Rejecting it
        // early turns that into a clear staging error instead of a confusing
        // remote digest mismatch.
        if rel_str.contains('\n') || rel_str.contains('\t') {
            return Err(Error::materialization(format!(
                "path contains newline or tab: {}",
                path.display()
            )));
        }
        let normalized: String = rel_str.nfc().collect();
        // Reject TRAVERSAL components — an exact `..` (or `.`) path
        // COMPONENT, never a substring: a legitimate filename like `a..b`
        // or `..hidden` contains ".." but is not traversal. The component
        // check splits on '/' and refuses only the exact traversal names.
        if normalized.split('/').any(|c| c == ".." || c == ".") {
            return Err(Error::materialization(format!(
                "path contains traversal components: {normalized}"
            )));
        }
        if normalized.starts_with('/') {
            return Err(Error::materialization(format!(
                "absolute path not allowed: {normalized}"
            )));
        }
        if !seen.insert(normalized.clone()) {
            return Err(Error::materialization(format!(
                "duplicate normalized path: {normalized}"
            )));
        }

        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| Error::materialization(format!("stat {}: {e}", path.display())))?;

        let entry_type;
        // Symlink entries carry a fixed canonical mode (0777) — the mode is
        // never read through the (symlink-following) platform helper, which
        // would fail on a dangling link. Dirs/files read their mode via the
        // platform helper (a documented 0o644 constant on Windows).
        let mut mode = if meta.is_symlink() {
            "0777".to_string()
        } else {
            fmt_mode(crate::platform::file_mode(path)?)
        };
        let mut content_sha256 = None;
        let mut symlink_target = None;

        if meta.is_dir() {
            entry_type = "dir";
        } else if meta.is_symlink() {
            entry_type = "symlink";
            let target = std::fs::read_link(path)
                .map_err(|e| Error::materialization(format!("readlink {}: {e}", path.display())))?;
            if target.is_absolute() {
                return Err(Error::materialization(format!(
                    "absolute symlink not allowed: {}",
                    path.display()
                )));
            }
            // Ensure target resolves inside the artifact root.
            let resolved = normalize_lexical(&root_c, &target);
            match resolved {
                Some(r) if r.starts_with(&root_c) => {}
                _ => {
                    return Err(Error::materialization(format!(
                        "escaping symlink not allowed: {}",
                        path.display()
                    )));
                }
            }
            let target_bytes = target.into_os_string().into_encoded_bytes();
            content_sha256 = Some(sha256_bytes(&target_bytes));
            symlink_target = Some(String::from_utf8_lossy(&target_bytes).into_owned());
            mode = "0777".to_string();
        } else if meta.is_file() {
            entry_type = "file";
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.nlink() > 1 {
                    return Err(Error::materialization(format!(
                        "hard links not allowed: {}",
                        path.display()
                    )));
                }
            }
            let data = std::fs::read(path)
                .map_err(|e| Error::materialization(format!("read {}: {e}", path.display())))?;
            content_sha256 = Some(sha256_bytes(&data));
        } else {
            return Err(Error::materialization(format!(
                "unsupported file type at {}",
                path.display()
            )));
        }

        entries.push(TreeEntry {
            path: normalized,
            entry_type: entry_type.to_string(),
            mode,
            content_sha256,
            symlink_target,
        });
    }

    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let mut meta = TreeMetadata {
        tree_schema_version: TREE_SCHEMA_VERSION,
        hash_algorithm: "sha256".to_string(),
        tree_sha256: String::new(),
        entries,
    };
    meta.tree_sha256 = compute_tree_digest(&meta);
    Ok(meta)
}

/// The remote tree-verification script: walks a tree on the remote and
/// prints one tab-separated line per entry —
/// `path\ttype\tmode_hex\tnlink\tcontent_sha256\tsymlink_target` — where
/// `type` is `f`/`d`/`l`/`o` (`o` = a non-regular file: FIFO, socket, or
/// device — classified separately so the assembler REJECTS it, mirroring
/// the local canonicalizer's rejection of special files, and so the script
/// never `open`s a FIFO, which would block), `mode_hex` is the raw st_mode
/// in hex, and `content_sha256` is the sha256 of the file bytes (or of the
/// symlink target). The tool assembles the canonical metadata from this
/// output and computes the digest ([`canonicalize_remote_entries`]), so
/// verification never transfers the tree CONTENT — only the per-file hashes
/// — which on a slow link costs a small round trip instead of a full tree
/// download. Runs via `Remote::exec` as `perl -e <script> <root>`;
/// `Digest::SHA` is a core perl module on every supported host.
///
/// A walk that did not actually enumerate the WHOLE tree must never exit 0
/// with a short or empty listing: a root that is not a directory, and any
/// directory the walk cannot open or read, makes the script `die` (non-zero
/// exit) so the caller refuses it. Only a walk that covered the whole tree
/// exits 0, and a root that IS a directory but has no entries (an existing
/// empty directory) prints empty stdout with exit 0 — assembling to the
/// EMPTY manifest it really is.
pub fn remote_tree_verify_script() -> &'static str {
    r#"use Digest::SHA qw(sha256_hex); my $root=$ARGV[0]; die qq{not a directory: $root\n} unless defined($root) && -d $root; my $emit = sub { my ($rel,$p)=@_; my @st=lstat($p); die qq{lstat $p: $!\n} unless @st; my $t = -l $p ? q{l} : (-d $p ? q{d} : (-f $p ? q{f} : q{o})); my $m=sprintf(q{%x}, $st[2] & 07777); my $n=$st[3]; my ($h,$tg)=(q{},q{}); if ($t eq q{f}) { open my $fh, q{<}, $p or die qq{open $p: $!}; binmode $fh; local $/; my $d=<$fh>; $h=sha256_hex($d); close $fh; } elsif ($t eq q{l}) { $tg=readlink($p); die qq{readlink $p: $!\n} unless defined $tg; $h=sha256_hex($tg); } print qq{$rel\t$t\t$m\t$n\t$h\t$tg\n}; }; my $walk; $walk = sub { my ($dir,$prefix)=@_; opendir(my $dh,$dir) or die qq{opendir $dir: $!\n}; $! = 0; my @names=readdir($dh); die qq{readdir $dir: $!\n} if $!; closedir($dh) or die qq{closedir $dir: $!\n}; for my $name (@names) { next if $name eq q{.} || $name eq q{..}; my $p=qq{$dir/$name}; my $rel=length($prefix) ? qq{$prefix/$name} : $name; $emit->($rel,$p); $walk->($p,$rel) if -d $p && !-l $p; } }; $walk->($root, q{});"#
}

/// Assemble canonical tree metadata from the remote verification script's
/// output ([`remote_tree_verify_script`]), applying the SAME validations the
/// local canonicalizer applies ([`canonicalize_tree`]): NFC normalization,
/// NUL/traversal/absolute/duplicate path rejection, hardlink rejection, and
/// in-root symlink targets. The per-file content hashes come from the remote
/// (sha256sum); the digest is computed from the assembled metadata, so a
/// corrupted or divergent remote tree produces a digest mismatch without any
/// content transfer. `root` is the remote tree root (absolute, on the
/// remote host) used for the in-root symlink check.
///
/// `output` must come from a walk that actually enumerated the whole tree:
/// [`remote_tree_verify_script`] exits non-zero for an absent, non-directory,
/// or unreadable root, and the caller must refuse that exit rather than
/// assemble the short or empty listing. Only a complete walk — including an
/// existing empty directory, whose empty stdout is the empty manifest — may
/// be assembled here.
pub fn canonicalize_remote_entries(output: &str, root: &Path) -> Result<TreeMetadata> {
    let mut entries: Vec<TreeEntry> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for line in output.lines() {
        let mut it = line.split('\t');
        let path = it.next().unwrap_or("");
        if path.is_empty() {
            continue;
        }
        let entry_type = it.next().unwrap_or("");
        let mode_hex = it.next().unwrap_or("");
        let nlink = it.next().unwrap_or("0");
        let content_hash = it.next().unwrap_or("");
        let symlink_target = it.next().unwrap_or("");

        // Path validation — mirror canonicalize_tree exactly.
        if path.contains('\0') {
            return Err(Error::materialization(format!(
                "path contains NUL bytes: {path}"
            )));
        }
        // Newline/tab are the wire-format breakers: the script's output is
        // line- and tab-separated, so a filename containing either would
        // mangle the fields. The local canonicalizer rejects them too, so
        // the two verification paths agree (a tree with such a filename is
        // refused at staging, never silently unverifiable on a remote).
        if path.contains('\n') || path.contains('\t') {
            return Err(Error::materialization(format!(
                "path contains newline or tab: {path}"
            )));
        }
        let normalized: String = path.nfc().collect();
        if normalized.split('/').any(|c| c == ".." || c == ".") {
            return Err(Error::materialization(format!(
                "path contains traversal components: {normalized}"
            )));
        }
        if normalized.starts_with('/') {
            return Err(Error::materialization(format!(
                "absolute path not allowed: {normalized}"
            )));
        }
        if !seen.insert(normalized.clone()) {
            return Err(Error::materialization(format!(
                "duplicate normalized path: {normalized}"
            )));
        }

        let mode = u32::from_str_radix(mode_hex, 16).map_err(|_| {
            Error::materialization(format!("invalid mode {mode_hex:?} for {normalized}"))
        })?;

        let entry = match entry_type {
            "d" => TreeEntry {
                path: normalized,
                entry_type: "dir".to_string(),
                mode: fmt_mode(mode),
                content_sha256: None,
                symlink_target: None,
            },
            "f" => {
                let n: u64 = nlink.parse().map_err(|_| {
                    Error::materialization(format!("invalid nlink {nlink:?} for {normalized}"))
                })?;
                if n > 1 {
                    return Err(Error::materialization(format!(
                        "hard links not allowed: {normalized}"
                    )));
                }
                if content_hash.is_empty() {
                    return Err(Error::materialization(format!(
                        "missing content hash for {normalized}"
                    )));
                }
                // The remote script emits lowercase hex (Digest::SHA's
                // sha256_hex), exactly like the local canonicalizer
                // ([`crate::digest::sha256_bytes`]). A malformed hash (wrong
                // length, non-hex, or uppercase) is rejected with a clear
                // error instead of silently producing a confusing digest
                // mismatch.
                if content_hash.len() != 64
                    || !content_hash
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                {
                    return Err(Error::materialization(format!(
                        "invalid content hash {content_hash:?} for {normalized}"
                    )));
                }
                TreeEntry {
                    path: normalized,
                    entry_type: "file".to_string(),
                    mode: fmt_mode(mode),
                    content_sha256: Some(content_hash.to_string()),
                    symlink_target: None,
                }
            }
            "l" => {
                if symlink_target.is_empty() {
                    return Err(Error::materialization(format!(
                        "missing symlink target for {normalized}"
                    )));
                }
                let target = PathBuf::from(symlink_target);
                if target.is_absolute() {
                    return Err(Error::materialization(format!(
                        "absolute symlink not allowed: {normalized}"
                    )));
                }
                let resolved = normalize_lexical(root, &target);
                match resolved {
                    Some(r) if r.starts_with(root) => {}
                    _ => {
                        return Err(Error::materialization(format!(
                            "escaping symlink not allowed: {normalized}"
                        )));
                    }
                }
                let target_bytes = symlink_target.as_bytes();
                TreeEntry {
                    path: normalized,
                    entry_type: "symlink".to_string(),
                    mode: "0777".to_string(),
                    content_sha256: Some(sha256_bytes(target_bytes)),
                    symlink_target: Some(symlink_target.to_string()),
                }
            }
            other => {
                return Err(Error::materialization(format!(
                    "unsupported file type at {normalized}: {other:?}"
                )));
            }
        };
        entries.push(entry);
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let mut meta = TreeMetadata {
        tree_schema_version: TREE_SCHEMA_VERSION,
        hash_algorithm: "sha256".to_string(),
        tree_sha256: String::new(),
        entries,
    };
    meta.tree_sha256 = compute_tree_digest(&meta);
    Ok(meta)
}

/// Verify that a stored [`TreeMetadata`] is EXACTLY the canonical metadata of
/// the tree content at `root`: canonicalize the root and compare EVERY field
/// (schema version, hash algorithm, tree digest, and each entry's
/// path/type/mode/content_sha256/symlink_target). Returns the RECOMPUTED
/// canonical metadata on success; any mismatch is an [`Error::integrity`]
/// failure (fail closed — a metadata record whose fields were mutated while
/// the tree content was left unchanged is never returned as if it were the
/// canonical metadata for that content).
pub fn verify_tree_metadata(root: &Path, stored: &TreeMetadata) -> Result<TreeMetadata> {
    let canonical = canonicalize_tree(root).map_err(|e| {
        Error::integrity(format!(
            "tree content at {} cannot be canonicalized: {e}",
            root.display()
        ))
    })?;
    if stored.tree_schema_version != canonical.tree_schema_version {
        return Err(Error::integrity(format!(
            "stored tree metadata at {} does not match the canonical metadata of the tree content: tree_schema_version {} != {}",
            root.display(),
            stored.tree_schema_version,
            canonical.tree_schema_version
        )));
    }
    if stored.hash_algorithm != canonical.hash_algorithm {
        return Err(Error::integrity(format!(
            "stored tree metadata at {} does not match the canonical metadata of the tree content: hash_algorithm {:?} != {:?}",
            root.display(),
            stored.hash_algorithm,
            canonical.hash_algorithm
        )));
    }
    if stored.tree_sha256 != canonical.tree_sha256 {
        return Err(Error::integrity(format!(
            "stored tree metadata at {} does not match the canonical metadata of the tree content: tree_sha256 {} != {}",
            root.display(),
            stored.tree_sha256,
            canonical.tree_sha256
        )));
    }
    if stored.entries.len() != canonical.entries.len() {
        return Err(Error::integrity(format!(
            "stored tree metadata at {} does not match the canonical metadata of the tree content: {} entries != {} entries",
            root.display(),
            stored.entries.len(),
            canonical.entries.len()
        )));
    }
    for (i, (se, ce)) in stored
        .entries
        .iter()
        .zip(canonical.entries.iter())
        .enumerate()
    {
        if se.path != ce.path {
            return Err(Error::integrity(format!(
                "stored tree metadata at {} does not match the canonical metadata of the tree content: entry {i} path {:?} != {:?}",
                root.display(),
                se.path,
                ce.path
            )));
        }
        if se.entry_type != ce.entry_type {
            return Err(Error::integrity(format!(
                "stored tree metadata at {} does not match the canonical metadata of the tree content: entry {i} ({:?}) type {:?} != {:?}",
                root.display(),
                se.path,
                se.entry_type,
                ce.entry_type
            )));
        }
        if se.mode != ce.mode {
            return Err(Error::integrity(format!(
                "stored tree metadata at {} does not match the canonical metadata of the tree content: entry {i} ({:?}) mode {:?} != {:?}",
                root.display(),
                se.path,
                se.mode,
                ce.mode
            )));
        }
        if se.content_sha256 != ce.content_sha256 {
            return Err(Error::integrity(format!(
                "stored tree metadata at {} does not match the canonical metadata of the tree content: entry {i} ({:?}) content_sha256 {:?} != {:?}",
                root.display(),
                se.path,
                se.content_sha256,
                ce.content_sha256
            )));
        }
        if se.symlink_target != ce.symlink_target {
            return Err(Error::integrity(format!(
                "stored tree metadata at {} does not match the canonical metadata of the tree content: entry {i} ({:?}) symlink_target {:?} != {:?}",
                root.display(),
                se.path,
                se.symlink_target,
                ce.symlink_target
            )));
        }
    }
    Ok(canonical)
}

/// Compute the canonical tree digest from metadata. Deterministic, independent
/// of filesystem layout or source ordering.
pub fn compute_tree_digest(meta: &TreeMetadata) -> String {
    let bytes = serde_json::to_vec(meta).expect("tree metadata serializes");
    sha256_bytes(&bytes)
}

/// Build the artifact-relative path strings for a tree's entries.
pub fn entry_paths(meta: &TreeMetadata) -> Vec<&str> {
    meta.entries.iter().map(|e| e.path.as_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{fixture_env, fixture_tmpdir, proptest_cases};
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    /// Build a RICH tree (a file, a nested file, and a symlink) so every
    /// entry-field mutation class has a target entry to mutate. The symlink
    /// target is resolved relative to the tree ROOT (the canonicalizer's
    /// in-root rule), so `sub/link -> file.txt` stays inside the root.
    fn build_tree(root: &Path) {
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("file.txt"), b"content").unwrap();
        std::fs::write(root.join("sub").join("nested.txt"), b"nested").unwrap();
        std::os::unix::fs::symlink("file.txt", root.join("sub").join("link")).unwrap();
    }

    /// The remote verification script ([`remote_tree_verify_script`]) must
    /// produce the EXACT same canonical digest as the local canonicalizer
    /// ([`canonicalize_tree`]): the script walks the tree and prints per-entry
    /// metadata (path/type/mode/nlink/content sha256), and
    /// [`canonicalize_remote_entries`] assembles the digest from it. This
    /// pins the equivalence on a RICH tree (a file, a nested file, and a
    /// symlink) — a divergence would falsely quarantine valid remote trees.
    #[test]
    fn remote_verify_script_digest_matches_local_canonicalization() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        build_tree(&root);
        let local = canonicalize_tree(&root).unwrap();

        let out = std::process::Command::new("perl")
            .args(["-e", remote_tree_verify_script()])
            .arg(&root)
            .output()
            .expect("perl must run");
        assert!(
            out.status.success(),
            "script failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let remote =
            canonicalize_remote_entries(&String::from_utf8_lossy(&out.stdout), &root).unwrap();
        assert_eq!(
            remote.tree_sha256, local.tree_sha256,
            "remote-script digest must equal the local canonical digest"
        );
        assert_eq!(remote.entries, local.entries);
    }

    /// The digest binds the tree content: a local tree canonicalizes to a
    /// digest, and mutating ONE byte of one file changes that digest (and the
    /// entry's content hash). Without this binding a manifest could not tell
    /// two different trees apart.
    #[test]
    fn one_byte_mutation_changes_the_digest() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("file.txt"), b"content").unwrap();
        let before = canonicalize_tree(&root).unwrap();
        assert_eq!(before.entries.len(), 1);
        assert_eq!(
            before.entries[0].content_sha256.as_deref().map(str::len),
            Some(64)
        );

        std::fs::write(root.join("file.txt"), b"contenu").unwrap();
        let after = canonicalize_tree(&root).unwrap();
        assert_ne!(
            before.tree_sha256, after.tree_sha256,
            "mutating one byte must change the tree digest"
        );
        assert_ne!(
            before.entries, after.entries,
            "mutating one byte must change the canonical entry"
        );
    }

    /// A legitimate filename containing `..` as a SUBSTRING (e.g. `a..b`,
    /// `..hidden`) is NOT traversal — the component-wise check accepts it.
    /// (An exact `..` path component cannot be created on POSIX — it is the
    /// parent — so the rejection arm is defensive; the acceptance arm is the
    /// regression this test pins: the old substring check falsely rejected
    /// these valid filenames.)
    #[test]
    fn dotdot_substring_is_not_traversal() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a..b"), b"content").unwrap();
        std::fs::write(root.join("..hidden"), b"content").unwrap();
        let meta = canonicalize_tree(&root).unwrap();
        let paths: Vec<&str> = meta.entries.iter().map(|e| e.path.as_str()).collect();
        assert!(
            paths.contains(&"a..b"),
            "a filename containing '..' as a substring is valid, got {paths:?}"
        );
        assert!(
            paths.contains(&"..hidden"),
            "a filename starting with '..' is valid, got {paths:?}"
        );
    }

    /// Run the remote verification script on `root` and return its stdout
    /// (the caller asserts on the parse outcome).
    fn run_remote_script(root: &Path) -> String {
        let out = std::process::Command::new("perl")
            .args(["-e", remote_tree_verify_script()])
            .arg(root)
            .output()
            .expect("perl must run");
        assert!(
            out.status.success(),
            "script failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Run the remote verification script on `root` and return the raw
    /// subprocess result, so a test can assert on the EXIT STATUS (the script
    /// must fail closed when it cannot enumerate the whole tree).
    fn run_remote_script_raw(root: &Path) -> std::process::Output {
        std::process::Command::new("perl")
            .args(["-e", remote_tree_verify_script()])
            .arg(root)
            .output()
            .expect("perl must run")
    }

    /// An existing EMPTY DIRECTORY is a legitimate tree: the script exits 0
    /// with empty stdout, and the assembler turns that into the empty manifest
    /// it really is. This is the complement of the refusal cases below — the
    /// empty-manifest result is only allowed when the walk really did
    /// enumerate a directory.
    #[test]
    fn remote_script_accepts_an_empty_directory_as_an_empty_manifest() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("empty");
        std::fs::create_dir_all(&root).unwrap();

        let out = run_remote_script_raw(&root);
        assert!(
            out.status.success(),
            "an empty directory must exit 0: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.stdout.is_empty(),
            "an empty directory must print an empty listing, got {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
        let meta =
            canonicalize_remote_entries(&String::from_utf8_lossy(&out.stdout), &root).unwrap();
        assert!(meta.entries.is_empty());
        assert_eq!(
            meta.tree_sha256.len(),
            64,
            "the empty manifest still carries a computed digest"
        );
    }

    /// A MISSING root must make the script exit non-zero: perl would otherwise
    /// print an empty listing with exit 0, which the caller would assemble into
    /// "the far side described an empty tree" — a manifest that drives
    /// deletions under `delete_extraneous`.
    #[test]
    fn remote_script_rejects_a_missing_root() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let missing = dir.path().join("does-not-exist");
        let out = run_remote_script_raw(&missing);
        assert!(
            !out.status.success(),
            "a missing root must exit non-zero, got success with stdout {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    /// A root that is a REGULAR FILE must exit non-zero for the same reason: a
    /// non-directory root is not a tree with no entries.
    #[test]
    fn remote_script_rejects_a_regular_file_root() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("plain.txt");
        std::fs::write(&root, b"content").unwrap();
        let out = run_remote_script_raw(&root);
        assert!(
            !out.status.success(),
            "a regular-file root must exit non-zero, got success with stdout {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    /// A subdirectory the walk cannot OPEN must exit non-zero rather than
    /// silently print a listing of the entries it happened to reach: a
    /// permission failure is not an empty (or short) tree.
    #[test]
    fn remote_script_rejects_an_unreadable_subdirectory() {
        use std::os::unix::fs::PermissionsExt;
        // Running as root defeats the permission check (DAC override), so the
        // case is untestable there; skip rather than assert a lie.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("a.txt"), b"content").unwrap();
        std::fs::write(root.join("sub/b.txt"), b"content").unwrap();
        let sub = root.join("sub");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000)).unwrap();

        let out = run_remote_script_raw(&root);

        // Restore so the TempDir's recursive cleanup can remove the tree.
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            !out.status.success(),
            "an unreadable subdirectory must exit non-zero, got success with stdout {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    /// A regular-file root must be REFUSED by the local canonicalizer instead
    /// of yielding an empty manifest: `WalkDir::new(file).min_depth(1)` yields
    /// nothing, so without the explicit directory check the file would be
    /// described as a tree with no entries.
    #[test]
    fn canonicalize_tree_rejects_a_non_directory_root() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("plain.txt");
        std::fs::write(&root, b"content").unwrap();
        let err = canonicalize_tree(&root).unwrap_err();
        assert!(
            err.to_string().contains("not a directory"),
            "a regular-file root must be refused, got: {err}"
        );
    }

    /// An existing EMPTY DIRECTORY is still a legitimate tree and
    /// canonicalizes to an empty manifest (the complement of the refusal above
    /// — the directory check must not reject a real empty tree).
    #[test]
    fn canonicalize_tree_accepts_an_empty_directory_as_an_empty_manifest() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("empty");
        std::fs::create_dir_all(&root).unwrap();
        let meta = canonicalize_tree(&root).unwrap();
        assert!(meta.entries.is_empty(), "an empty directory has no entries");
        assert_eq!(
            meta.tree_sha256.len(),
            64,
            "the empty manifest still carries a computed digest"
        );
    }

    /// A FIFO (or socket/device) must be rejected by BOTH verification
    /// paths: the local canonicalizer refuses non-regular files, and the
    /// remote script classifies it as `o` (other) — never `f` — so the
    /// assembler rejects it too, and the script never `open`s the FIFO
    /// (which would block until the exec timeout). This pins the
    /// convergence of the two paths on special files.
    #[test]
    fn special_files_rejected_by_both_canonicalizers() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("file.txt"), b"content").unwrap();
        let fifo = root.join("pipe");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o644) };
        assert_eq!(
            rc,
            0,
            "mkfifo must succeed: {}",
            std::io::Error::last_os_error()
        );

        // Local path: rejected.
        let local_err = canonicalize_tree(&root).unwrap_err();
        assert!(
            local_err.to_string().contains("unsupported file type"),
            "local canonicalizer must reject the FIFO, got: {local_err}"
        );

        // Remote path: the script classifies the FIFO as `o` and the
        // assembler rejects it (and the script COMPLETES — it never blocks
        // opening the FIFO).
        let out = run_remote_script(&root);
        let remote_err = canonicalize_remote_entries(&out, &root).unwrap_err();
        assert!(
            remote_err.to_string().contains("unsupported file type"),
            "remote assembler must reject the FIFO, got: {remote_err}"
        );
    }

    /// A hard link (nlink > 1) must be rejected by the remote verification
    /// path exactly as the local canonicalizer rejects it: the script prints
    /// the raw nlink and the assembler refuses nlink > 1.
    #[test]
    fn hard_links_rejected_by_remote_path() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.txt"), b"content").unwrap();
        std::fs::hard_link(root.join("a.txt"), root.join("b.txt")).unwrap();

        // Local path: rejected.
        let local_err = canonicalize_tree(&root).unwrap_err();
        assert!(
            local_err.to_string().contains("hard links not allowed"),
            "local canonicalizer must reject the hard link, got: {local_err}"
        );

        // Remote path: the script prints nlink=2 and the assembler rejects it.
        let out = run_remote_script(&root);
        let remote_err = canonicalize_remote_entries(&out, &root).unwrap_err();
        assert!(
            remote_err.to_string().contains("hard links not allowed"),
            "remote assembler must reject the hard link, got: {remote_err}"
        );
    }

    /// A symlink whose target escapes the tree root must be refused by BOTH
    /// verification paths: the local canonicalizer resolves the target
    /// lexically against the canonical root, and the remote assembler does
    /// the same against the remote root. An escaping link would let a
    /// manifest describe bytes outside the tree.
    #[test]
    fn escaping_symlink_rejected_by_both_canonicalizers() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        let outside = dir.path().join("outside.txt");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&outside, b"secret").unwrap();
        std::os::unix::fs::symlink("../outside.txt", root.join("escape")).unwrap();

        // Local path: rejected.
        let local_err = canonicalize_tree(&root).unwrap_err();
        assert!(
            local_err.to_string().contains("escaping symlink"),
            "local canonicalizer must reject the escaping symlink, got: {local_err}"
        );

        // Remote path: the script prints the raw target and the assembler
        // resolves it against the remote root and rejects the escape.
        let out = run_remote_script(&root);
        let remote_err = canonicalize_remote_entries(&out, &root).unwrap_err();
        assert!(
            remote_err.to_string().contains("escaping symlink"),
            "remote assembler must reject the escaping symlink, got: {remote_err}"
        );
    }

    /// The remote assembler applies the SAME duplicate-normalized-path rule
    /// the local canonicalizer applies: two wire paths that NFC-normalize to
    /// the same string describe the same entry twice and are refused (a local
    /// filesystem cannot produce that collision on POSIX, so only the wire
    /// path can).
    #[test]
    fn duplicate_normalized_path_rejected_by_remote_assembler() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        let hash = "0".repeat(64);
        // "café" written as e + combining acute, then as the precomposed form:
        // distinct bytes, one NFC-normalized path.
        let output =
            format!("cafe\u{301}.txt\tf\t1a4\t1\t{hash}\t\ncaf\u{e9}.txt\tf\t1a4\t1\t{hash}\t\n");
        let err = canonicalize_remote_entries(&output, &root).unwrap_err();
        assert!(
            err.to_string().contains("duplicate normalized path"),
            "remote assembler must reject the duplicated normalized path, got: {err}"
        );
    }

    /// The digest-equivalence pin extended to the entry classes the original
    /// test missed: an EMPTY file (zero-length content hash) and a UNICODE
    /// filename (NFC normalization must agree between the two paths).
    #[test]
    fn remote_script_digest_matches_for_empty_and_unicode_files() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("empty.txt"), b"").unwrap();
        // "café" written as e + combining acute (NFC-normalizes to é).
        std::fs::write(root.join("caf\u{301}.txt"), b"unicode").unwrap();
        let local = canonicalize_tree(&root).unwrap();

        let out = run_remote_script(&root);
        let remote = canonicalize_remote_entries(&out, &root).unwrap();
        assert_eq!(
            remote.tree_sha256, local.tree_sha256,
            "remote-script digest must equal the local canonical digest"
        );
        assert_eq!(remote.entries, local.entries);
    }

    /// A filename containing a newline or tab is refused by BOTH
    /// canonicalizers: the remote script's output is line- and
    /// tab-separated, so such a filename would mangle the wire format and
    /// make the tree unverifiable on a remote. Rejecting it in the local
    /// canonicalizer too keeps the two verification paths in agreement —
    /// the tree is refused at staging with a clear error, never silently
    /// unverifiable on a remote.
    #[test]
    fn newline_and_tab_filenames_rejected_by_both_canonicalizers() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a\nb"), b"content").unwrap();
        let local_err = canonicalize_tree(&root).unwrap_err();
        assert!(
            local_err.to_string().contains("newline or tab"),
            "local canonicalizer must reject the newline filename, got: {local_err}"
        );

        let root2 = dir.path().join("tree2");
        std::fs::create_dir_all(&root2).unwrap();
        std::fs::write(root2.join("a\tb"), b"content").unwrap();
        let local_err2 = canonicalize_tree(&root2).unwrap_err();
        assert!(
            local_err2.to_string().contains("newline or tab"),
            "local canonicalizer must reject the tab filename, got: {local_err2}"
        );

        // Remote path: the newline filename mangles the line split and the
        // tab filename mangles the field split — both must fail closed.
        let out = run_remote_script(&root);
        assert!(
            canonicalize_remote_entries(&out, &root).is_err(),
            "remote assembler must reject the newline filename"
        );
        let out2 = run_remote_script(&root2);
        assert!(
            canonicalize_remote_entries(&out2, &root2).is_err(),
            "remote assembler must reject the tab filename"
        );
    }

    /// The remote assembler must reject a malformed content hash (wrong
    /// length, non-hex, or uppercase) with a clear error instead of
    /// silently folding it into the digest — a corrupted or divergent
    /// script output must fail closed loudly.
    #[test]
    fn remote_entries_reject_malformed_content_hash() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("file.txt"), b"content").unwrap();
        let good = run_remote_script(&root);

        for bad in [
            // Too short.
            "file.txt\tf\t1a4\t1\tdeadbeef\t",
            // Non-hex.
            "file.txt\tf\t1a4\t1\tzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\t",
            // Uppercase hex.
            "file.txt\tf\t1a4\t1\tABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEF\t",
        ] {
            let err = canonicalize_remote_entries(bad, &root).unwrap_err();
            assert!(
                err.to_string().contains("invalid content hash"),
                "malformed hash must be rejected with a clear error, got: {err}"
            );
        }
        // The well-formed output still parses.
        canonicalize_remote_entries(&good, &root).unwrap();
    }

    /// One systematically-mutated metadata field the verifier must reject
    /// while the tree root is left unchanged.
    #[derive(Clone, Copy, Debug)]
    enum Mutation {
        TreeSha256,
        HashAlgorithm,
        SchemaVersion,
        EntryPath,
        EntryType,
        EntryMode,
        EntryContentSha256,
        EntrySymlinkTarget,
        RemoveEntry,
        AddEntry,
        ReorderEntries,
    }

    fn mutation() -> impl Strategy<Value = Mutation> {
        prop::sample::select(vec![
            Mutation::TreeSha256,
            Mutation::HashAlgorithm,
            Mutation::SchemaVersion,
            Mutation::EntryPath,
            Mutation::EntryType,
            Mutation::EntryMode,
            Mutation::EntryContentSha256,
            Mutation::EntrySymlinkTarget,
            Mutation::RemoveEntry,
            Mutation::AddEntry,
            Mutation::ReorderEntries,
        ])
    }

    /// Apply exactly ONE mutation to the canonical metadata, leaving the tree
    /// root untouched.
    fn apply_mutation(mut meta: TreeMetadata, m: Mutation) -> TreeMetadata {
        match m {
            Mutation::TreeSha256 => meta.tree_sha256 = "0".repeat(64),
            Mutation::HashAlgorithm => meta.hash_algorithm = "sha512".to_string(),
            Mutation::SchemaVersion => meta.tree_schema_version += 1,
            Mutation::EntryPath => meta.entries[0].path = "mutated.txt".to_string(),
            Mutation::EntryType => meta.entries[0].entry_type = "dir".to_string(),
            Mutation::EntryMode => meta.entries[0].mode = "0000".to_string(),
            Mutation::EntryContentSha256 => {
                meta.entries[0].content_sha256 = Some("0".repeat(64));
            }
            Mutation::EntrySymlinkTarget => {
                if let Some(e) = meta.entries.iter_mut().find(|e| e.symlink_target.is_some()) {
                    e.symlink_target = Some("../other.txt".to_string());
                }
            }
            Mutation::RemoveEntry => {
                meta.entries.pop();
            }
            Mutation::AddEntry => meta.entries.push(TreeEntry {
                path: "bogus.txt".to_string(),
                entry_type: "file".to_string(),
                mode: "0644".to_string(),
                content_sha256: Some("0".repeat(64)),
                symlink_target: None,
            }),
            Mutation::ReorderEntries => {
                meta.entries.swap(0, 1);
            }
        }
        meta
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        // THE CONTENT BINDING: the verifier compares the COMPLETE stored
        // metadata against freshly canonicalized metadata of the actual tree
        // content. Mutating ANY metadata field (tree_sha256, hash_algorithm,
        // schema version, an entry's path/type/mode/content_sha256/
        // symlink_target, entry count, ordering) while leaving the tree root
        // unchanged must be REJECTED; the unmutated metadata verifies and
        // returns the recomputed canonical value.
        #[test]
        fn mutated_metadata_is_rejected(m in mutation()) {
            let dir = fixture_tmpdir(&fixture_env()).unwrap();
            let root = dir.path().join("tree");
            build_tree(&root);
            let canonical = canonicalize_tree(&root).unwrap();
            let mutated = apply_mutation(canonical.clone(), m);
            prop_assert!(
                verify_tree_metadata(&root, &mutated).is_err(),
                "mutation {m:?} of the stored metadata must be rejected while the tree root is unchanged"
            );
            // The unmutated metadata verifies and returns the RECOMPUTED
            // canonical value (never the stored bytes).
            let verified = verify_tree_metadata(&root, &canonical).unwrap();
            prop_assert_eq!(verified, canonical);
        }
    }
}
