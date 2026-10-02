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
//!
//! # Names are on-disk names: NFC UTF-8, or the tree is refused
//!
//! The manifest's paths are the entries' ON-DISK names, so an entry path is
//! stored exactly as the filesystem spells it (joined with `/`): valid UTF-8
//! and already NFC. Canonicalization therefore REFUSES a tree containing a
//! name that is not valid UTF-8 or not already NFC, with an error that names
//! the offending entry, instead of converting or normalizing it. This is
//! deliberate: the stored path is used to ADDRESS the file downstream, and
//! storing a normalized spelling names a path that does not exist on a
//! normalization-sensitive filesystem (Linux/ext4) — the sync would either
//! fail to find the file or, worse, report success while leaving the
//! destination holding both spellings. The two canonicalizers (the local walk
//! and the remote wire assembler) apply the same rule, so they accept exactly
//! the same trees.
//!
//! # Symlink targets are bytes: UTF-8 and separator-free, or the tree is refused
//!
//! A symlink target is the LINK CONTENT, a byte string the kernel dereferences
//! literally, and the manifest stores it as a UTF-8 [`String`] on a line- and
//! tab-separated wire. Canonicalization therefore REFUSES (never truncates,
//! never lossily converts) a target that is not valid UTF-8 or that contains
//! any `WIRE_UNREPRESENTABLE_CHARS` character (NUL, LF, CR, or TAB). LF and
//! TAB are the wire separators; CR is refused because a CRLF-folding line
//! reader (Rust's `str::lines`, which the assembler must not use) strips a CR
//! that ends a line, and the LAST wire field is the target — a target ending
//! in CR would be silently truncated and then re-hashed, hiding the
//! divergence; NUL cannot be a C string. Any of them would make the stored
//! spelling address a DIFFERENT path than the on-disk link. The raw target
//! bytes are what the content hash binds, so the two canonicalizers must agree
//! on them exactly.
//!
//! NFC is deliberately NOT required of a target. A name is an index into the
//! tree, but a target is DATA: the kernel resolves it verbatim, it may contain
//! `..`, and normalizing it would silently repoint the link (and change the
//! hash that binds the link's content). Refusing non-NFC targets would reject
//! legitimate links that merely happen to spell their target in a decomposed
//! form; accepting them verbatim is faithful and keeps both canonicalizers in
//! agreement. Only the UTF-8 half of the NAME rule is applied to targets; the
//! NFC half is not.

use crate::digest::sha256_bytes;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use unicode_normalization::UnicodeNormalization;
use walkdir::WalkDir;

/// One entry in a canonical tree object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntry {
    /// The entry's ON-DISK name, in NFC over UTF-8, `/`-separated relative
    /// to the artifact root. Canonicalization stores the exact on-disk
    /// spelling (never a re-spelled form) because this string is what
    /// downstream code uses to ADDRESS the file. The spelling is
    /// host-independent: nested entries are `a/b` on every platform. A
    /// literal `\` inside one component is an ordinary name character (legal
    /// on Unix) and is preserved verbatim, so readers must split on `/` only.
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

/// The manifest's canonical spelling for an artifact-relative path: every
/// valid-UTF-8 [`Component::Normal`] name joined with `/`.
///
/// This is a COMPONENT join, never a `\` -> `/` string replacement, because
/// `\` is an ordinary character in a Unix file name: rewriting it would
/// corrupt a legal single-component name like `a\b`. Joining components
/// instead makes the spelling host-independent — on Windows `a\b` is two
/// components and becomes the portable `a/b`, while on Unix the same bytes
/// are one component and stay `a\b`, exactly as the remote (POSIX) script
/// already spells it. The spelling is stored VERBATIM, so a name it cannot
/// address is refused rather than converted: a non-`Normal` component (a root
/// or prefix, or a `.`/`..` component) is an error, a name that is not valid
/// UTF-8 is an error (never a lossy conversion), and an empty path (no
/// components) is an error too.
fn canonical_entry_path(rel: &Path) -> Result<String> {
    let mut out = String::new();
    let mut count = 0usize;
    for comp in rel.components() {
        match comp {
            Component::Normal(name) => {
                let Some(name) = name.to_str() else {
                    return Err(Error::materialization(format!(
                        "manifest requires NFC/UTF-8 names, but this entry's name is not valid UTF-8: {rel:?}"
                    )));
                };
                if count > 0 {
                    out.push('/');
                }
                out.push_str(name);
                count += 1;
            }
            _ => {
                return Err(Error::materialization(format!(
                    "path has a non-normal component: {rel:?}"
                )));
            }
        }
    }
    if count == 0 {
        return Err(Error::materialization(format!(
            "path has no components: {rel:?}"
        )));
    }
    Ok(out)
}

/// Whether every `/`-separated component of a wire path is a normal name:
/// non-empty, and neither `.` nor `..`. These are exactly the wire analogues
/// of requiring every OS path `Component` to be [`Component::Normal`], so a
/// path like `../x`, `/x`, `a/../b`, `a//b`, or `a/` can never enter a
/// manifest. A literal `\` is NOT special here: it is an ordinary character
/// within one component.
fn has_only_normal_components(path: &str) -> bool {
    path.split('/')
        .all(|c| !c.is_empty() && c != "." && c != "..")
}

/// The characters an entry NAME or a symlink TARGET may not contain: the ONE
/// refused set that both canonicalizers share.
///
/// - NUL cannot appear in a POSIX path or in the C string a link target is.
/// - LF and TAB are the manifest wire's line and field separators.
/// - CR is refused because a CRLF-folding line reader (Rust's `str::lines`,
///   which the assembler must not use) strips a CR that ends a line; the last
///   wire field is the symlink target, so a target ending in CR would be
///   silently truncated and then re-hashed, hiding the divergence.
///
/// [`validate_entry_path`] and [`validate_symlink_target`] both consult this
/// set, and the far-side script refuses the same four bytes, so the local walk
/// and the wire path accept exactly the same trees.
const WIRE_UNREPRESENTABLE_CHARS: [char; 4] = ['\0', '\n', '\r', '\t'];

/// The first character in `s` that cannot cross the wire faithfully
/// ([`WIRE_UNREPRESENTABLE_CHARS`]), or `None` when `s` is wire-clean.
fn first_unrepresentable_char(s: &str) -> Option<char> {
    s.chars().find(|c| WIRE_UNREPRESENTABLE_CHARS.contains(c))
}

/// A short human-readable name for a refused character, used in errors so the
/// refusal says exactly which byte broke the wire rule.
fn unrepresentable_char_name(c: char) -> &'static str {
    match c {
        '\0' => "NUL",
        '\n' => "newline (LF)",
        '\r' => "carriage return (CR)",
        '\t' => "tab",
        _ => "unrepresentable character",
    }
}

/// Validate an entry path (the local spelling built by
/// [`canonical_entry_path`], or the raw WIRE spelling the remote script
/// printed) and return it UNCHANGED. Both canonicalizers funnel through this
/// so they accept exactly the same set of trees.
///
/// Rejects any [`WIRE_UNREPRESENTABLE_CHARS`] character (NUL, LF, CR, or TAB) —
/// LF/TAB are the wire separators, and a CR would be folded by a CRLF-aware
/// line reader and silently truncate the field — naming the character and the
/// entry. It also rejects absolute paths and any empty or traversal (`.`/`..`)
/// component, and — because the manifest stores on-disk names — REQUIRES the
/// spelling to be already NFC instead of normalizing it. A non-NFC name is
/// refused, naming the entry: storing a normalized spelling would address a
/// path that does not exist on a normalization-sensitive filesystem.
fn validate_entry_path(path: &str) -> Result<String> {
    if let Some(c) = first_unrepresentable_char(path) {
        return Err(Error::materialization(format!(
            "path contains {} (a wire-unrepresentable character; the manifest wire refuses NUL/LF/CR/TAB): {path}",
            unrepresentable_char_name(c)
        )));
    }
    if path.starts_with('/') {
        return Err(Error::materialization(format!(
            "absolute path not allowed: {path}"
        )));
    }
    if !has_only_normal_components(path) {
        return Err(Error::materialization(format!(
            "path contains a traversal or empty component: {path}"
        )));
    }
    let nfc: String = path.nfc().collect();
    if nfc != path {
        return Err(Error::materialization(format!(
            "manifest requires NFC/UTF-8 names, but this entry path is not NFC-normalized: {path}"
        )));
    }
    Ok(path.to_string())
}

/// Validate a symlink target exactly as the wire requires: valid UTF-8 (the
/// manifest's [`TreeEntry::symlink_target`] is a string), and free of every
/// [`WIRE_UNREPRESENTABLE_CHARS`] character (NUL, LF, CR, or TAB). The target
/// is returned UNCHANGED.
///
/// NFC is NOT required: a target is not an addressable NAME but the link's
/// DATA — the kernel dereferences it verbatim, it may legitimately contain `..`,
/// and normalizing it would repoint the link and change the hash that binds its
/// content. A non-UTF-8 target cannot be stored in a UTF-8 manifest at all, so
/// it is refused rather than lossily converted (which would install a link to a
/// different path). `entry_path` names the offending entry in every error.
fn validate_symlink_target(entry_path: &str, target: &str) -> Result<String> {
    if let Some(c) = first_unrepresentable_char(target) {
        return Err(Error::materialization(format!(
            "symlink target of entry {entry_path} contains {} (a wire-unrepresentable character; the manifest wire refuses NUL/LF/CR/TAB): {target:?}",
            unrepresentable_char_name(c)
        )));
    }
    Ok(target.to_string())
}

/// Canonicalize a directory into a [`TreeMetadata`] and compute its digest.
///
/// `root` must be a directory: an absent root is an error (the lexical
/// `canonicalize` fails), and a root that is not a directory (a regular
/// file, a symlink to one) is an error too — NEVER an empty manifest. An
/// existing EMPTY directory is a legitimate tree and canonicalizes to a
/// manifest with no entries.
///
/// Rejects absolute paths, `..`, NUL/LF/CR/TAB in names and targets (the
/// remote verification wire format is line- and tab-separated and a CRLF
/// reader folds a trailing CR, so the two verification paths must agree),
/// names that are not valid UTF-8 or not
/// already NFC (the stored path IS the on-disk name, never a normalized
/// re-spelling), duplicate paths, escaping/absolute symbolic links, devices,
/// sockets, FIFOs, and hard links.
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

        // Build the canonical spelling from the path's COMPONENTS, never by
        // rewriting separators in a string. Every component must be a valid
        // UTF-8 `Component::Normal`: a root/prefix, `.`, or `..` component is
        // not a portable artifact-relative path and is refused, and a
        // non-UTF-8 name is refused rather than lossily converted. On Windows
        // a nested path (`a\b`) has two components and becomes the portable
        // `a/b`; on Unix those same bytes are ONE component, so a literal
        // `\` inside a file name is preserved verbatim rather than corrupted
        // into a separator.
        let joined = canonical_entry_path(rel_os)?;
        // Validate the spelling the manifest will store — the ON-DISK name —
        // because that is exactly what the remote assembler sees too: NUL,
        // LF, CR, and TAB, absolute paths, empty/traversal components, and
        // names that are not already NFC are refused here exactly as they are
        // there. The accepted spelling is stored UNCHANGED; a normalized
        // spelling would name a different file on a normalization-sensitive
        // filesystem.
        let entry_path = validate_entry_path(&joined)?;
        if !seen.insert(entry_path.clone()) {
            return Err(Error::materialization(format!(
                "duplicate normalized path: {entry_path}"
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
            // The target is LINK CONTENT, so it must be stored faithfully or
            // the tree refused: a lossy conversion would install a link to a
            // different path. It is validated as UTF-8 (the manifest stores a
            // string) and for every wire-unrepresentable character, naming
            // this entry on refusal; the hash binds the RAW bytes.
            let target_bytes = target.into_os_string().into_encoded_bytes();
            let target_str = std::str::from_utf8(&target_bytes).map_err(|_| {
                Error::materialization(format!(
                    "manifest requires UTF-8 symlink targets, but the target of entry {entry_path} is not valid UTF-8 (raw bytes: {target_bytes:?})"
                ))
            })?;
            symlink_target = Some(validate_symlink_target(&entry_path, target_str)?);
            content_sha256 = Some(sha256_bytes(&target_bytes));
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
            path: entry_path,
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
/// `Digest::SHA` and `Unicode::Normalize` are core perl modules on every
/// supported host.
///
/// A walk that did not actually enumerate the WHOLE tree must never exit 0
/// with a short or empty listing: a root that is not a directory, and any
/// directory the walk cannot open or read, makes the script `die` (non-zero
/// exit) so the caller refuses it. Only a walk that covered the whole tree
/// exits 0, and a root that IS a directory but has no entries (an existing
/// empty directory) prints empty stdout with exit 0 — assembling to the
/// EMPTY manifest it really is.
///
/// The script also VALIDATES the raw bytes before printing, because the
/// client decodes stdout lossily ([`String::from_utf8_lossy`] in the
/// runner) and so can never recover a byte the script mangled. It `die`s
/// (non-zero exit) — never truncates or lossily converts — for any entry
/// NAME that is not valid UTF-8, is not already NFC, or contains any
/// NUL/LF/CR/TAB, and for any symlink TARGET that is not valid UTF-8 or
/// contains any NUL/LF/CR/TAB. LF and TAB are the wire separators; CR is
/// refused because a CRLF-folding line reader would strip a trailing CR and
/// truncate the last field (the target). NFC is NOT required of a target: it
/// is link data the kernel dereferences verbatim, not an addressable name.
/// The client's existing `!out.success()` path turns the
/// non-zero exit into an error that carries this stderr, so a tree that
/// cannot cross the wire faithfully is refused where the raw bytes are
/// still visible rather than silently mis-described.
pub fn remote_tree_verify_script() -> &'static str {
    r#"use Digest::SHA qw(sha256_hex);
use Unicode::Normalize qw(NFC);
my $root=$ARGV[0];
die qq{not a directory: $root\n} unless defined($root) && -d $root;
my $hex = sub { my ($s)=@_; return unpack(q{H*},$s); };
my $check_name = sub {
    my ($n,$dir)=@_;
    die(qq{entry name under $dir contains a tab, newline, carriage return, or NUL (the manifest wire refuses NUL/LF/CR/TAB): } . $hex->($n) . qq{\n}) if $n =~ /[\n\r\t\0]/;
    my $c=$n;
    die(qq{entry name under $dir is not valid UTF-8: } . $hex->($n) . qq{\n}) unless utf8::decode($c);
    die(qq{entry name under $dir is not NFC-normalized: $n\n}) if NFC($c) ne $c;
};
my $check_target = sub {
    my ($tg,$rel)=@_;
    die(qq{symlink target of $rel contains a tab, newline, carriage return, or NUL (the manifest wire refuses NUL/LF/CR/TAB): } . $hex->($tg) . qq{\n}) if $tg =~ /[\n\r\t\0]/;
    my $c=$tg;
    die(qq{symlink target of $rel is not valid UTF-8: } . $hex->($tg) . qq{\n}) unless utf8::decode($c);
};
my $emit = sub { my ($rel,$p)=@_; my @st=lstat($p); die qq{lstat $p: $!\n} unless @st; my $t = -l $p ? q{l} : (-d $p ? q{d} : (-f $p ? q{f} : q{o})); my $m=sprintf(q{%x}, $st[2] & 07777); my $n=$st[3]; my ($h,$tg)=(q{},q{}); if ($t eq q{f}) { open my $fh, q{<}, $p or die qq{open $p: $!}; binmode $fh; local $/; my $d=<$fh>; $h=sha256_hex($d); close $fh; } elsif ($t eq q{l}) { $tg=readlink($p); die qq{readlink $p: $!\n} unless defined $tg; $check_target->($tg,$rel); $h=sha256_hex($tg); } print qq{$rel\t$t\t$m\t$n\t$h\t$tg\n}; };
my $walk; $walk = sub { my ($dir,$prefix)=@_; opendir(my $dh,$dir) or die qq{opendir $dir: $!\n}; $! = 0; my @names=readdir($dh); die qq{readdir $dir: $!\n} if $!; closedir($dh) or die qq{closedir $dir: $!\n}; for my $name (@names) { next if $name eq q{.} || $name eq q{..}; $check_name->($name,$dir); my $p=qq{$dir/$name}; my $rel=length($prefix) ? qq{$prefix/$name} : $name; $emit->($rel,$p); $walk->($p,$rel) if -d $p && !-l $p; } };
$walk->($root, q{});"#
}

/// Validate a 64-character lowercase-hex SHA-256 as printed by the far-side
/// script (Digest::SHA's `sha256_hex`). Returns an error naming the entry for
/// a wrong-length, non-hex, or uppercase hash, so a corrupted or divergent
/// line fails closed instead of silently producing a confusing digest.
fn validate_wire_hash(hash: &str, entry_path: &str) -> Result<()> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::materialization(format!(
            "invalid content hash {hash:?} for {entry_path}"
        )));
    }
    Ok(())
}

/// Assemble canonical tree metadata from the remote verification script's
/// output ([`remote_tree_verify_script`]), applying the SAME validations the
/// local canonicalizer applies ([`canonicalize_tree`]): already-NFC/UTF-8
/// names (a non-NFC name is refused, never normalized),
/// NUL/traversal/absolute/duplicate path rejection, hardlink rejection, and
/// in-root symlink targets that are valid UTF-8 and free of every
/// `WIRE_UNREPRESENTABLE_CHARS` character (NUL/LF/CR/TAB). A line is split on
/// LF ALONE and refused when it ends in a bare CR (Rust's `str::lines` would
/// fold it away, truncating the last field), and a line that does not have
/// exactly six tab-separated fields is refused: the script never emits one,
/// so it can only mean a name or target contained a tab — which the field
/// split would silently TRUNCATE — or a mangled/short line, and the assembler
/// refuses such a spelling instead of accepting a shorter one than the far
/// side meant. A SYMLINK's `content_sha256` is the hash the far side computed
/// over the RAW target bytes; the assembler validates its shape and REQUIRES
/// it to equal the hash of the target that crossed the wire, so a wire split
/// or fold can never be hidden by recomputing the hash after decoding. The
/// per-file content hashes come from the remote (sha256sum); the digest is
/// computed from the assembled metadata, so a corrupted or divergent remote
/// tree produces a digest mismatch without any content transfer. `root` is
/// the remote tree root (absolute, on the remote host) used for the in-root
/// symlink check.
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
    for line in output.split('\n') {
        // The script terminates every line with a single LF and never emits a
        // CR. `str::lines()` would fold a CR that immediately precedes the LF,
        // silently truncating the LAST wire field (the symlink target) so the
        // far side's bytes and the assembled target diverge. Split on LF alone
        // and refuse a bare CR explicitly, keeping the byte visible instead of
        // folding it away.
        if line.is_empty() {
            continue;
        }
        if line.ends_with('\r') {
            return Err(Error::materialization(format!(
                "wire line ends with a bare carriage return; the far side emits LF-terminated lines only, so this CR is field DATA that a CRLF-folding reader would discard: {line:?}"
            )));
        }
        // The script emits EXACTLY six tab-separated fields per entry:
        // path, type, mode, nlink, content_sha256, symlink_target. A different
        // count can only come from a tab inside a name or target (which the
        // split has already truncated) or from a mangled/short line; refuse it
        // rather than defaulting the missing fields and accepting a shorter
        // spelling than the far side printed. (The script itself dies first on
        // such a tree; this keeps a hand-built or proxied line from being
        // accepted lossily too.)
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 6 {
            return Err(Error::materialization(format!(
                "wire line does not have exactly six tab-separated fields (path/type/mode/nlink/hash/target); a name or symlink target contains a tab, or the line is malformed: {line:?}"
            )));
        }
        let path = fields[0];
        if path.is_empty() {
            continue;
        }
        let entry_type = fields[1];
        let mode_hex = fields[2];
        let nlink = fields[3];
        let content_hash = fields[4];
        let symlink_target = fields[5];

        // Path validation — mirror canonicalize_tree exactly by running the
        // SAME validator on the wire spelling. NUL/LF/CR/TAB are the
        // wire-unrepresentable characters (the script's output is line- and
        // tab-separated, and a CRLF reader folds a trailing CR),
        // absolute/empty/traversal components are refused,
        // and a name that is not already NFC is refused rather than
        // normalized, so the two verification paths accept exactly the same
        // trees.
        let entry_path = validate_entry_path(path)?;
        if !seen.insert(entry_path.clone()) {
            return Err(Error::materialization(format!(
                "duplicate normalized path: {entry_path}"
            )));
        }

        let mode = u32::from_str_radix(mode_hex, 16).map_err(|_| {
            Error::materialization(format!("invalid mode {mode_hex:?} for {entry_path}"))
        })?;

        let entry = match entry_type {
            "d" => TreeEntry {
                path: entry_path,
                entry_type: "dir".to_string(),
                mode: fmt_mode(mode),
                content_sha256: None,
                symlink_target: None,
            },
            "f" => {
                let n: u64 = nlink.parse().map_err(|_| {
                    Error::materialization(format!("invalid nlink {nlink:?} for {entry_path}"))
                })?;
                if n > 1 {
                    return Err(Error::materialization(format!(
                        "hard links not allowed: {entry_path}"
                    )));
                }
                if content_hash.is_empty() {
                    return Err(Error::materialization(format!(
                        "missing content hash for {entry_path}"
                    )));
                }
                // The remote script emits lowercase hex (Digest::SHA's
                // sha256_hex), exactly like the local canonicalizer
                // ([`crate::digest::sha256_bytes`]). A malformed hash (wrong
                // length, non-hex, or uppercase) is rejected with a clear
                // error instead of silently producing a confusing digest
                // mismatch.
                validate_wire_hash(content_hash, &entry_path)?;
                TreeEntry {
                    path: entry_path,
                    entry_type: "file".to_string(),
                    mode: fmt_mode(mode),
                    content_sha256: Some(content_hash.to_string()),
                    symlink_target: None,
                }
            }
            "l" => {
                if symlink_target.is_empty() {
                    return Err(Error::materialization(format!(
                        "missing symlink target for {entry_path}"
                    )));
                }
                // The script hashes the RAW link bytes (`readlink`) with
                // `sha256_hex`. The assembler must NOT silently RECOMPUTE the
                // hash over the decoded target: recomputation is exactly what
                // hides a wire split or fold, because a truncated target would
                // be re-hashed after truncation and the manifest would agree
                // with itself while disagreeing with the far side. Validate the
                // hash's shape and REQUIRE it to equal the hash of the target
                // that crossed the wire; a mismatch is refused, naming the
                // entry, rather than binding the far side's bytes to a
                // different target.
                validate_wire_hash(content_hash, &entry_path)?;
                // The target is link DATA, so it must be stored faithfully:
                // the SAME validator the local walk uses refuses NUL, LF, CR,
                // and TAB (the script refuses them before they reach this
                // string).
                let symlink_target = validate_symlink_target(&entry_path, symlink_target)?;
                let target = PathBuf::from(&symlink_target);
                if target.is_absolute() {
                    return Err(Error::materialization(format!(
                        "absolute symlink not allowed: {entry_path}"
                    )));
                }
                let resolved = normalize_lexical(root, &target);
                match resolved {
                    Some(r) if r.starts_with(root) => {}
                    _ => {
                        return Err(Error::materialization(format!(
                            "escaping symlink not allowed: {entry_path}"
                        )));
                    }
                }
                let recomputed = sha256_bytes(symlink_target.as_bytes());
                if recomputed != content_hash {
                    return Err(Error::materialization(format!(
                        "symlink target hash mismatch for {entry_path}: the far side hashed its raw target bytes as {content_hash}, but the target that crossed the wire hashes to {recomputed}; refusing rather than recording a hash of a target that is not what the far side saw"
                    )));
                }
                TreeEntry {
                    path: entry_path,
                    entry_type: "symlink".to_string(),
                    mode: "0777".to_string(),
                    content_sha256: Some(recomputed),
                    symlink_target: Some(symlink_target),
                }
            }
            other => {
                return Err(Error::materialization(format!(
                    "unsupported file type at {entry_path}: {other:?}"
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

    /// Whether `perl` is on `PATH`. The remote verification script IS the
    /// production wire format (it runs through `Remote::exec` as `perl -e`),
    /// so the tests that exercise it need an interpreter. On a host without
    /// one they SKIP with a visible reason instead of failing the suite for
    /// an environment reason that has nothing to do with this crate.
    fn perl_on_path() -> bool {
        std::process::Command::new("perl")
            .args(["-e", "exit 0"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    /// Skip the current test, with a clear reason, when `perl` is not on
    /// `PATH`. Used at the top of every test that runs the remote script.
    macro_rules! skip_without_perl {
        ($name:literal) => {
            if !perl_on_path() {
                eprintln!(
                    "skipping {}: perl is not on PATH, so the remote verification \
                     script cannot run",
                    $name
                );
                return;
            }
        };
    }

    /// Whether a mode-`0o000` directory ACTUALLY refuses enumeration for THIS
    /// process. Root and any process holding `CAP_DAC_READ_SEARCH`, and a
    /// filesystem that ignores mode bits, can still list it, so the
    /// unreadable-subdirectory premise is untestable there — asserting the
    /// script's refusal would fail for a reason unrelated to the script. Probe
    /// the premise with a REAL `read_dir` (the sync suite's pattern) rather
    /// than `geteuid() == 0`. Returns `true` when the read FAILED (the premise
    /// holds), and prints the skip reason otherwise so a skipped run is never
    /// silent.
    #[cfg(unix)]
    fn an_unreadable_dir_really_refuses_reads() -> bool {
        use std::os::unix::fs::PermissionsExt;
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let unreadable = dir.path().join("unreadable");
        std::fs::create_dir_all(&unreadable).unwrap();
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
        let refused = std::fs::read_dir(&unreadable).is_err();
        // Restore so the TempDir's recursive cleanup can remove the tree.
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o755)).unwrap();
        if !refused {
            eprintln!(
                "skipping: this process can still enumerate a mode-0o000 directory \
                 (effective uid 0, CAP_DAC_READ_SEARCH, or a mode-ignoring \
                 filesystem?), so the unreadable-subdirectory premise is untestable here"
            );
        }
        refused
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
        skip_without_perl!("remote_verify_script_digest_matches_local_canonicalization");
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

        // The canonical spelling IS the wire format: `/`-separated on every
        // host, so a nested entry is `sub/nested.txt` — never the Windows
        // `sub\nested.txt`. This is the parity pin for the platform defect:
        // before the component join, a Windows local walk and the POSIX
        // remote script disagreed on exactly this spelling.
        let paths: Vec<&str> = local.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["file.txt", "sub", "sub/link", "sub/nested.txt"],
            "entry paths must be '/'-separated"
        );
        assert!(
            paths.iter().all(|p| !p.contains('\\')),
            "no entry path may carry a backslash separator: {paths:?}"
        );
        // The manifest is BYTE-IDENTICAL between the two walks: the two
        // canonicalizers emit the same `tree.json` bytes, so neither can
        // describe the same tree differently.
        assert_eq!(
            serde_json::to_vec(&local).unwrap(),
            serde_json::to_vec(&remote).unwrap(),
            "the local and remote manifests must serialize to the same bytes"
        );
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

    /// A nested tree canonicalizes to `a/b/c`-style paths on EVERY platform:
    /// the separator is always `/`, never the host's native separator. This
    /// is the property the wire format depends on.
    #[test]
    fn nested_tree_paths_are_forward_slash_separated() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(root.join("a").join("b")).unwrap();
        std::fs::write(root.join("a").join("b").join("c.txt"), b"deep").unwrap();
        let meta = canonicalize_tree(&root).unwrap();
        let paths: Vec<&str> = meta.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["a", "a/b", "a/b/c.txt"]);
        assert!(
            paths.iter().all(|p| !p.contains('\\')),
            "a nested tree must never spell a separator as a backslash: {paths:?}"
        );
    }

    /// The rule for a literal `\` inside a single file NAME: `\` is not a
    /// separator on Unix, so such a name is ONE `Component::Normal` and the
    /// manifest keeps the backslash verbatim — the component join only ever
    /// inserts `/` BETWEEN components. This is exactly why normalization must
    /// NOT be a `\` -> `/` string replacement (that would rewrite a legal
    /// Unix filename); on Windows, where `\` IS a separator, it is instead
    /// split into two components and becomes the portable `a/b`.
    #[cfg(unix)]
    #[test]
    fn backslash_inside_a_unix_filename_is_preserved_verbatim() {
        skip_without_perl!("backslash_inside_a_unix_filename_is_preserved_verbatim");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        // A single-component name on Unix: this is not directory `a` with a
        // child `b`.
        std::fs::write(root.join("a\\b"), b"content").unwrap();
        let meta = canonicalize_tree(&root).unwrap();
        let paths: Vec<&str> = meta.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["a\\b"],
            "a backslash inside a Unix file name is an ordinary character"
        );
        assert_eq!(meta.entries[0].path, "a\\b");

        // The remote (POSIX) script spells the same name the same way, so the
        // two canonicalizers still agree byte-for-byte.
        let out = run_remote_script(&root);
        let remote = canonicalize_remote_entries(&out, &root).unwrap();
        assert_eq!(remote.entries, meta.entries);
        assert_eq!(remote.tree_sha256, meta.tree_sha256);
    }

    /// A path whose components are not all a valid-UTF-8
    /// `Component::Normal` is refused: the component join errors for a
    /// root/prefix, `.`, or `..` component, for an empty path, and (never a
    /// lossy conversion) for a name that is not valid UTF-8. The shared wire
    /// validator refuses the same spellings (`../x`, `/x`, `a/../b`, plus
    /// empty components) with NUL rejected too, and — because the manifest
    /// stores on-disk names — REQUIRES an already-NFC spelling instead of
    /// normalizing it.
    #[test]
    fn traversal_and_absolute_components_are_refused() {
        // The local component join refuses any non-`Normal` component.
        assert!(canonical_entry_path(Path::new("../x")).is_err());
        assert!(canonical_entry_path(Path::new("/x")).is_err());
        assert!(canonical_entry_path(Path::new("a/../b")).is_err());
        assert!(canonical_entry_path(Path::new("./x")).is_err());
        assert!(canonical_entry_path(Path::new("")).is_err());
        // A name containing `..` as a substring is still one normal component.
        assert_eq!(
            canonical_entry_path(Path::new("a..b")).unwrap(),
            "a..b".to_string()
        );

        // The shared validator — used by BOTH canonicalizers — refuses the
        // same spellings directly.
        for bad in ["../x", "/x", "a/../b", "a//b", "a/", "."] {
            assert!(
                validate_entry_path(bad).is_err(),
                "wire path {bad:?} must be refused"
            );
        }
        assert!(validate_entry_path("a\0b").is_err(), "NUL must be refused");
        assert!(
            validate_entry_path("a\nb").is_err(),
            "newline must be refused"
        );
        assert!(validate_entry_path("a\tb").is_err(), "tab must be refused");

        // The NFC rule: an already-NFC non-ASCII name is accepted and
        // returned UNCHANGED, while a decomposed spelling is refused (never
        // normalized) with an error that names the offending entry.
        assert_eq!(
            validate_entry_path("caf\u{e9}.txt").unwrap(),
            "caf\u{e9}.txt",
            "an already-NFC non-ASCII name must be stored unchanged"
        );
        let nfd_err = validate_entry_path("cafe\u{301}.txt").unwrap_err();
        assert!(
            nfd_err.to_string().contains("NFC/UTF-8"),
            "a non-NFC name must be refused with the rule it broke, got: {nfd_err}"
        );
        assert!(
            nfd_err.to_string().contains("cafe\u{301}.txt"),
            "the non-NFC refusal must name the offending entry, got: {nfd_err}"
        );

        // And the wire assembler refuses the same paths end to end.
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        let hash = "0".repeat(64);
        for bad in ["../x", "/x", "a/../b", "a//b", "a/"] {
            let output = format!("{bad}\tf\t1a4\t1\t{hash}\t\n");
            let err = canonicalize_remote_entries(&output, &root).unwrap_err();
            assert!(
                err.to_string().contains("traversal or empty")
                    || err.to_string().contains("absolute path not allowed"),
                "wire path {bad:?} must be refused, got: {err}"
            );
        }
    }

    /// A name that is not valid UTF-8 is refused by the component join,
    /// never lossily converted to `U+FFFD`: a lossy spelling would name a
    /// different file (and one the destination cannot address). The path is
    /// built from raw bytes so the test needs no filesystem support for
    /// invalid-UTF-8 names (macOS APFS rejects them outright).
    #[cfg(unix)]
    #[test]
    fn non_utf8_entry_name_is_refused_by_component_join() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let bad = Path::new(OsStr::from_bytes(b"bad\xffname.txt"));
        let err = canonical_entry_path(bad).unwrap_err();
        assert!(
            err.to_string().contains("NFC/UTF-8"),
            "a non-UTF-8 name must be refused with the rule it broke, got: {err}"
        );
        assert!(
            err.to_string().contains("bad"),
            "the non-UTF-8 refusal must name the offending entry, got: {err}"
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
        skip_without_perl!("remote_script_accepts_an_empty_directory_as_an_empty_manifest");
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
        skip_without_perl!("remote_script_rejects_a_missing_root");
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
        skip_without_perl!("remote_script_rejects_a_regular_file_root");
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
        skip_without_perl!("remote_script_rejects_an_unreadable_subdirectory");
        // A real probe, not `geteuid() == 0`: root, CAP_DAC_READ_SEARCH, and a
        // mode-ignoring filesystem all let this process list a 0o000 directory,
        // which would make the script's refusal untestable here.
        if !an_unreadable_dir_really_refuses_reads() {
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
        skip_without_perl!("special_files_rejected_by_both_canonicalizers");
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
        skip_without_perl!("hard_links_rejected_by_remote_path");
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
        skip_without_perl!("escaping_symlink_rejected_by_both_canonicalizers");
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

    /// Since every accepted path must already be NFC, a decomposed wire
    /// spelling is refused as non-NFC rather than normalized into a collision
    /// with its precomposed partner. The duplicate check itself remains as
    /// defence in depth: two IDENTICAL accepted lines still describe the same
    /// entry twice and are refused (only exact duplicates can collide now).
    #[test]
    fn non_nfc_and_duplicate_wire_paths_are_rejected_by_remote_assembler() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        let hash = "0".repeat(64);

        // "café" written as e + combining acute is not NFC: refused, never
        // normalized.
        let nfd = format!("cafe\u{301}.txt\tf\t1a4\t1\t{hash}\t\n");
        let err = canonicalize_remote_entries(&nfd, &root).unwrap_err();
        assert!(
            err.to_string().contains("NFC/UTF-8"),
            "a non-NFC wire path must be refused, got: {err}"
        );
        // Its already-NFC partner IS accepted.
        let nfc = format!("caf\u{e9}.txt\tf\t1a4\t1\t{hash}\t\n");
        canonicalize_remote_entries(&nfc, &root).unwrap();

        // An exact duplicate line is still refused as a duplicate entry.
        let duplicate = format!("a.txt\tf\t1a4\t1\t{hash}\t\na.txt\tf\t1a4\t1\t{hash}\t\n");
        let err = canonicalize_remote_entries(&duplicate, &root).unwrap_err();
        assert!(
            err.to_string().contains("duplicate normalized path"),
            "remote assembler must reject a duplicated path, got: {err}"
        );
    }

    /// The digest-equivalence pin extended to the entry classes the original
    /// test missed: an EMPTY file (zero-length content hash) and an
    /// already-NFC UNICODE filename (the two canonicalizers must agree on the
    /// stored spelling). It also pins the new refusal: a tree whose on-disk
    /// name is decomposed is refused by BOTH the local walk and the wire
    /// assembler, naming the offending entry, instead of being silently
    /// normalized into a spelling that cannot address the file on Linux.
    #[test]
    fn remote_script_digest_matches_for_empty_and_nfc_unicode_files() {
        skip_without_perl!("remote_script_digest_matches_for_empty_and_nfc_unicode_files");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("empty.txt"), b"").unwrap();
        // "café" in the precomposed (NFC) form is stored verbatim.
        std::fs::write(root.join("caf\u{e9}.txt"), b"unicode").unwrap();
        let local = canonicalize_tree(&root).unwrap();
        assert!(
            local.entries.iter().any(|e| e.path == "caf\u{e9}.txt"),
            "an already-NFC non-ASCII name must be stored verbatim, got {:?}",
            entry_paths(&local)
        );

        let out = run_remote_script(&root);
        let remote = canonicalize_remote_entries(&out, &root).unwrap();
        assert_eq!(
            remote.tree_sha256, local.tree_sha256,
            "remote-script digest must equal the local canonical digest"
        );
        assert_eq!(remote.entries, local.entries);

        // The decomposed spelling is a DIFFERENT on-disk name: refused by the
        // local walk and — more importantly — by the far-side SCRIPT itself,
        // where the raw bytes are still visible (the client's stdout decode
        // is lossy, but the non-zero exit is not).
        let nfd_root = dir.path().join("nfd");
        std::fs::create_dir_all(&nfd_root).unwrap();
        std::fs::write(nfd_root.join("cafe\u{301}.txt"), b"unicode").unwrap();
        let local_err = canonicalize_tree(&nfd_root).unwrap_err();
        assert!(
            local_err.to_string().contains("NFC/UTF-8")
                && local_err.to_string().contains("cafe\u{301}.txt"),
            "the local walk must refuse the decomposed name and name it, got: {local_err}"
        );
        let nfd_out = run_remote_script_raw(&nfd_root);
        assert!(
            !nfd_out.status.success(),
            "the wire script must refuse the decomposed name far-side, got success with stdout {:?}",
            String::from_utf8_lossy(&nfd_out.stdout)
        );
        let nfd_stderr = String::from_utf8_lossy(&nfd_out.stderr);
        assert!(
            nfd_stderr.contains("not NFC-normalized") && nfd_stderr.contains("nfd"),
            "the far-side refusal must name the NFC rule and the entry, got: {nfd_stderr}"
        );
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
        skip_without_perl!("newline_and_tab_filenames_rejected_by_both_canonicalizers");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a\nb"), b"content").unwrap();
        let local_err = canonicalize_tree(&root).unwrap_err();
        assert!(
            local_err.to_string().contains("newline (LF)"),
            "local canonicalizer must reject the newline filename, got: {local_err}"
        );

        let root2 = dir.path().join("tree2");
        std::fs::create_dir_all(&root2).unwrap();
        std::fs::write(root2.join("a\tb"), b"content").unwrap();
        let local_err2 = canonicalize_tree(&root2).unwrap_err();
        assert!(
            local_err2.to_string().contains("tab"),
            "local canonicalizer must reject the tab filename, got: {local_err2}"
        );

        // Remote path: the newline filename mangles the line split and the
        // tab filename mangles the field split — the SCRIPT must fail closed
        // on the raw bytes, because the client decodes stdout lossily and
        // cannot recover a byte the script mangled.
        let out = run_remote_script_raw(&root);
        assert!(
            !out.status.success(),
            "remote script must reject the newline filename, got success with stdout {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
        let out2 = run_remote_script_raw(&root2);
        assert!(
            !out2.status.success(),
            "remote script must reject the tab filename, got success with stdout {:?}",
            String::from_utf8_lossy(&out2.stdout)
        );
        // The assembler also refuses a hand-built tab-mangled line instead of
        // silently truncating the name at the tab.
        let hash = "0".repeat(64);
        assert!(
            canonicalize_remote_entries(&format!("a\tb\tf\t1a4\t1\t{hash}\t\n"), &root2).is_err(),
            "the assembler must refuse a seven-field (tab-mangled) line"
        );
    }

    /// A symlink TARGET containing a tab (a wire separator) is refused by the
    /// LOCAL walk, exactly as a tab-containing NAME is. Pre-fix only the PATH
    /// was checked, so the local walk ACCEPTED this tree and stored the target
    /// verbatim; the far side split the printed line at the tab and the pull
    /// installed a link to `a` instead of `a\tb` while reporting success. This
    /// assertion therefore FAILS against the pre-fix code.
    #[test]
    fn tab_in_symlink_target_rejected_by_local_canonicalizer() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink("a\tb", root.join("l")).unwrap();
        let err = canonicalize_tree(&root).unwrap_err();
        assert!(
            err.to_string().contains("symlink target"),
            "a tab target must be refused with the target rule, got: {err}"
        );
        assert!(
            err.to_string().contains("tab"),
            "the target refusal must name the separator rule, got: {err}"
        );
        assert!(
            err.to_string().contains("entry l"),
            "the target refusal must name the offending entry, got: {err}"
        );
    }

    /// A symlink TARGET that is not valid UTF-8 is refused by the LOCAL walk,
    /// never lossily stored. Pre-fix the walk wrote the `U+FFFD` replacement
    /// (and hashed the raw bytes), so the destination link pointed at a
    /// DIFFERENT path than the source and only post-transfer verification
    /// caught it — after the destination had already been mutated. This
    /// assertion therefore FAILS against the pre-fix code. macOS and Linux both
    /// allow a non-UTF-8 symlink target (unlike a non-UTF-8 name).
    #[cfg(unix)]
    #[test]
    fn non_utf8_symlink_target_rejected_by_local_canonicalizer() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(OsStr::from_bytes(b"caf\xe9"), root.join("l")).unwrap();
        let err = canonicalize_tree(&root).unwrap_err();
        assert!(
            err.to_string().contains("not valid UTF-8"),
            "a non-UTF-8 target must be refused with the UTF-8 rule, got: {err}"
        );
        assert!(
            err.to_string().contains("entry l"),
            "the refusal must name the offending entry, got: {err}"
        );
    }

    /// The far-side SCRIPT refuses a tab-containing symlink TARGET before
    /// printing, so the client's `!out.success()` path turns it into an error
    /// instead of splitting the target at the tab and assembling a shorter one.
    /// Pre-fix the script exited 0 and printed `...<hash>\ta\tb`, which the
    /// assembler read as target `a` — this assertion FAILS against it.
    #[test]
    fn wire_script_refuses_tab_in_symlink_target() {
        skip_without_perl!("wire_script_refuses_tab_in_symlink_target");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink("a\tb", root.join("l")).unwrap();
        let out = run_remote_script_raw(&root);
        assert!(
            !out.status.success(),
            "the wire script must refuse a tab target far-side, got success with stdout {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("symlink target") && stderr.contains("tab"),
            "the far-side refusal must name the target and the separator rule, got: {stderr}"
        );
    }

    /// The far-side SCRIPT refuses a non-UTF-8 symlink TARGET before printing
    /// (a lossy `U+FFFD` target would install a link to a different path).
    /// Pre-fix the script exited 0 and the assembler accepted the `U+FFFD`
    /// spelling — this assertion FAILS against it.
    #[cfg(unix)]
    #[test]
    fn wire_script_refuses_non_utf8_symlink_target() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        skip_without_perl!("wire_script_refuses_non_utf8_symlink_target");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(OsStr::from_bytes(b"caf\xe9"), root.join("l")).unwrap();
        let out = run_remote_script_raw(&root);
        assert!(
            !out.status.success(),
            "the wire script must refuse a non-UTF-8 target far-side, got success with stdout {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("symlink target") && stderr.contains("not valid UTF-8"),
            "the far-side refusal must name the target and the UTF-8 rule, got: {stderr}"
        );
    }

    /// The WIRE path refuses a non-UTF-8 NAME where the raw bytes are still
    /// visible. The client decodes the script's stdout with
    /// `String::from_utf8_lossy`, so the assembler only ever sees `U+FFFD` and
    /// cannot tell a real replacement character from a lossy one; the script
    /// `die`s on the raw name instead, and the client's non-zero-exit check
    /// surfaces it as an error naming the far side rather than an empty or
    /// partial manifest. Linux-only: APFS refuses to create such a name
    /// (`EILSEQ`), so the test SKIPS with a visible reason when creation fails.
    /// Pre-fix the script exited 0 (the name arrived as `U+FFFD`) — this
    /// assertion FAILS against it.
    #[cfg(unix)]
    #[test]
    fn wire_script_refuses_non_utf8_entry_name() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        skip_without_perl!("wire_script_refuses_non_utf8_entry_name");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        if let Err(e) = std::fs::write(root.join(OsStr::from_bytes(b"bad\xffname")), b"content") {
            eprintln!(
                "skipping wire_script_refuses_non_utf8_entry_name: this filesystem cannot \
                 store a non-UTF-8 name ({e})"
            );
            return;
        }
        let out = run_remote_script_raw(&root);
        assert!(
            !out.status.success(),
            "the wire script must refuse a non-UTF-8 name far-side, got success with stdout {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("not valid UTF-8"),
            "the far-side refusal must name the UTF-8 rule, got: {stderr}"
        );
        // The message names the FAR SIDE (the remote directory), which is what
        // the client's error wraps: `remote_manifest` refuses on the non-zero
        // exit and surfaces `out.stderr` instead of assembling a partial or
        // empty manifest from the lossy stdout.
        assert!(
            stderr.contains(root.to_string_lossy().as_ref()),
            "the far-side refusal must name the remote directory, got: {stderr}"
        );
        // Why the check must live far-side: a `U+FFFD` name is valid UTF-8 and
        // NFC, so the assembler alone ACCEPTS the lossy spelling. There is no
        // downstream test that could catch the byte the transport destroyed.
        let hash = "0".repeat(64);
        assert!(
            canonicalize_remote_entries(&format!("bad\u{fffd}name\tf\t1a4\t1\t{hash}\t\n"), &root)
                .is_ok(),
            "premise: a U+FFFD spelling is structurally acceptable, so the assembler cannot \
             detect the transport loss"
        );
    }

    /// PARITY: the two canonicalizers accept EXACTLY the same trees. For every
    /// tree the LOCAL walk refuses on a name/target rule, the WIRE path (the
    /// real perl script, whose raw-byte checks are the only ones that can see a
    /// tab or a non-UTF-8 byte) must also refuse. This is the test that catches
    /// a divergence of the round-17 class: before the far-side check a
    /// non-UTF-8 name was refused locally but accepted (as `U+FFFD`) over the
    /// wire. Pre-fix the local walk ACCEPTED the tab and non-UTF-8 TARGET cases
    /// and the script exited 0 for the tab NAME case, so this test FAILS
    /// against the pre-fix code in every case it can construct on the host.
    #[cfg(unix)]
    #[test]
    fn canonicalizers_agree_on_unrepresentable_names_and_targets() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        skip_without_perl!("canonicalizers_agree_on_unrepresentable_names_and_targets");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let hash = "0".repeat(64);

        // (1) A tab inside a NAME: refused locally and far-side.
        let root = dir.path().join("tab_name");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a\tb"), b"content").unwrap();
        assert!(
            canonicalize_tree(&root).is_err(),
            "local walk must refuse a tab name"
        );
        assert!(
            !run_remote_script_raw(&root).status.success(),
            "wire path must refuse a tab name"
        );

        // (2) A tab inside a symlink TARGET: refused locally and far-side.
        let root = dir.path().join("tab_target");
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink("a\tb", root.join("l")).unwrap();
        assert!(
            canonicalize_tree(&root).is_err(),
            "local walk must refuse a tab symlink target"
        );
        assert!(
            !run_remote_script_raw(&root).status.success(),
            "wire path must refuse a tab symlink target"
        );

        // (3) A non-UTF-8 symlink TARGET: macOS and Linux both allow one.
        let root = dir.path().join("non_utf8_target");
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(OsStr::from_bytes(b"caf\xe9"), root.join("l")).unwrap();
        assert!(
            canonicalize_tree(&root).is_err(),
            "local walk must refuse a non-UTF-8 symlink target"
        );
        assert!(
            !run_remote_script_raw(&root).status.success(),
            "wire path must refuse a non-UTF-8 symlink target"
        );

        // (4) A non-UTF-8 NAME: Linux-only (APFS refuses to create one); the
        //     case is SKIPPED with a visible reason elsewhere.
        let root = dir.path().join("non_utf8_name");
        std::fs::create_dir_all(&root).unwrap();
        match std::fs::write(root.join(OsStr::from_bytes(b"bad\xffname")), b"content") {
            Ok(()) => {
                assert!(
                    canonicalize_tree(&root).is_err(),
                    "local walk must refuse a non-UTF-8 name"
                );
                assert!(
                    !run_remote_script_raw(&root).status.success(),
                    "wire path must refuse a non-UTF-8 name"
                );
            }
            Err(e) => eprintln!(
                "canonicalizers_agree_on_unrepresentable_names_and_targets: skipped case (4), \
                 this filesystem cannot store a non-UTF-8 name ({e})"
            ),
        }

        // The assembler refuses a hand-built seven-field line (a tab inside a
        // name or target) rather than truncating the field, so it cannot be
        // fooled by a proxied line either.
        assert!(
            canonicalize_remote_entries(&format!("a\tb\tf\t1a4\t1\t{hash}\t\n"), &root).is_err(),
            "assembler must refuse a tab-mangled name line"
        );
        assert!(
            canonicalize_remote_entries(&format!("l\tl\t1ff\t1\t{hash}\ta\tb\n"), &root).is_err(),
            "assembler must refuse a tab-mangled target line"
        );
    }

    /// The refusal rules must not reject LEGAL targets: a `..`-containing
    /// in-root target and a decomposed non-ASCII target still round-trip
    /// faithfully through BOTH canonicalizers, byte-for-byte (no NFC
    /// rewriting of the target DATA — only names are NFC-constrained).
    #[test]
    fn legitimate_symlink_targets_round_trip_through_both_canonicalizers() {
        skip_without_perl!("legitimate_symlink_targets_round_trip_through_both_canonicalizers");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("file.txt"), b"content").unwrap();
        // A `..`-containing target that stays inside the root under the
        // canonicalizer's ROOT-relative rule.
        std::os::unix::fs::symlink("sub/../file.txt", root.join("up")).unwrap();
        // A target spelled in a decomposed form: it is link DATA, not a name,
        // so it is accepted VERBATIM (never normalized into a different path).
        std::os::unix::fs::symlink("cafe\u{301}.txt", root.join("nfd_target")).unwrap();

        let local = canonicalize_tree(&root).unwrap();
        let up = local.entries.iter().find(|e| e.path == "up").unwrap();
        assert_eq!(
            up.symlink_target.as_deref(),
            Some("sub/../file.txt"),
            "a `..` in-root target must be stored verbatim"
        );
        let nfd = local
            .entries
            .iter()
            .find(|e| e.path == "nfd_target")
            .unwrap();
        assert_eq!(
            nfd.symlink_target.as_deref(),
            Some("cafe\u{301}.txt"),
            "a decomposed target is DATA and must be stored verbatim, never NFC-normalized"
        );

        let out = run_remote_script(&root);
        let remote = canonicalize_remote_entries(&out, &root).unwrap();
        assert_eq!(
            remote.entries, local.entries,
            "both canonicalizers must store the same target bytes"
        );
        assert_eq!(remote.tree_sha256, local.tree_sha256);
    }

    /// A symlink target ending in CR is refused by the LOCAL walk. CR is not a
    /// wire separator, so pre-fix the walk stored `x\r` verbatim (hash
    /// `896dfdac…`), while the far side printed `…\tx\r\n` and the assembler's
    /// `output.lines()` stripped the CR and re-hashed `x` (`2d711642…`): two
    /// DIFFERENT manifests for one tree, falsifying the "both canonicalizers
    /// accept exactly the same trees" invariant, and an end-to-end sync that
    /// reported `Ok`/`skipped` while the destination still held `x\r`. This
    /// assertion FAILS against the pre-fix code (`unwrap_err` on `Ok`).
    #[test]
    fn trailing_cr_symlink_target_rejected_by_local_canonicalizer() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink("x\r", root.join("l")).unwrap();
        let err = canonicalize_tree(&root).unwrap_err();
        assert!(
            err.to_string().contains("symlink target"),
            "a CR target must be refused with the target rule, got: {err}"
        );
        assert!(
            err.to_string().contains("carriage return"),
            "the target refusal must name the CR rule, got: {err}"
        );
        assert!(
            err.to_string().contains("entry l"),
            "the target refusal must name the offending entry, got: {err}"
        );
    }

    /// The far-side script refuses a CR-containing symlink TARGET on the RAW
    /// bytes, before printing a line that a CRLF-folding reader would misread.
    /// Pre-fix the script exited 0 and the client assembled `x` (the CR
    /// already folded away) — this assertion FAILS against it.
    #[test]
    fn wire_script_refuses_cr_in_symlink_target() {
        skip_without_perl!("wire_script_refuses_cr_in_symlink_target");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink("x\r", root.join("l")).unwrap();
        let out = run_remote_script_raw(&root);
        assert!(
            !out.status.success(),
            "the wire script must refuse a CR target far-side, got success with stdout {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("symlink target") && stderr.contains("carriage return"),
            "the far-side refusal must name the target and the CR rule, got: {stderr}"
        );
    }

    /// A NAME containing CR — interior OR trailing — is refused by BOTH
    /// canonicalizers. A trailing CR in a name is not folded by a tab-splitting
    /// reader (the name is not the last field), but the wire format has ONE
    /// refused set: any NUL/LF/CR/TAB in a name is refused everywhere so no
    /// reader can depend on field position. Pre-fix both canonicalizers
    /// ACCEPTED these names — this assertion FAILS against the pre-fix code.
    #[test]
    fn cr_in_entry_name_rejected_by_both_canonicalizers() {
        skip_without_perl!("cr_in_entry_name_rejected_by_both_canonicalizers");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        for (sub, name) in [("interior", "x\ry"), ("trailing", "x\r")] {
            let root = dir.path().join(sub);
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(root.join(name), b"content").unwrap();
            let local_err = canonicalize_tree(&root).unwrap_err();
            assert!(
                local_err.to_string().contains("carriage return"),
                "the local walk must refuse the {sub} CR name with the CR rule, got: {local_err}"
            );
            let out = run_remote_script_raw(&root);
            assert!(
                !out.status.success(),
                "the wire script must refuse the {sub} CR name, got success with stdout {:?}",
                String::from_utf8_lossy(&out.stdout)
            );
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains("carriage return"),
                "the far-side refusal must name the CR rule for the {sub} CR name, got: {stderr}"
            );
        }
    }

    /// The ASSEMBLER cannot see a CR that `str::lines()` already folded (the
    /// fold happens before any validator runs), so the local/far-side checks
    /// alone do not protect a hand-built or proxied line. Three assertions
    /// close that class:
    /// (1) a line ending in a bare CR is refused rather than folded;
    /// (2) a dir line whose CR-only target `lines()` would fold is refused;
    /// (3) a symlink whose hash disagrees with the target that crossed the
    ///     wire is refused instead of re-hashing the (possibly truncated)
    ///     target — the exact recomputation that made the defect invisible.
    /// The mismatch case specifically FAILS against the pre-fix assembler,
    /// which recomputed `sha256("x")` and accepted.
    #[test]
    fn assembler_refuses_bare_cr_and_mismatched_symlink_hash() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        let hash = "0".repeat(64);

        // (1) The exact reproduction line: stdout `L\tl\t1ff\t1\t<hash>\tx\r\n`.
        // Pre-fix `lines()` folded the CR and accepted target `x`.
        let cr_target_hash = crate::digest::sha256_bytes(b"x\r");
        let raw = format!("L\tl\t1ff\t1\t{cr_target_hash}\tx\r\n");
        let err = canonicalize_remote_entries(&raw, &root).unwrap_err();
        assert!(
            err.to_string().contains("carriage return"),
            "a bare CR before the line terminator must be refused, got: {err}"
        );

        // (2) A dir line with a CR-only final field: pre-fix `lines()` folded
        // the CR and the dir was accepted (the target is ignored for dirs).
        let dir_line = "d\td\t1ed\t1\t\t\r\n";
        assert!(
            canonicalize_remote_entries(dir_line, &root).is_err(),
            "a dir line whose final field is a bare CR must be refused"
        );

        // (3) The far side hashed `x\r` but the line carries target `x`: the
        // assembler must NOT recompute the hash over `x` and call it equal.
        // Pre-fix it recomputed (`sha256("x")`), stored the recomputed hash,
        // and accepted the divergent line.
        let mismatch = format!("L\tl\t1ff\t1\t{cr_target_hash}\tx\n");
        let err = canonicalize_remote_entries(&mismatch, &root).unwrap_err();
        assert!(
            err.to_string().contains("symlink target hash mismatch"),
            "a script hash that disagrees with the wire target must be refused, got: {err}"
        );
        assert!(
            err.to_string().contains("L"),
            "the mismatch refusal must name the entry, got: {err}"
        );

        // A short (five-field) line is refused rather than defaulting the
        // missing field, so a CR hiding in a line-final hash cannot be folded
        // away either.
        assert!(
            canonicalize_remote_entries(&format!("f.txt\tf\t1a4\t1\t{hash}"), &root).is_err(),
            "a five-field line must be refused, not defaulted"
        );
    }

    /// PARITY over the ONE refused set: for every [`WIRE_UNREPRESENTABLE_CHARS`]
    /// character the local walk and the wire path agree. NUL cannot appear in
    /// an on-disk name or target (POSIX names and link targets are C strings),
    /// so it is checked through the shared validators and a hand-built line;
    /// LF, CR, and TAB are checked end to end on real trees. Pre-fix the local
    /// walk and the script both ACCEPTED CR in names and targets, so the CR
    /// rows FAIL against the pre-fix code.
    #[test]
    fn refused_character_set_agrees_between_local_walk_and_wire() {
        skip_without_perl!("refused_character_set_agrees_between_local_walk_and_wire");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let hash = "0".repeat(64);

        assert_eq!(
            WIRE_UNREPRESENTABLE_CHARS,
            ['\0', '\n', '\r', '\t'],
            "the refused set is exactly NUL/LF/CR/TAB"
        );
        assert!(validate_entry_path("a\0b").is_err());
        assert!(validate_symlink_target("l", "a\0b").is_err());

        // NUL cannot be materialized on the host, so exercise the wire path
        // with a hand-built line.
        let nul_root = dir.path().join("nul");
        std::fs::create_dir_all(&nul_root).unwrap();
        assert!(
            canonicalize_remote_entries(&format!("a\0b\tf\t1a4\t1\t{hash}\t\n"), &nul_root)
                .is_err(),
            "the assembler must refuse a NUL name"
        );

        for (c, label) in [('\n', "lf"), ('\r', "cr"), ('\t', "tab")] {
            // A NAME containing `c`, in the interior and trailing positions.
            for (pos, name) in [
                ("interior", format!("x{c}y")),
                ("trailing", format!("x{c}")),
            ] {
                let root = dir.path().join(format!("name_{label}_{pos}"));
                std::fs::create_dir_all(&root).unwrap();
                std::fs::write(root.join(&name), b"content").unwrap();
                assert!(
                    canonicalize_tree(&root).is_err(),
                    "local walk must refuse the {pos} {c:?} name"
                );
                assert!(
                    !run_remote_script_raw(&root).status.success(),
                    "wire path must refuse the {pos} {c:?} name"
                );
            }
            // A symlink TARGET containing `c`, interior and trailing.
            for (pos, target) in [
                ("interior", format!("x{c}y")),
                ("trailing", format!("x{c}")),
            ] {
                let root = dir.path().join(format!("target_{label}_{pos}"));
                std::fs::create_dir_all(&root).unwrap();
                std::os::unix::fs::symlink(&target, root.join("l")).unwrap();
                assert!(
                    canonicalize_tree(&root).is_err(),
                    "local walk must refuse the {pos} {c:?} target"
                );
                assert!(
                    !run_remote_script_raw(&root).status.success(),
                    "wire path must refuse the {pos} {c:?} target"
                );
            }
        }
    }

    /// Non-regression: a legitimate target containing a SPACE still round-trips
    /// byte-for-byte through BOTH canonicalizers (the shared refused set must
    /// not reject legal link data). This guards the new refusal rules against
    /// over-reach.
    #[test]
    fn space_in_symlink_target_round_trips_through_both_canonicalizers() {
        skip_without_perl!("space_in_symlink_target_round_trips_through_both_canonicalizers");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("file with space.txt"), b"content").unwrap();
        std::os::unix::fs::symlink("file with space.txt", root.join("l")).unwrap();

        let local = canonicalize_tree(&root).unwrap();
        let link = local.entries.iter().find(|e| e.path == "l").unwrap();
        assert_eq!(
            link.symlink_target.as_deref(),
            Some("file with space.txt"),
            "a space in a target is legal link DATA and must be stored verbatim"
        );
        let remote = canonicalize_remote_entries(&run_remote_script(&root), &root).unwrap();
        assert_eq!(remote.entries, local.entries);
        assert_eq!(remote.tree_sha256, local.tree_sha256);
    }

    /// An already-NFC non-ASCII NAME still round-trips unchanged through BOTH
    /// canonicalizers: the far-side NFC check must accept it, not reject it.
    /// (This is the non-regression complement of the far-side refusal tests.)
    #[test]
    fn already_nfc_non_ascii_name_round_trips_through_both_canonicalizers() {
        skip_without_perl!("already_nfc_non_ascii_name_round_trips_through_both_canonicalizers");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("caf\u{e9}.txt"), b"unicode").unwrap();
        let local = canonicalize_tree(&root).unwrap();
        assert_eq!(entry_paths(&local), vec!["caf\u{e9}.txt"]);
        let out = run_remote_script(&root);
        let remote = canonicalize_remote_entries(&out, &root).unwrap();
        assert_eq!(remote.entries, local.entries);
        assert_eq!(remote.tree_sha256, local.tree_sha256);
    }

    /// The remote assembler must reject a malformed content hash (wrong
    /// length, non-hex, or uppercase) with a clear error instead of
    /// silently folding it into the digest — a corrupted or divergent
    /// script output must fail closed loudly.
    #[test]
    fn remote_entries_reject_malformed_content_hash() {
        skip_without_perl!("remote_entries_reject_malformed_content_hash");
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
