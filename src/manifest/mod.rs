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
//! # Symlink targets are link data: UTF-8, wire-clean, and non-escaping
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
//! A target is NOT `separator-free`. It may contain `/` (multi-component, e.g.
//! `sub/target`) and `..`, because it is link DATA the kernel resolves, and a
//! separator or a `..` is not by itself an escape. What the rules forbid is an
//! ABSOLUTE target, and a RELATIVE target whose resolution leaves the tree
//! root — and the resolution base is the directory CONTAINING the link (its own
//! parent), as POSIX specifies, not the tree root. So `dir/link -> ../other`
//! resolves to `<root>/other` and is ACCEPTED, while `dir/link ->
//! ../../outside` resolves outside the root and is REFUSED.
//!
//! # Containment is decided PHYSICALLY, on the TARGET's components
//!
//! The kernel resolves a relative target PHYSICALLY: it walks the SPELLED
//! components in order and `..` moves to the physical parent of whatever it
//! has reached, so a lexical `..`-collapse is faithful ONLY while no component
//! it walks is a symlink. A `..` that follows a symlink component is exactly
//! where the collapse and the kernel disagree: with `dir/sub -> ../other`,
//! `dir/link -> sub/../../outside` collapses to `<root>/outside` (inside,
//! because the first `..` undoes `sub`), while the kernel WALKS THROUGH
//! `dir/sub` to `<root>/../other`, so the next `..` reaches the root's parent
//! and the target leaves the root. The kernel also FOLLOWS the FINAL component,
//! so a target that ends at a symlink can leave the root even when its spelling
//! never pops above it. The rule therefore refuses a relative target as soon as
//! the walk reaches a component (final or intermediate) that is a symlink, and
//! refuses a `..` that pops above the root: the collapse is never trusted past
//! a symlink. This is the crate's fail-closed doctrine — refuse rather than
//! guess where a follow ends.
//!
//! The walk is over root-RELATIVE paths and never builds an absolute base, so
//! it does not depend on the root's spelling, and the LOCAL walk and the
//! far-side wire assembler apply exactly the same rule: the local walk answers
//! "is this component a symlink?" with `symlink_metadata` of the live tree, and
//! the assembler answers it with the `symlink` entries it assembled from the
//! far side. Neither canonicalizes the root, so a root reached through a
//! symlink can no longer make the two verdicts differ.
//!
//! The root-relative walk is also the only rule that keeps containment
//! PORTABLE, which is the property a manifest must have: a target that stays in
//! the root only because the root happens to be NAMED a particular name (e.g.
//! `dir/link -> ../../real/other` when the root is `.../real`) leaves the root
//! as soon as the tree is materialized under any other name. Checking it
//! against the resolved real root would accept a tree whose containment is a
//! coincidence of the root's spelling, so such a target is refused.
//!
//! The earlier version of this section got the argument wrong in a way worth
//! recording: it argued only about the LINK'S PARENT components (which the walk
//! had already verified as real directories) and never about the TARGET's
//! components — the half whose treatment the resolution base had just changed.
//! A safety argument must cover the part of the input whose treatment can
//! change, not the part that was already correct.
//!
//! NFC is deliberately NOT required of a target. A name is an index into the
//! tree, but a target is DATA: the kernel resolves it verbatim, it may contain
//! `..` and `/` separators, and normalizing it would silently repoint the link
//! (and change the hash that binds the link's content). Refusing non-NFC
//! targets would reject
//! legitimate links that merely happen to spell their target in a decomposed
//! form; accepting them verbatim is faithful and keeps both canonicalizers in
//! agreement. Only the UTF-8 half of the NAME rule is applied to targets; the
//! NFC half is not.
//!
//! # Fidelity scope: what a sync carries, and what it silently does not
//!
//! A sync transports THIS manifest plus the file bytes, and the manifest
//! model is exactly the fields of [`TreeEntry`] — so fidelity is bounded by
//! them. This section is the crate's authoritative statement of scope: every
//! item under "carried" was verified end to end, and every item under "not
//! carried" is a deliberate, currently-unimplemented limitation rather than
//! a guarantee. A caller must be able to read this and predict the result
//! without experimenting.
//!
//! **CARRIED faithfully:** the entry's path name (NFC UTF-8, `/`-separated;
//! see above), its kind (file, directory, or symlink), its mode INCLUDING
//! the setuid/setgid/sticky bits (stored as the full octal mode and applied
//! with an explicit `chmod`, so a permissive umask cannot narrow it), the
//! file's content (the SHA-256-bound bytes), and a symlink's target (the raw
//! target bytes).
//!
//! **NOT carried — silently dropped.** The manifest has no field for any of
//! these, so a sync neither reproduces nor REPORTS them:
//!
//! * **ownership** (`uid`/`gid`) — a destination entry ends up owned by the
//!   transferring account;
//! * **extended attributes** — Linux `user.*` and `security.*` (including
//!   `security.capability`) and macOS `com.apple.*` (resource forks,
//!   `com.apple.FinderInfo`);
//! * **POSIX access and default ACLs**;
//! * **timestamps** (`mtime`/`atime`);
//! * **file flags** (`chattr +i`, `chflags uchg`);
//! * **sparseness** — a sparse file is written out fully allocated;
//! * **memory** — a sync reads each file WHOLE: the local canonicalizer
//!   ([`canonicalize_tree`]'s `std::fs::read`) and the far-side perl
//!   manifest script both slurp the entire file in one allocation, so peak
//!   resident memory is proportional to the LARGEST SINGLE FILE, not to the
//!   tree's total size. This is a PER-FILE bound, not a total-tree bound,
//!   and no streaming path exists. (Measured: a 512 MiB file → ~515 MiB RSS;
//!   a 2 GiB file → ~2.00 GiB RSS.)
//!
//! The loss of xattrs, `security.capability`, and ACLs is INVISIBLE TO THE
//! DIFFER: a second sync compares only the manifest model, sees the entry as
//! already `Same`, and reports success, so only xattr/ACL-aware tooling on
//! the destination can reveal the divergence.
//!
//! **NOT carried — REFUSED, not dropped:** a hard link (an entry with
//! `nlink > 1`) is rejected by BOTH canonicalizers — the local walk and the
//! remote wire assembler — with an error naming the entry, rather than being
//! silently materialized as two independent copies. Refusal is the crate's
//! doctrine for anything it cannot reproduce faithfully (the name and
//! symlink-target rules above follow the same principle): a silent
//! transformation that changes what the tree means is worse than a loud
//! failure.
//!
//! **Push and pull now mutate a destination the SAME way.** Both publish a
//! written file by ATOMIC RENAME into place (a NEW inode), so the replaced
//! file's pre-existing xattrs and owner are destroyed with the old inode in
//! BOTH directions. (Before a push was made atomic, a push overwrote the
//! bytes IN PLACE — the SSH transport's `cat >`, the local transport's
//! `O_TRUNC` create — and kept the old inode; that asymmetry, and the torn
//! destination a failed in-place push could leave, are gone.)
//!
//! **The manifest carries no TIMESTAMPS.** `TreeEntry` has no `mtime`/`atime`
//! field, so a caller that wants "the newest N snapshots" MUST derive the
//! order from the snapshot id's LEXICAL order (or keep its own timestamp
//! record): the manifest (and therefore the differ) cannot rank two entries
//! by time, and two snapshots whose only difference is a modification time
//! compare `Same`.
//!
//! # Durability and atomicity of a written entry
//!
//! The write discipline is chosen by the DESTINATION, never by the direction.
//! This is the statement a caller should read before relying on either:
//!
//! * **LOCAL destination** — a PULL's local root, OR a PUSH whose transport
//!   declares `is_local() == true` ([`crate::transport::LocalTransport`]):
//!   the entry is written by the crate's durable atomic replace
//!   ([`crate::atomic::write_atomic_replace_fd`]). A UNIQUE temp is created in
//!   the destination's own directory, chmodded private, `fsync`ed, then
//!   `renameat` into place (COMMIT POINT 1 — the new content becomes VISIBLE),
//!   then the PARENT DIRECTORY is `fsync`ed (COMMIT POINT 2 — the rename
//!   becomes DURABLE). A failure BEFORE the rename is an `Err` that leaves the
//!   PREVIOUS content wholly in place and unlinks the temp; a failure of the
//!   parent fsync AFTER the rename is
//!   [`crate::atomic::ReplaceOutcome::ReplacedDurabilityUnknown`] — the new
//!   content is VISIBLE but its durability is unconfirmed — NEVER a bare
//!   `Err` (a bare `Err` would falsely claim the rename never happened).
//! * **REMOTE destination** ([`crate::transport::SshTransport`]): the SAME
//!   protocol on the far side, in one POSIX shell command: a `mktemp` temp in
//!   the destination's own directory, the payload on STDIN into it, the final
//!   mode, a portable perl `fsync(2)` of the temp, a perl `rename(2)` INTO
//!   PLACE (overwriting the final entry atomically, never following a symlink),
//!   then a perl `fsync(2)` of the parent directory. Every operand is
//!   single-quoted, `--` precedes a value that may start with `-`, the parent
//!   is computed on this host (never by a far-side `dirname`), and the payload
//!   is never embedded in the command string. GNU and BSD userlands are both
//!   exercised by the far-side suites. A failure before the rename leaves the
//!   PREVIOUS content in place and removes the temp.
//! * **WINDOWS local destination**: the PATH-BASED replace
//!   ([`crate::atomic::write_atomic_replace`]): a temp + rename with NO
//!   parent-directory fsync and a NON-atomic replace (Windows `rename` does
//!   not overwrite an existing target, so the target is removed first and a
//!   reader can observe a transient absence). This is the ONE destination kind
//!   that cannot be made atomic and durable here; the Windows port
//!   type-checks but is NOT exercised, so treat it as unverified.
//!
//! `EntryPolicy::AppendTail` adds a COMPARE before an append's write: the write
//! happens only if the destination still holds the bytes the append read, so a
//! concurrent modification becomes a REPORTED conflict rather than a silent
//! overwrite (see [`crate::sync`] for what the compare can and cannot cover).
//!
//! A caller that needs `security.capability`, ACLs, ownership, or timestamps
//! preserved must apply them out of band after the sync.

use crate::digest::sha256_bytes;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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

/// Why a RELATIVE symlink target is refused.
///
/// The kernel resolves a relative target PHYSICALLY: it walks the SPELLED
/// components in order from the directory containing the link, and `..` moves
/// to the physical parent of whatever it has reached. A lexical `..`-collapse
/// equals that walk ONLY while no component it walks is a symlink, so the
/// decision is made on the spelled components, in order, not on the collapsed
/// path. The kernel also follows the FINAL component, so a target that ends at
/// a symlink can leave the root even when its spelling does not.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SymlinkTargetRefusal {
    /// The spelled target pops above the tree root.
    EscapesRoot,
    /// A component the walk reaches (final or intermediate) is a symlink the
    /// kernel would follow, so the spelled location is not the physical one.
    ThroughSymlink(PathBuf),
}

/// Decide whether a RELATIVE symlink target may be accepted, using the SAME
/// rule at BOTH call sites: the local walk and the far-side wire assembler.
///
/// `link_rel` is the link's path relative to the tree root (e.g. `dir/link`),
/// and `target` is its raw relative link target. The walk starts at the link's
/// CONTAINING directory, per POSIX. Every component it reaches is checked:
/// a `..` pops one component and refuses if it would pop above the root, and a
/// `Component::Normal` that names a symlink is refused, because the kernel
/// follows it and the physical location is then not the spelled one.
///
/// `is_symlink` answers, for a ROOT-RELATIVE spelling, whether that path names
/// a symlink in the tree. Both call sites work in root-RELATIVE paths, so
/// neither depends on the root's spelling and the two cannot disagree: the
/// local walk answers with `symlink_metadata` of the live tree, and the wire
/// assembler answers with the set of `symlink` entries it assembled. (The
/// previous rule built an ABSOLUTE base from the root and collapsed the target
/// lexically; that made the local walk canonicalize the root while the
/// assembler could not, so a symlinked root made the two disagree, and the
/// collapse itself never followed a symlink component.)
fn check_relative_symlink_target(
    link_rel: &Path,
    target: &Path,
    is_symlink: &mut dyn FnMut(&Path) -> bool,
) -> std::result::Result<(), SymlinkTargetRefusal> {
    let mut current = PathBuf::new();
    if let Some(parent) = link_rel.parent() {
        for comp in parent.components() {
            match comp {
                Component::Normal(name) => current.push(name),
                Component::CurDir => {}
                // A validated entry path has only `Normal` components; fail
                // closed rather than reason about a spelling that cannot occur.
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(SymlinkTargetRefusal::EscapesRoot);
                }
            }
        }
    }
    for comp in target.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => {
                return Err(SymlinkTargetRefusal::EscapesRoot);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !current.pop() {
                    return Err(SymlinkTargetRefusal::EscapesRoot);
                }
            }
            Component::Normal(name) => {
                current.push(name);
                if is_symlink(&current) {
                    return Err(SymlinkTargetRefusal::ThroughSymlink(current.clone()));
                }
            }
        }
    }
    Ok(())
}

/// The refusal message for [`SymlinkTargetRefusal`], naming the offending
/// entry and the symlink component the walk reached (when there is one). The
/// `escaping symlink` prefix is the crate's single classification for a
/// relative target that cannot be shown to stay inside the root.
fn symlink_target_refusal_message(
    refusal: SymlinkTargetRefusal,
    link_display: &str,
    target: &str,
) -> String {
    match refusal {
        SymlinkTargetRefusal::EscapesRoot => {
            format!("escaping symlink not allowed: {link_display}")
        }
        SymlinkTargetRefusal::ThroughSymlink(component) => format!(
            "escaping symlink not allowed: {link_display} (target {target:?} resolves through the symlink component {component:?}, which the kernel follows, so a lexical `..` after it is not the kernel's resolution)"
        ),
    }
}

/// Join a root-relative path of `Component::Normal` names with `/`, the
/// manifest's canonical spelling. Used to look a candidate component up in the
/// wire assembler's set of `symlink` entries.
fn rel_path_string(rel: &Path) -> String {
    let mut out = String::new();
    for comp in rel.components() {
        if let Component::Normal(name) = comp {
            if !out.is_empty() {
                out.push('/');
            }
            out.push_str(&name.to_string_lossy());
        }
    }
    out
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
    // NAME_MAX is asserted in prose (see [`crate::atomic::NAME_MAX`]) AND
    // enforced here, at the wire/local boundary: a component longer than any
    // filesystem entry could hold is refused with a clear materialization
    // error instead of being accepted here and then refused by the store with
    // `ENAMETOOLONG` (B5).
    if let Some(component) = path
        .split('/')
        .find(|component| component.len() > crate::atomic::NAME_MAX)
    {
        return Err(Error::materialization(format!(
            "path component exceeds the {}-byte filesystem name bound: {component:?} ({} bytes) in {path}",
            crate::atomic::NAME_MAX,
            component.len()
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
///
/// COST: this READS AND HASHES EVERY FILE IN THE TREE, so a snapshot's cost is
/// O(bytes scanned), NOT O(bytes changed). Content addressing makes the STORE
/// deduplicated, but there is no dirty tracking and no reuse of a previously
/// computed manifest, so a periodic checkpoint that changes one 4-byte file in
/// a 350 MB tree still pays the full scan: measured 1.327 s before -> 1.384 s
/// after (macOS), 2.739 s -> 2.690 s (Linux). This is a design cost of the
/// manifest-and-hash model; reusing a caller-supplied previous manifest would
/// remove it but is not implemented.
pub fn canonicalize_tree(root: &Path) -> Result<TreeMetadata> {
    Ok(canonicalize_tree_with(root, UnsupportedPolicy::Refuse)?.meta)
}

/// One DESTINATION entry that the manifest model can carry as PRESENT but that
/// the strict address-fidelity rules refuse to ACCEPT as a faithful member of
/// the tree: an absolute or escaping symlink, or a hard link. It is returned
/// alongside the manifest by [`canonicalize_tree_destination`] (and
/// [`canonicalize_remote_entries_destination`]) so the sync can classify the
/// entry as destination-only and let a caller-sanctioned
/// [`crate::sync::Extraneous::Delete`] remove it, instead of failing the whole
/// run at destination-manifest time.
///
/// The entry ITSELF is present in the returned manifest, with its live kind
/// and (where it has one) its faithfully hashed content/target — so the diff
/// sees it, the report names it, and the removal walk addresses it under the
/// spelling and kind it really has. Only the [`reason`](Self::reason) records
/// why the strict rules would have refused it. This is NOT a licence to
/// transfer such an entry: the sync REFUSES to write a source entry over a
/// path an `UnsupportedEntry` names (see `crate::sync::apply`), so an
/// unsupported destination entry can be deleted under a sanction, never
/// silently overwritten, aliased, or moved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsupportedEntry {
    /// The manifest spelling of the entry, exactly as it appears in the
    /// returned manifest.
    pub path: String,
    /// The strict rule's refusal message (e.g. `absolute symlink not allowed:
    /// <path>`), preserved verbatim so a caller sees the same reason the
    /// strict canonicalizer would have reported.
    pub reason: String,
}

/// The result of canonicalizing a DESTINATION tree: the manifest plus the
/// entries the strict rules would have refused.
///
/// `meta` is a DESTINATION OBSERVATION, not a canonical tree object: an entry
/// named in `unsupported` may not be one the strict canonicalizer would emit
/// (its symlink target may be absolute, or it may be a hard link recorded as
/// an ordinary file). Never serialize it as a `tree.json`, never feed it to
/// [`verify_tree_metadata`], and never use it as a SOURCE manifest — the
/// source side must stay strict, so a tree this crate cannot represent
/// faithfully is a loud failure rather than a silent transformation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationTree {
    pub meta: TreeMetadata,
    pub unsupported: Vec<UnsupportedEntry>,
}

/// Canonicalize a destination tree, TOLERATING the address-fidelity refusals
/// that a destination may legitimately hold: an absolute symlink, an escaping
/// symlink, and a hard link. Each tolerated entry is recorded in the returned
/// [`DestinationTree::unsupported`] with the strict rule's reason, and the
/// manifest still carries it (under its live kind) so a caller-sanctioned
/// removal can address it.
///
/// Everything ELSE the strict [`canonicalize_tree`] refuses is still refused
/// here, unchanged: an absent or non-directory root, a non-UTF-8 or non-NFC
/// name, a wire-unrepresentable character, an absolute/traversal path, a
/// duplicate, and a special file (FIFO/socket/device). The tolerance is a
/// DESTINATION-ONLY concept: a source manifest is always built with
/// [`canonicalize_tree`], so an unrepresentable SOURCE entry still fails the
/// run.
pub fn canonicalize_tree_destination(root: &Path) -> Result<DestinationTree> {
    canonicalize_tree_with(root, UnsupportedPolicy::Tolerate)
}

/// Whether the shared walk REFUSES an unrepresentable entry (the strict source
/// semantics) or RECORDS it and keeps going (the destination semantics).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UnsupportedPolicy {
    Refuse,
    Tolerate,
}

fn canonicalize_tree_with(root: &Path, policy: UnsupportedPolicy) -> Result<DestinationTree> {
    let mut entries: Vec<TreeEntry> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut unsupported: Vec<UnsupportedEntry> = Vec::new();

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
        // Set when a strict address-fidelity rule refused this entry under
        // `UnsupportedPolicy::Tolerate`; the entry is still recorded (under
        // its live kind) and the reason joins `unsupported`.
        let mut unsupported_reason: Option<String> = None;

        if meta.is_dir() {
            entry_type = "dir";
        } else if meta.is_symlink() {
            entry_type = "symlink";
            let target = std::fs::read_link(path)
                .map_err(|e| Error::materialization(format!("readlink {}: {e}", path.display())))?;
            if target.is_absolute() {
                let reason = format!("absolute symlink not allowed: {}", path.display());
                match policy {
                    UnsupportedPolicy::Refuse => return Err(Error::materialization(reason)),
                    UnsupportedPolicy::Tolerate => unsupported_reason = Some(reason),
                }
            } else {
                // A RELATIVE target is resolved against the directory
                // CONTAINING the link (the link's own parent), per POSIX, not
                // against the tree root: `dir/link -> ../other` lands in
                // `<root>/other`, which is inside the root, and is ACCEPTED.
                // Containment is decided PHYSICALLY, on the target's spelled
                // components: the kernel follows a symlink component (final or
                // intermediate), so a target whose walk reaches one is refused
                // rather than collapsed lexically. `root_c` is the real
                // directory the kernel resolves against, so the `lstat` sees
                // the live tree; the walk itself is root-relative and does not
                // depend on the root's spelling (see
                // [`check_relative_symlink_target`]).
                let mut is_symlink = |rel: &Path| -> bool {
                    std::fs::symlink_metadata(root_c.join(rel))
                        .map(|m| m.is_symlink())
                        .unwrap_or(false)
                };
                if let Err(refusal) =
                    check_relative_symlink_target(rel_os, &target, &mut is_symlink)
                {
                    let reason = symlink_target_refusal_message(
                        refusal,
                        &path.display().to_string(),
                        &target.to_string_lossy(),
                    );
                    match policy {
                        UnsupportedPolicy::Refuse => return Err(Error::materialization(reason)),
                        UnsupportedPolicy::Tolerate => unsupported_reason = Some(reason),
                    }
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
                    let reason = format!("hard links not allowed: {}", path.display());
                    match policy {
                        UnsupportedPolicy::Refuse => return Err(Error::materialization(reason)),
                        UnsupportedPolicy::Tolerate => unsupported_reason = Some(reason),
                    }
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

        if let Some(reason) = unsupported_reason.take() {
            unsupported.push(UnsupportedEntry {
                path: entry_path.clone(),
                reason,
            });
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
    unsupported.sort_by(|a, b| a.path.cmp(&b.path));
    let mut meta = TreeMetadata {
        tree_schema_version: TREE_SCHEMA_VERSION,
        hash_algorithm: "sha256".to_string(),
        tree_sha256: String::new(),
        entries,
    };
    meta.tree_sha256 = compute_tree_digest(&meta);
    Ok(DestinationTree { meta, unsupported })
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
/// with a short or empty listing: an ABSENT root, a root that is not a
/// directory, and any directory the walk cannot open or read each make the
/// script `die` (non-zero exit) so the caller refuses it. The two root
/// refusals carry DISTINCT diagnostics — `absent: <root>` versus `not a
/// directory: <root>` — so the caller can report an absent far side
/// ([`crate::Error::NotFound`], consistent with how the crate reports absence
/// elsewhere) separately from a root that exists but cannot be described.
/// Only a walk that covered the whole tree exits 0, and a root that IS a
/// directory but has no entries (an existing empty directory) prints empty
/// stdout with exit 0 — assembling to the EMPTY manifest it really is.
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
die qq{absent: $root\n} unless defined($root) && -e $root;
die qq{not a directory: $root\n} unless -d $root;
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

/// Require a manifest to be PARENT-CLOSED: every entry path that has a `/`
/// must have an entry for its parent directory, and that parent entry must be
/// a `dir`. Refuse, naming the offending entry, otherwise.
///
/// The wire walk emits a child only after its parent (`$walk` recurses after
/// emitting), but nothing in the manifest FORMAT requires that: a hand-built
/// or proxied line `d/x ...` with no `d` line used to be accepted. The apply
/// layer verifies only the FINAL component of a path, so a parent component's
/// spelling was never checked unless the parent happened to be a source
/// manifest entry: on a case-insensitive destination a crafted `d/x` could be
/// reported as `applied` while the destination held `D/x` (one on-disk entry
/// named under two spellings), and on a case-sensitive one the write's
/// `ensure_private_dir_fd` would IMPLICITLY create `d` — an on-disk entry named
/// by NO report list (and, with `delete_extraneous`, the just-installed entry
/// destroyed by the sanctioned removal of the pre-existing `D`). Requiring
/// closure at assembly makes both consequences unreachable.
///
/// The LOCAL walk is closed by construction: `WalkDir` yields a directory
/// before the entries inside it, so every nested path's parent is already an
/// entry of the same kind. Only the wire assembler needs the explicit gate.
fn require_parent_closed(entries: &[TreeEntry]) -> Result<()> {
    let kinds: BTreeMap<&str, &str> = entries
        .iter()
        .map(|e| (e.path.as_str(), e.entry_type.as_str()))
        .collect();
    for entry in entries {
        let Some((parent, _)) = entry.path.rsplit_once('/') else {
            // A top-level entry's parent is the tree root itself, which is not
            // an entry (the manifest is root-relative).
            continue;
        };
        match kinds.get(parent) {
            None => {
                return Err(Error::materialization(format!(
                    "manifest is not parent-closed: entry {:?} has no entry for its parent directory {:?}; every parent must be listed as a `dir` entry so a parent's spelling is verified instead of being implicitly created",
                    entry.path, parent
                )));
            }
            Some(kind) if *kind != "dir" => {
                return Err(Error::materialization(format!(
                    "manifest has a non-directory parent: entry {:?} is under {:?}, which is a {:?}, not a `dir`",
                    entry.path, parent, kind
                )));
            }
            Some(_) => {}
        }
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
/// tree produces a digest mismatch without any content transfer. A SYMLINK's
/// RELATIVE target is checked with the SAME root-relative walk the local
/// canonicalizer uses, driven by the kinds the far side reported: a component
/// the listing marks `symlink` is refused, exactly as the local walk's
/// `symlink_metadata` refuses it. `root` is accepted for compatibility but the
/// symlink check does NOT consult it: the far side's root cannot be
/// canonicalized from here, and because the walk is root-relative it does not
/// need to be, so the local and wire verdicts agree even when the root is
/// itself reached through a symlink.
///
/// `output` must come from a walk that actually enumerated the whole tree:
/// [`remote_tree_verify_script`] exits non-zero for an absent, non-directory,
/// or unreadable root, and the caller must refuse that exit rather than
/// assemble the short or empty listing. Only a complete walk — including an
/// existing empty directory, whose empty stdout is the empty manifest — may
/// be assembled here.
pub fn canonicalize_remote_entries(output: &str, root: &Path) -> Result<TreeMetadata> {
    Ok(canonicalize_remote_entries_with(output, root, UnsupportedPolicy::Refuse)?.meta)
}

/// The destination-tolerant form of [`canonicalize_remote_entries`]: the same
/// wire validation, but a hard link and an absolute or escaping symlink are
/// RECORDED in [`DestinationTree::unsupported`] (and kept in the manifest
/// under their live kind) instead of failing the whole assembly. A
/// special-file line (`o`) is still refused: the applier's live-kind authority
/// has no primitive for it, so the crate cannot remove it safely.
pub fn canonicalize_remote_entries_destination(
    output: &str,
    root: &Path,
) -> Result<DestinationTree> {
    canonicalize_remote_entries_with(output, root, UnsupportedPolicy::Tolerate)
}

fn canonicalize_remote_entries_with(
    output: &str,
    _root: &Path,
    policy: UnsupportedPolicy,
) -> Result<DestinationTree> {
    let mut entries: Vec<TreeEntry> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut unsupported: Vec<UnsupportedEntry> = Vec::new();
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
                    let reason = format!("hard links not allowed: {entry_path}");
                    match policy {
                        UnsupportedPolicy::Refuse => return Err(Error::materialization(reason)),
                        UnsupportedPolicy::Tolerate => unsupported.push(UnsupportedEntry {
                            path: entry_path.clone(),
                            reason,
                        }),
                    }
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
                if Path::new(&symlink_target).is_absolute() {
                    let reason = format!("absolute symlink not allowed: {entry_path}");
                    match policy {
                        UnsupportedPolicy::Refuse => return Err(Error::materialization(reason)),
                        UnsupportedPolicy::Tolerate => unsupported.push(UnsupportedEntry {
                            path: entry_path.clone(),
                            reason,
                        }),
                    }
                }
                // A RELATIVE target's containment is checked in a POST-PASS,
                // because the rule needs the KIND of every entry the target's
                // spelled walk reaches (a component that is a symlink makes the
                // lexical collapse lie) and a target may name an entry that
                // appears later in the listing. See
                // [`check_relative_symlink_target`].
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
    // The manifest must be parent-closed (see [`require_parent_closed`]); the
    // wire walk emits parents first, so a complete far-side listing already
    // satisfies this, and a hand-built or proxied line that does not is
    // refused rather than implicitly creating an unnamed parent.
    require_parent_closed(&entries)?;
    // The SAME relative-target rule as the local walk, applied with the KINDS
    // the far side reported. The walk is over root-RELATIVE paths, so `root`
    // is deliberately NOT consulted: the far side cannot be canonicalized from
    // here, and neither side needs to, because the rule never builds an
    // absolute base. A component counts as a symlink exactly when the listing
    // says `symlink` at that path — the same fact the local walk's `lstat`
    // reads — so a symlinked root can no longer make the two verdicts differ.
    let symlink_paths: BTreeSet<String> = entries
        .iter()
        .filter(|e| e.entry_type == "symlink")
        .map(|e| e.path.clone())
        .collect();
    for entry in &entries {
        if entry.entry_type != "symlink" {
            continue;
        }
        let Some(target) = entry.symlink_target.as_deref() else {
            continue;
        };
        let target = Path::new(target);
        if target.is_absolute() {
            // Already classified (and tolerated or refused) at the field.
            continue;
        }
        let mut is_symlink = |rel: &Path| -> bool { symlink_paths.contains(&rel_path_string(rel)) };
        if let Err(refusal) =
            check_relative_symlink_target(Path::new(&entry.path), target, &mut is_symlink)
        {
            let reason =
                symlink_target_refusal_message(refusal, &entry.path, &target.to_string_lossy());
            match policy {
                UnsupportedPolicy::Refuse => return Err(Error::materialization(reason)),
                UnsupportedPolicy::Tolerate => unsupported.push(UnsupportedEntry {
                    path: entry.path.clone(),
                    reason,
                }),
            }
        }
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    unsupported.sort_by(|a, b| a.path.cmp(&b.path));
    let mut meta = TreeMetadata {
        tree_schema_version: TREE_SCHEMA_VERSION,
        hash_algorithm: "sha256".to_string(),
        tree_sha256: String::new(),
        entries,
    };
    meta.tree_sha256 = compute_tree_digest(&meta);
    Ok(DestinationTree { meta, unsupported })
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

    /// Announce a SKIPPED test on the REAL console of a PLAIN `cargo test` run.
    ///
    /// libtest CAPTURES `print!`/`eprintln!` per test and DISCARDS the captured
    /// output of a PASSING test, so a skip message written with those macros is
    /// invisible in the default gate: a skipped assertion is then
    /// indistinguishable from a passing one. This writes a single
    /// machine-greppable line DIRECTLY to file descriptor 1 (bypassing libtest's
    /// capture) and names the test with the harness thread's name (libtest
    /// names each test thread after the test). Grep a plain `cargo test` for
    /// `STORE_SYNC_SKIP` to enumerate every skipped test.
    #[cfg(unix)]
    fn announce_skip(reason: &str) {
        let test = std::thread::current()
            .name()
            .unwrap_or("<unknown test>")
            .to_string();
        let line = format!("STORE_SYNC_SKIP test={test} reason={reason}\n");
        unsafe {
            libc::write(1, line.as_ptr().cast::<libc::c_void>(), line.len());
        }
    }

    /// Non-Unix fallback: no raw-fd bypass is needed where the reproductions
    /// that use it are `#[cfg(unix)]`.
    #[cfg(not(unix))]
    fn announce_skip(reason: &str) {
        let test = std::thread::current()
            .name()
            .unwrap_or("<unknown test>")
            .to_string();
        println!("STORE_SYNC_SKIP test={test} reason={reason}");
    }

    /// Skip the current test, with a clear reason, when `perl` is not on
    /// `PATH`. Used at the top of every test that runs the remote script.
    macro_rules! skip_without_perl {
        ($name:literal) => {
            if !perl_on_path() {
                announce_skip("perl is not on PATH, so the remote verification script cannot run");
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
            announce_skip(
                "this process can still enumerate a mode-0o000 directory \
                 (effective uid 0, CAP_DAC_READ_SEARCH, or a mode-ignoring \
                 filesystem?), so the unreadable-subdirectory premise is untestable here",
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

        // B5: the NAME_MAX bound is ENFORCED at the wire/local boundary, not
        // merely asserted in prose. A component at the bound is accepted; one
        // byte over is refused with a clear error (the store would otherwise
        // refuse it later with `ENAMETOOLONG`).
        let at_max = "a".repeat(crate::atomic::NAME_MAX);
        assert_eq!(validate_entry_path(&at_max).unwrap(), at_max);
        let over = "a".repeat(crate::atomic::NAME_MAX + 1);
        let over_err = validate_entry_path(&over).unwrap_err();
        assert!(
            over_err.to_string().contains("filesystem name bound"),
            "an over-long component must be refused with the bound named, got: {over_err}"
        );
        // A DEEP path is fine as long as every COMPONENT is within the bound.
        let deep = format!("{at_max}/{at_max}");
        assert_eq!(validate_entry_path(&deep).unwrap(), deep);
        // A hand-built 1000-byte WIRE component is refused by the assembler.
        let wire = format!("{}\tf\t644\t1\t{}\t\n", "b".repeat(1000), "0".repeat(64));
        assert!(
            canonicalize_remote_entries(&wire, Path::new("/srv/store")).is_err(),
            "a 1000-byte wire component must be refused at assembly"
        );

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

    /// F2 (destination tolerance, LOCAL): the strict canonicalizer still
    /// refuses an absolute/escaping symlink and a hard link, and the
    /// DESTINATION-tolerant form records each in `unsupported` while keeping
    /// it in the manifest under its live kind — the capability a
    /// caller-sanctioned deletion needs.
    #[test]
    fn destination_tolerant_canonicalizer_records_unrepresentable_local_entries() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let links = dir.path().join("links");
        std::fs::create_dir_all(&links).unwrap();
        std::os::unix::fs::symlink("/opt/app/v1", links.join("abs")).unwrap();
        std::os::unix::fs::symlink("../../../etc/passwd", links.join("esc")).unwrap();

        // STRICT SOURCE SEMANTICS ARE UNCHANGED.
        let strict = canonicalize_tree(&links).unwrap_err().to_string();
        assert!(strict.contains("symlink not allowed"), "{strict}");

        let tree = canonicalize_tree_destination(&links).expect("destination tolerates the links");
        let mut recorded: Vec<(String, String)> = tree
            .unsupported
            .iter()
            .map(|u| (u.path.clone(), u.reason.clone()))
            .collect();
        recorded.sort();
        assert_eq!(recorded.len(), 2, "{recorded:?}");
        assert!(
            recorded[0].0 == "abs" && recorded[0].1.contains("absolute symlink not allowed"),
            "{recorded:?}"
        );
        assert!(
            recorded[1].0 == "esc" && recorded[1].1.contains("escaping symlink not allowed"),
            "{recorded:?}"
        );
        // PRESENT under the live kind so the diff, the report, and the removal
        // walk can address them.
        assert!(
            tree.meta
                .entries
                .iter()
                .any(|e| e.path == "abs" && e.entry_type == "symlink"),
            "{:?}",
            tree.meta.entries
        );
        assert!(
            tree.meta
                .entries
                .iter()
                .any(|e| e.path == "esc" && e.entry_type == "symlink")
        );

        // A hard link, likewise: both names have nlink > 1 and are recorded.
        let hard = dir.path().join("hard");
        std::fs::create_dir_all(&hard).unwrap();
        std::fs::write(hard.join("a"), b"content").unwrap();
        std::fs::hard_link(hard.join("a"), hard.join("b")).unwrap();
        assert!(canonicalize_tree(&hard).is_err());
        let tree = canonicalize_tree_destination(&hard).unwrap();
        let mut paths: Vec<String> = tree.unsupported.iter().map(|u| u.path.clone()).collect();
        paths.sort();
        assert_eq!(
            paths,
            vec!["a".to_string(), "b".to_string()],
            "{:?}",
            tree.unsupported
        );
        assert!(
            tree.unsupported
                .iter()
                .all(|u| u.reason.contains("hard links not allowed"))
        );
        assert!(tree.meta.entries.iter().all(|e| e.entry_type == "file"));
    }

    /// F2 (destination tolerance, REMOTE): the same tolerance through the
    /// far-side wire assembler — and the refusals it must NOT tolerate.
    #[test]
    fn destination_tolerant_remote_assembler_records_unrepresentable_entries() {
        skip_without_perl!("destination_tolerant_remote_assembler_records_unrepresentable_entries");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let links = dir.path().join("links");
        std::fs::create_dir_all(&links).unwrap();
        std::os::unix::fs::symlink("/opt/app/v1", links.join("abs")).unwrap();
        std::os::unix::fs::symlink("../../../etc/passwd", links.join("esc")).unwrap();

        let out = run_remote_script(&links);
        assert!(canonicalize_remote_entries(&out, &links).is_err());
        let tree = canonicalize_remote_entries_destination(&out, &links)
            .expect("the remote destination assembler tolerates the links");
        let mut paths: Vec<String> = tree.unsupported.iter().map(|u| u.path.clone()).collect();
        paths.sort();
        assert_eq!(
            paths,
            vec!["abs".to_string(), "esc".to_string()],
            "{:?}",
            tree.unsupported
        );

        // A special file is STILL refused on BOTH tolerant paths: the applier's
        // live-kind authority has no primitive for it, so tolerating it would
        // promise a removal the run cannot make.
        let special = dir.path().join("special");
        std::fs::create_dir_all(&special).unwrap();
        let fifo = special.join("pipe");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        let out = run_remote_script(&special);
        let remote_err = canonicalize_remote_entries_destination(&out, &special).unwrap_err();
        assert!(
            remote_err.to_string().contains("unsupported file type"),
            "{remote_err}"
        );
        let local_err = canonicalize_tree_destination(&special).unwrap_err();
        assert!(
            local_err.to_string().contains("unsupported file type"),
            "{local_err}"
        );
    }

    /// A symlink whose target escapes the tree root must be refused by BOTH
    /// verification paths: each resolves the relative target lexically against
    /// the directory CONTAINING the link (its own parent, per POSIX) and then
    /// tests containment in the root. An escaping link would let a
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
        // resolves it from the link's own directory and rejects the escape.
        let out = run_remote_script(&root);
        let remote_err = canonicalize_remote_entries(&out, &root).unwrap_err();
        assert!(
            remote_err.to_string().contains("escaping symlink"),
            "remote assembler must reject the escaping symlink, got: {remote_err}"
        );
    }

    /// B1: a RELATIVE symlink target is resolved against the directory
    /// CONTAINING the link (its own parent), per POSIX, not against the tree
    /// root. `dir/up -> ../other` resolves to `<root>/other` and is ACCEPTED by
    /// BOTH canonicalizers, as is a multi-separator `..` target that walks up
    /// and back down (`dir/sub/up -> ../../file`). The targets are stored
    /// VERBATIM as link data. This test FAILS against the pre-fix code, whose
    /// root-based base refused `dir/up -> ../other` as an "escaping symlink".
    #[test]
    fn relative_symlink_targets_resolve_against_the_links_directory() {
        skip_without_perl!("relative_symlink_targets_resolve_against_the_links_directory");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(root.join("dir").join("sub")).unwrap();
        std::fs::create_dir_all(root.join("other")).unwrap();
        std::fs::write(root.join("other/file"), b"ok").unwrap();
        std::fs::write(root.join("file"), b"top").unwrap();

        // `<root>/dir/up` -> `<root>/dir/../other` = `<root>/other`: IN root.
        std::os::unix::fs::symlink("../other", root.join("dir/up")).unwrap();
        // `<root>/dir/sub/up` -> `<root>/dir/sub/../../file` = `<root>/file`:
        // multiple separators plus a `..` that returns into the root.
        std::os::unix::fs::symlink("../../file", root.join("dir/sub/up")).unwrap();

        let local = canonicalize_tree(&root)
            .expect("an in-root `..` target is lawful and must be accepted");
        assert_eq!(
            local
                .entries
                .iter()
                .find(|e| e.path == "dir/up")
                .unwrap()
                .symlink_target
                .as_deref(),
            Some("../other"),
            "an in-root `..` target is stored verbatim"
        );
        assert_eq!(
            local
                .entries
                .iter()
                .find(|e| e.path == "dir/sub/up")
                .unwrap()
                .symlink_target
                .as_deref(),
            Some("../../file"),
            "a multi-separator `..` target that re-enters the root is stored verbatim"
        );

        // The wire assembler applies the SAME POSIX base, so it accepts exactly
        // the same tree and stores the same bytes.
        let out = run_remote_script(&root);
        let remote = canonicalize_remote_entries(&out, &root)
            .expect("the wire assembler must accept the same in-root links");
        assert_eq!(remote.entries, local.entries);
        assert_eq!(remote.tree_sha256, local.tree_sha256);
    }

    /// B1, the refusal half: after resolving relative targets from the link's
    /// own directory, an ABSOLUTE target and a target that genuinely leaves the
    /// root stay refused by BOTH canonicalizers. `dir/escape -> ../../outside`
    /// resolves to `<root>/../outside`, which is outside `<root>`.
    #[test]
    fn absolute_and_escaping_symlink_targets_stay_refused() {
        skip_without_perl!("absolute_and_escaping_symlink_targets_stay_refused");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(root.join("dir")).unwrap();
        std::fs::write(dir.path().join("outside"), b"secret").unwrap();
        std::os::unix::fs::symlink("../../outside", root.join("dir/escape")).unwrap();

        let local_err = canonicalize_tree(&root).unwrap_err();
        assert!(
            local_err.to_string().contains("escaping symlink"),
            "the local canonicalizer must still refuse the escape, got: {local_err}"
        );
        let out = run_remote_script(&root);
        let remote_err = canonicalize_remote_entries(&out, &root).unwrap_err();
        assert!(
            remote_err.to_string().contains("escaping symlink"),
            "the wire assembler must still refuse the escape, got: {remote_err}"
        );

        std::fs::remove_file(root.join("dir/escape")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root.join("dir/abs")).unwrap();
        let local_err = canonicalize_tree(&root).unwrap_err();
        assert!(
            local_err.to_string().contains("absolute symlink"),
            "the local canonicalizer must still refuse an absolute target, got: {local_err}"
        );
        let out = run_remote_script(&root);
        let remote_err = canonicalize_remote_entries(&out, &root).unwrap_err();
        assert!(
            remote_err.to_string().contains("absolute symlink"),
            "the wire assembler must still refuse an absolute target, got: {remote_err}"
        );
    }

    /// B1, the base's own resolution: when the ROOT is reached through a
    /// symlink, a target that stays inside the root (`../other` from `dir`) is
    /// accepted, and a target that escapes it is refused. The local walk's
    /// `lstat` base is the CANONICALIZED root, so it sees the live tree the
    /// kernel resolves against, while the containment walk itself is
    /// root-relative and does not depend on the root's spelling (which is what
    /// lets the wire assembler reach the same verdict).
    #[test]
    fn in_root_target_accepted_when_the_root_is_a_symlink() {
        skip_without_perl!("in_root_target_accepted_when_the_root_is_a_symlink");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(real.join("dir")).unwrap();
        std::fs::create_dir_all(real.join("other")).unwrap();
        std::fs::write(real.join("other/file"), b"ok").unwrap();
        std::os::unix::fs::symlink("../other", real.join("dir/up")).unwrap();
        let link_root = dir.path().join("link-root");
        std::os::unix::fs::symlink(&real, &link_root).unwrap();

        let local = canonicalize_tree(&link_root)
            .expect("the canonicalized root is the real directory the link sits in");
        assert_eq!(
            local
                .entries
                .iter()
                .find(|e| e.path == "dir/up")
                .unwrap()
                .symlink_target
                .as_deref(),
            Some("../other")
        );
        // A target that escapes the RESOLVED root is still refused.
        std::fs::remove_file(real.join("dir/up")).unwrap();
        std::os::unix::fs::symlink("../../outside", real.join("dir/escape")).unwrap();
        std::fs::write(dir.path().join("outside"), b"secret").unwrap();
        let err = canonicalize_tree(&link_root).unwrap_err();
        assert!(
            err.to_string().contains("escaping symlink"),
            "the resolved root must still bound the target, got: {err}"
        );
    }

    /// The reviewer's escape: a RELATIVE target whose SPELLED walk reaches a
    /// symlink component. `R/dir/sub -> ../other` and `R/dir/link ->
    /// sub/../../outside` collapse lexically to `R/outside` (inside the root,
    /// because the first `..` undoes `sub`), but the kernel WALKS THROUGH the
    /// `dir/sub` symlink to `R/other`, so the next `..` reaches the root's
    /// PARENT and `outside` is OUTSIDE. Containment is therefore decided on the
    /// spelled components: the walk reaches `dir/sub`, which the listing says is
    /// a symlink, and BOTH canonicalizers refuse it. Before the fix the local
    /// walk and the wire assembler both ACCEPTED this tree, and
    /// `read(dst/dir/link/secret)` returned the outside file.
    #[test]
    fn symlink_target_through_a_symlink_component_is_refused_by_both_canonicalizers() {
        skip_without_perl!(
            "symlink_target_through_a_symlink_component_is_refused_by_both_canonicalizers"
        );
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("R");
        std::fs::create_dir_all(root.join("dir")).unwrap();
        std::fs::create_dir_all(root.join("other")).unwrap();
        std::fs::write(root.join("other/file"), b"inside").unwrap();
        std::fs::create_dir_all(dir.path().join("outside")).unwrap();
        std::fs::write(dir.path().join("outside/secret"), b"SECRET").unwrap();
        // `R/dir/sub` is a SYMLINK to `R/other` (an accepted, in-root link).
        std::os::unix::fs::symlink("../other", root.join("dir/sub")).unwrap();
        // Its sibling walks `sub`, then `..` (which the kernel runs at the
        // SYMLINK's physical location), then out of the root.
        std::os::unix::fs::symlink("sub/../../outside", root.join("dir/link")).unwrap();

        // The escape is REAL on the live tree: through the symlink component,
        // the kernel leaves the root and reads the canary.
        assert_eq!(
            std::fs::read(root.join("dir/link/secret")).unwrap(),
            b"SECRET",
            "the escape must be real on the live tree for this test to mean anything"
        );

        let local_err = canonicalize_tree(&root).unwrap_err();
        let local_msg = local_err.to_string();
        assert!(
            local_msg.contains("escaping symlink") && local_msg.contains("dir/sub"),
            "the local walk must refuse the symlink component, naming it, got: {local_msg}"
        );
        let out = run_remote_script(&root);
        let remote_err = canonicalize_remote_entries(&out, &root).unwrap_err();
        let remote_msg = remote_err.to_string();
        assert!(
            remote_msg.contains("escaping symlink") && remote_msg.contains("dir/sub"),
            "the wire assembler must refuse the symlink component, naming it, got: {remote_msg}"
        );
    }

    /// The SAME disagreement with NO escape: `R/dir/sub -> ../other` and
    /// `R/dir/link -> sub/../other` collapse lexically to `R/dir/other`, but the
    /// kernel resolves `R/other`. Both land inside the root here, so the old
    /// lexical test accepted the tree with a WRONG answer; the physical rule
    /// refuses it (the `dir/sub` component is a symlink) rather than record a
    /// containment answer that does not match the kernel.
    #[test]
    fn symlink_target_through_a_symlink_component_is_refused_even_when_it_stays_lexically_in_root()
    {
        skip_without_perl!(
            "symlink_target_through_a_symlink_component_is_refused_even_when_it_stays_lexically_in_root"
        );
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("R");
        std::fs::create_dir_all(root.join("dir")).unwrap();
        std::fs::create_dir_all(root.join("other")).unwrap();
        std::fs::write(root.join("other/file"), b"inside").unwrap();
        std::os::unix::fs::symlink("../other", root.join("dir/sub")).unwrap();
        std::os::unix::fs::symlink("sub/../other", root.join("dir/link")).unwrap();

        // Lexical: `R/dir/sub/../other` = `R/dir/other` (inside). Physical:
        // `dir/sub` is `R/other`, so `sub/..` is `R`, then `other` is `R/other`.
        // The two answers differ, so the tree is refused, never recorded with
        // the lexical one.
        let local_err = canonicalize_tree(&root).unwrap_err();
        assert!(
            local_err.to_string().contains("dir/sub"),
            "the local walk must refuse the symlink component, got: {local_err}"
        );
        let out = run_remote_script(&root);
        let remote_err = canonicalize_remote_entries(&out, &root).unwrap_err();
        assert!(
            remote_err.to_string().contains("dir/sub"),
            "the wire assembler must refuse the symlink component, got: {remote_err}"
        );
    }

    /// The FINAL component counts too: the kernel FOLLOWS it, so a target that
    /// ends at a symlink can leave the root even when its spelling never pops
    /// above the root. `dir/link -> other-link`, where `other-link` is itself a
    /// symlink, is refused by BOTH canonicalizers rather than accepted as
    /// `<root>/other-link`. The rule is fail-closed even when the followed link
    /// happens to stay inside (as here, `other-link -> other`): the walk cannot
    /// know where the follow ends without following it, and the kernel WILL.
    #[test]
    fn symlink_target_ending_at_a_symlink_is_refused_by_both_canonicalizers() {
        skip_without_perl!("symlink_target_ending_at_a_symlink_is_refused_by_both_canonicalizers");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("R");
        std::fs::create_dir_all(root.join("dir")).unwrap();
        std::fs::create_dir_all(root.join("other")).unwrap();
        std::fs::write(root.join("other/file"), b"inside").unwrap();
        // A symlink INSIDE the root (it does not itself escape, so the refusal
        // below can only come from the FINAL-component rule).
        std::os::unix::fs::symlink("other", root.join("other-link")).unwrap();
        // The final component of this target is that symlink.
        std::os::unix::fs::symlink("../other-link", root.join("dir/link")).unwrap();
        assert_eq!(
            std::fs::read(root.join("dir/link/file")).unwrap(),
            b"inside",
            "the kernel follows the final symlink into the root"
        );

        let local_err = canonicalize_tree(&root).unwrap_err();
        assert!(
            local_err.to_string().contains("other-link"),
            "the local walk must refuse a target that ends at a symlink, got: {local_err}"
        );
        let out = run_remote_script(&root);
        let remote_err = canonicalize_remote_entries(&out, &root).unwrap_err();
        assert!(
            remote_err.to_string().contains("other-link"),
            "the wire assembler must refuse a target that ends at a symlink, got: {remote_err}"
        );
    }

    /// The two call sites must reach the SAME verdict when the ROOT is reached
    /// through a symlink, because the local walk used to canonicalize the root
    /// and the wire assembler could not. The relative walk is the same on both
    /// sides now, so a genuinely in-root target is ACCEPTED with byte-equal
    /// manifests on both, and a target that crosses the spelled root and
    /// re-enters only by spelling the root's own name is REFUSED by both. Before
    /// the fix `dir/link -> ../../real/other` was accepted locally and refused
    /// on the wire.
    #[test]
    fn symlinked_root_verdict_agrees_between_the_canonicalizers() {
        skip_without_perl!("symlinked_root_verdict_agrees_between_the_canonicalizers");
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let real = dir.path().join("deep").join("real");
        std::fs::create_dir_all(real.join("dir")).unwrap();
        std::fs::create_dir_all(real.join("other")).unwrap();
        std::fs::write(real.join("other/file"), b"ok").unwrap();
        let link_root = dir.path().join("lr");
        std::os::unix::fs::symlink(&real, &link_root).unwrap();

        // A genuinely in-root target (`../other` from `dir`): both ACCEPT, and
        // the manifests (and digests) are byte-equal.
        std::os::unix::fs::symlink("../other", real.join("dir/up")).unwrap();
        let local = canonicalize_tree(&link_root)
            .expect("a target that stays in the root must be accepted locally");
        let out = run_remote_script(&link_root);
        let remote = canonicalize_remote_entries(&out, &link_root)
            .expect("the wire assembler must reach the SAME accept verdict");
        assert_eq!(remote.entries, local.entries);
        assert_eq!(remote.tree_sha256, local.tree_sha256);
        assert_eq!(
            local
                .entries
                .iter()
                .find(|e| e.path == "dir/up")
                .unwrap()
                .symlink_target
                .as_deref(),
            Some("../other"),
            "the link target is stored verbatim"
        );

        // The divergence case: `dir/link -> ../../real/other` physically lands
        // at `<parent-of-real>/real/other` only because the root is NAMED
        // `real`; the spelled walk pops above the root and re-enters by that
        // name, so the link leaves the root the moment the tree is materialized
        // under any OTHER name. It is not portably contained, and the wire
        // cannot verify the physical re-entry, so the ONE rule refuses it on
        // both sides rather than let the two disagree.
        std::os::unix::fs::symlink("../../real/other", real.join("dir/link")).unwrap();
        let local_err = canonicalize_tree(&link_root).unwrap_err();
        assert!(
            local_err.to_string().contains("escaping symlink"),
            "the local walk must refuse it, got: {local_err}"
        );
        let out = run_remote_script(&link_root);
        let remote_err = canonicalize_remote_entries(&out, &link_root).unwrap_err();
        assert!(
            remote_err.to_string().contains("escaping symlink"),
            "the wire assembler must reach the SAME refuse verdict, got: {remote_err}"
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
            announce_skip(&format!(
                "this filesystem cannot store a non-UTF-8 name ({e})"
            ));
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
            Err(e) => announce_skip(&format!(
                "canonicalizers_agree_on_unrepresentable_names_and_targets: skipped case (4), \
                 this filesystem cannot store a non-UTF-8 name ({e})"
            )),
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

    /// A wire manifest must be PARENT-CLOSED: every entry with a `/` must have
    /// an entry for its parent directory, and that parent entry must be a
    /// `dir`. The wire walk emits parents first, but the FORMAT did not require
    /// it, so a crafted `d/x` line with no `d` line was accepted. The apply
    /// layer verifies only the FINAL path component, so the parent's spelling
    /// was never checked unless it happened to be a source entry: on a
    /// case-insensitive destination `applied` could name `d/x` while the
    /// destination held `D/x` (one on-disk entry under two spellings, broken
    /// report injectivity, every re-run repeating), and on a case-sensitive one
    /// the durable write's `ensure_private_dir_fd` IMPLICITLY created `d`, an
    /// on-disk entry no report list named (with `delete_extraneous` the
    /// just-installed entry was then destroyed by the sanctioned removal of the
    /// pre-existing `D`). This assertion FAILS against the pre-fix assembler,
    /// which accepted the crafted line.
    #[test]
    fn assembler_requires_parent_closed_manifests() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        std::fs::create_dir_all(&root).unwrap();
        let hash = "0".repeat(64);

        // (1) A child with NO parent entry: refused, naming the child and the
        // missing parent.
        let orphan = format!("d/x\tf\t1a4\t1\t{hash}\t\n");
        let err = canonicalize_remote_entries(&orphan, &root).unwrap_err();
        assert!(
            err.to_string().contains("not parent-closed"),
            "a child without its parent entry must be refused, got: {err}"
        );
        assert!(
            err.to_string().contains("d/x"),
            "the refusal must name the child, got: {err}"
        );
        assert!(
            err.to_string().contains('d') && err.to_string().contains("parent directory"),
            "the refusal must name the missing parent directory, got: {err}"
        );

        // (2) The CONTROL: adding the parent `dir` line makes the SAME entry
        // acceptable, so the gap is precisely the missing closure — not the
        // path, the type, or the hash.
        let closed = format!("d\td\t1ed\t1\t\t\nd/x\tf\t1a4\t1\t{hash}\t\n");
        canonicalize_remote_entries(&closed, &root).unwrap();

        // (3) The reverse: a parent that is present but NOT a `dir` (a file
        // with children) is refused, naming both.
        let file_parent = format!("p\tf\t1a4\t1\t{hash}\t\np/x\tf\t1a4\t1\t{hash}\t\n");
        let err = canonicalize_remote_entries(&file_parent, &root).unwrap_err();
        assert!(
            err.to_string().contains("non-directory parent"),
            "a file entry with children must be refused, got: {err}"
        );
        assert!(
            err.to_string().contains("p/x") && err.to_string().contains('p'),
            "the refusal must name the child and the non-directory parent, got: {err}"
        );

        // (4) A WELL-FORMED nested manifest is still accepted, and every
        // accepted entry's parent is a `dir` — the invariant the apply layer
        // relies on to keep its reports injective and to avoid implicitly
        // creating an unnamed parent.
        let meta = canonicalize_remote_entries(
            &format!("a\td\t1ed\t1\t\t\na/b\td\t1ed\t1\t\t\na/b/c\tf\t1a4\t1\t{hash}\t\n"),
            &root,
        )
        .unwrap();
        assert_eq!(entry_paths(&meta), vec!["a", "a/b", "a/b/c"]);
        for entry in &meta.entries {
            if let Some((parent, _)) = entry.path.rsplit_once('/') {
                let p = meta
                    .entries
                    .iter()
                    .find(|e| e.path == parent)
                    .unwrap_or_else(|| {
                        panic!(
                            "accepted manifest is not parent-closed at {}: no entry for {}",
                            entry.path, parent
                        )
                    });
                assert_eq!(p.entry_type, "dir", "parent {parent} must be a dir");
            }
        }
    }

    /// The LOCAL walk is parent-closed BY CONSTRUCTION and needs no gate:
    /// `WalkDir` yields a directory before the entries inside it, so every
    /// nested path's parent is already an entry of the same kind. This pins
    /// that invariant (the remote assembler's [`require_parent_closed`] gate is
    /// the only one needed).
    #[test]
    fn local_walk_is_parent_closed_by_construction() {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let root = dir.path().join("tree");
        build_tree(&root);
        let meta = canonicalize_tree(&root).unwrap();
        assert_eq!(
            entry_paths(&meta),
            vec!["file.txt", "sub", "sub/link", "sub/nested.txt"]
        );
        for entry in &meta.entries {
            if let Some((parent, _)) = entry.path.rsplit_once('/') {
                let p = meta
                    .entries
                    .iter()
                    .find(|e| e.path == parent)
                    .unwrap_or_else(|| {
                        panic!(
                            "local walk produced {} with no parent entry {}",
                            entry.path, parent
                        )
                    });
                assert_eq!(p.entry_type, "dir", "parent {parent} must be a dir");
            }
        }
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
