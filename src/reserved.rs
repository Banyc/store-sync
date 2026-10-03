//! The crate's RESERVED name spellings — the ONE authority for "is this
//! spelling reserved".
//!
//! Some names inside a store are the crate's own bookkeeping, never the
//! caller's content. Two are reserved today:
//!
//! * the CLAIM-ASIDE namespace, every name beginning with
//!   [`ASIDE_PREFIX`] (`.sync-aside.`): the temporary names a sync uses to move
//!   an entry aside while it replaces it;
//! * the operation-LOCK record spelling `.<name>.operation.lock` (a
//!   dot-prefixed sibling of a destination root, carrying a non-empty
//!   `<name>`): the record [`crate::sync::destination_lock_path`] derives and
//!   [`crate::lock::FileLock`] holds.
//!
//! The predicate lives HERE, once, because it is consulted from three places
//! that must never disagree:
//!
//! * [`crate::id::valid_name`] refuses a reserved spelling, so an identity the
//!   crate ACCEPTS is always a name the crate can replicate through a
//!   whole-store sync and destroy through its sanctioned delete route;
//! * [`crate::sync::apply`] strips reserved components from BOTH manifests
//!   before the diff, so a reserved entry is never transferred, never removed
//!   by [`crate::sync::Extraneous::Delete`], and is reported for the caller
//!   (a source collision as a `ReservedName` conflict, a destination entry as
//!   `SyncReport::residue`);
//! * a CONSUMER can ask before it fails: [`is_reserved_name`] answers "may I
//!   use this name?" for a single segment and [`is_reserved_path`] for a
//!   canonical manifest path.
//!
//! A reserved name is matched as a whole path COMPONENT, byte-exactly: the
//! check never decodes, normalizes, or case-folds, so a name that merely
//! RESEMBLES a reserved spelling without being an ALIAS of one is ordinary
//! content. Two spellings that are not byte-identical but CASE-FOLD onto one
//! another are the SAME directory entry on a case-insensitive filesystem
//! (macOS APFS by default, Windows by default), so the id/name rule refuses
//! such an alias ([`is_reserved_case_alias`]) even though the byte-exact
//! reserved MATCH above leaves it alone: `.SYNC-ASIDE.1` IS `.sync-aside.1`,
//! and `.DESTROOT.OPERATION.LOCK` IS `.destroot.operation.lock`.
//!
//! The application-store lock record's own name — the bare `operation.lock`
//! that [`crate::lock::FileLock`] holds at a store root — is likewise not one
//! of the two byte-exact reserved families, but it is unaddressable as an
//! identity ([`APPLICATION_LOCK_NAME`]): accepting it would let consumer
//! content share the name of the crate's own lock record. The crate's own
//! removal primitives refuse the whole lock-record spelling family
//! ([`is_lock_record_name`]), so the record's stable inode cannot be unlinked
//! through the substrate.

use std::path::{Component, Path};

/// The claim-aside namespace: any name with this prefix belongs to the
/// claim-by-rename machinery and is excluded from both manifests before the
/// diff.
pub const ASIDE_PREFIX: &str = ".sync-aside.";

/// The operation-lock record spelling's suffix: `.<name>.operation.lock`.
pub const OPERATION_LOCK_SUFFIX: &str = ".operation.lock";

/// Whether a SINGLE path segment is one of the crate's RESERVED spellings and
/// must not be used as caller content (an identity, a manifest path segment).
///
/// Reserved is:
///
/// * any non-empty name beginning with [`ASIDE_PREFIX`]; or
/// * a name of the exact shape `.<name>.operation.lock` — a leading dot, a
///   NON-EMPTY `<name>`, then [`OPERATION_LOCK_SUFFIX`]. The bare
///   `operation.lock` and the empty base (`.operation.lock`) are NOT this
///   spelling and stay ordinary.
///
/// The match is byte-exact and case-sensitive; nothing is normalized.
pub fn is_reserved_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.starts_with(ASIDE_PREFIX) {
        return true;
    }
    let Some(base) = name.strip_prefix('.') else {
        return false;
    };
    let Some(base) = base.strip_suffix(OPERATION_LOCK_SUFFIX) else {
        return false;
    };
    !base.is_empty()
}

/// The FILE NAME of the crate's application-store lock record: the in-root
/// advisory lock [`crate::lock::FileLock`] holds (`<root>/operation.lock`).
///
/// This spelling is deliberately NOT one of the two byte-exact reserved
/// families above — [`is_reserved_name`] stays byte-exact, so the sync's
/// reserved stripping is unchanged — but it IS unaddressable as an identity:
/// accepting it would let consumer content share a name with the crate's own
/// lock record, which [`crate::lock::FileLock::acquire`] truncates and
/// rewrites, and which the crate's removal guard protects.
pub const APPLICATION_LOCK_NAME: &str = "operation.lock";

/// Whether `name` is the crate's application-store lock record spelling
/// ([`APPLICATION_LOCK_NAME`]).
pub fn is_application_lock_name(name: &str) -> bool {
    name == APPLICATION_LOCK_NAME
}

/// Whether `name` is a CASE ALIAS of a spelling the crate reserves for its own
/// bookkeeping: its Unicode case fold (`str::to_lowercase` — the SAME fold the
/// sync's destination-alias model uses) is a reserved spelling or the
/// application lock record while `name` itself is byte-different.
///
/// On a case-insensitive filesystem (macOS APFS by default, Windows by
/// default) `name` and the reserved spelling are the SAME directory entry, so
/// an accepted alias could collide with the crate's own bookkeeping:
/// `.SYNC-ASIDE.1` IS `.sync-aside.1`, and `.DESTROOT.OPERATION.LOCK` IS
/// `.destroot.operation.lock` (the record [`crate::lock::FileLock::acquire`]
/// truncates). Byte-exact reserved MATCHING is deliberately unaffected — this
/// is about ALIASING, not about matching — so [`is_reserved_name`] keeps
/// answering byte-exactly while the id/name rule refuses the alias.
pub fn is_reserved_case_alias(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let folded = name.to_lowercase();
    folded != name && (is_reserved_name(&folded) || is_application_lock_name(&folded))
}

/// Whether the id/name rule must REFUSE `name` because it NAMES or can ALIAS
/// the crate's own bookkeeping on a supported filesystem: a byte-exact
/// reserved spelling, the application lock record, or a case alias of either.
/// This is the predicate [`crate::id::valid_name`] consults, so an identity
/// the crate accepts can never alias a reserved entry on any filesystem the
/// crate supports (while [`is_reserved_name`] / [`is_reserved_path`] stay
/// byte-exact for the sync's reserved stripping).
pub fn is_unaddressable_name(name: &str) -> bool {
    is_reserved_name(name) || is_application_lock_name(name) || is_reserved_case_alias(name)
}

/// Whether `name` is a LOCK-RECORD spelling: the application lock record
/// ([`APPLICATION_LOCK_NAME`]) or the sibling record spelling
/// [`is_reserved_name`] recognises (`.<name>.operation.lock`), in byte-exact or
/// case-ALIAS form. The crate's own removal primitives refuse this spelling
/// ([`crate::atomic::remove_file_fd`] / [`crate::atomic::remove_dir_all_fd`]):
/// the lock's STABLE INODE is what makes two simultaneous holders impossible,
/// so removing (or replacing) the record through the substrate would admit a
/// second holder.
pub fn is_lock_record_name(name: &str) -> bool {
    fn sibling(name: &str) -> bool {
        let Some(base) = name.strip_prefix('.') else {
            return false;
        };
        let Some(base) = base.strip_suffix(OPERATION_LOCK_SUFFIX) else {
            return false;
        };
        !base.is_empty()
    }
    if sibling(name) || is_application_lock_name(name) {
        return true;
    }
    let folded = name.to_lowercase();
    folded != name && (sibling(&folded) || is_application_lock_name(&folded))
}

/// Whether ANY component of a canonical manifest path is reserved (see
/// [`is_reserved_name`]). A reserved DIRECTORY makes every entry below it
/// reserved too: the aside holds a stranded subtree, and the lock record is
/// never descended into.
///
/// Components are split with [`Path::components`], never a literal-separator
/// split, so the answer is the same whether a manifest spells paths with `/`
/// (the canonical spelling on every platform) or with the platform separator.
pub fn is_reserved_path(path: &str) -> bool {
    Path::new(path)
        .components()
        .any(|component| match component {
            Component::Normal(name) => name.to_str().is_some_and(is_reserved_name),
            _ => false,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The predicate accepts exactly the two reserved families and leaves
    /// every near-miss ordinary. The near-misses are the load-bearing half:
    /// `operation.lock`, `.operation.lock`, `sync-aside.1`, `.sync-aside`
    /// (no trailing dot), and a lock spelling with an EMPTY base are all
    /// ordinary names.
    #[test]
    fn reserved_names_are_exactly_the_two_families() {
        for reserved in [
            ".sync-aside.1",
            ".sync-aside.123.0",
            ".sync-aside.",
            ".001.operation.lock",
            "..sync-aside.1.operation.lock",
            ".a.operation.lock",
        ] {
            assert!(is_reserved_name(reserved), "{reserved:?} must be reserved");
        }
        for ordinary in [
            "",
            ".",
            "..",
            "operation.lock",
            ".operation.lock",
            ".operation.lock.operation.lock.", // trailing dot: not the suffix
            "sync-aside.1",
            ".sync-aside", // no trailing dot
            "xsync-aside.1",
            "a.operation.lock", // no leading dot
            ".001.operation.lockx",
            ".001.operation.lock/x",
        ] {
            assert!(
                !is_reserved_name(ordinary),
                "{ordinary:?} must NOT be reserved"
            );
        }
    }

    /// A reserved name is reserved as a WHOLE component anywhere in a path,
    /// including above a subtree; an ordinary near-miss component is not.
    #[test]
    fn reserved_paths_match_components_not_substrings() {
        assert!(is_reserved_path("snapshots/.001.operation.lock"));
        assert!(is_reserved_path(".sync-aside.1/sub/file"));
        assert!(is_reserved_path("a/.sync-aside.1"));
        assert!(!is_reserved_path("snapshots/001/operation.lock"));
        assert!(!is_reserved_path("snapshots/x.001.operation.lock"));
        assert!(!is_reserved_path(""));
    }

    /// The reserved rule AGREES with the identifier rule: every reserved
    /// spelling is refused by [`crate::id::valid_name`], and every name the
    /// identifier accepts is NOT reserved. This is the "an accepted id is
    /// always a name the crate can replicate and destroy" property, stated
    /// directly against both authorities.
    #[test]
    fn the_id_rule_and_the_reserved_rule_agree() {
        for reserved in [".sync-aside.1", ".001.operation.lock"] {
            assert!(is_reserved_name(reserved));
            assert!(
                !crate::id::valid_name(reserved),
                "an id the crate accepts must never be a reserved spelling: {reserved:?}"
            );
        }
        for ok in ["s1", "production", "wave-1", "a..b", "a.b", "a_b-c.d"] {
            assert!(!is_reserved_name(ok), "{ok:?} is ordinary");
            assert!(crate::id::valid_name(ok), "{ok:?} is a valid id");
        }
    }

    /// A name that is not byte-identical to a reserved spelling but CASE-FOLDS
    /// onto one is the SAME directory entry on a case-insensitive filesystem,
    /// so the id/name rule refuses the alias while the byte-exact reserved
    /// MATCH leaves it alone. This is the A3 aliasing rule: matching is
    /// byte-exact, ALIASING is folded.
    #[test]
    fn case_aliases_of_reserved_spellings_are_unaddressable_but_not_byte_reserved() {
        for alias in [
            ".SYNC-ASIDE.1",
            ".Sync-Aside.1",
            ".001.OPERATION.LOCK",
            ".Destroot.Operation.Lock",
            "OPERATION.LOCK",
            "Operation.Lock",
        ] {
            assert!(
                is_reserved_case_alias(alias),
                "{alias:?} case-folds onto a reserved spelling and must be an alias"
            );
            assert!(
                !is_reserved_name(alias),
                "the byte-exact MATCH must leave {alias:?} alone (aliasing is a separate rule)"
            );
            assert!(
                is_unaddressable_name(alias),
                "{alias:?} must be unaddressable as an identity"
            );
            assert!(
                !crate::id::valid_name(alias),
                "the id rule must refuse the alias {alias:?}"
            );
        }
        // A byte-exact reserved spelling is not an ALIAS (it is the spelling
        // itself), and a genuinely distinct near-miss is neither.
        for not_alias in [
            ".sync-aside.1",
            ".001.operation.lock",
            "sync-aside.1",
            ".sync-aside",
            "a.operation.lock",
            "operation.lock!",
            "",
        ] {
            assert!(
                !is_reserved_case_alias(not_alias),
                "{not_alias:?} is not a case ALIAS"
            );
        }
    }

    /// The crate's own lock-record spellings are recognised as LOCK RECORDS
    /// (so the removal primitives can refuse them) without turning the
    /// byte-exact reserved family into a broader match: `.sync-aside.1` is
    /// reserved but is NOT a lock record.
    #[test]
    fn lock_record_spellings_are_recognised() {
        for lock in [
            "operation.lock",
            ".001.operation.lock",
            ".Destroot.Operation.Lock",
            "OPERATION.LOCK",
            "Operation.Lock",
        ] {
            assert!(is_lock_record_name(lock), "{lock:?} names a lock record");
        }
        for other in [
            ".sync-aside.1",
            ".operation.lock",
            "a.operation.lock",
            "operation.lockx",
            ".001.operation.lockx",
            "",
        ] {
            assert!(
                !is_lock_record_name(other),
                "{other:?} does not name a lock record"
            );
        }
    }

    /// The ON-DISK half of the A3 aliasing rule: on a case-insensitive
    /// filesystem `.SYNC-ASIDE.1` and `.sync-aside.1` are the SAME directory
    /// entry, so a name the id rule accepted would collide with the crate's
    /// claim-aside machinery. The pure rule is pinned everywhere by
    /// [`case_aliases_of_reserved_spellings_are_unaddressable_but_not_byte_reserved`];
    /// THIS test pins the phenomenon on the filesystem that has it, and skips
    /// (with a truthful, announced reason) on a case-sensitive one.
    #[test]
    fn a_case_variant_of_a_reserved_spelling_is_one_inode_and_unaddressable() {
        use std::fs;
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env())
            .expect("fixture tmpdir");
        fs::write(dir.path().join(".sync-aside.1"), b"held").unwrap();
        let folds = fs::symlink_metadata(dir.path().join(".SYNC-ASIDE.1")).is_ok();
        if !folds {
            crate::test_support::announce_skip(
                "this filesystem is case-SENSITIVE, so `.SYNC-ASIDE.1` and `.sync-aside.1` are \
                 DISTINCT entries and the on-disk alias reproduction is untestable here; the pure \
                 alias rule is still pinned by the predicate test",
            );
            return;
        }
        println!(
            "A3 case-alias probe ran on platform={} (the filesystem folds case, so the two \
             spellings are one entry)",
            std::env::consts::OS
        );
        // The alias the id rule must refuse; the byte-exact reserved MATCH is
        // deliberately unchanged (aliasing is a separate rule).
        assert!(is_reserved_case_alias(".SYNC-ASIDE.1"));
        assert!(!is_reserved_name(".SYNC-ASIDE.1"));
        assert!(is_unaddressable_name(".SYNC-ASIDE.1"));
        assert!(!crate::id::valid_name(".SYNC-ASIDE.1"));
        assert!(!crate::id::valid_name(".sync-aside.1"));
        // The application lock record's case alias resolves to the record's
        // own entry, and is unaddressable too.
        fs::write(dir.path().join("operation.lock"), b"hold").unwrap();
        assert!(fs::symlink_metadata(dir.path().join("OPERATION.LOCK")).is_ok());
        assert!(!crate::id::valid_name("OPERATION.LOCK"));
    }
}
