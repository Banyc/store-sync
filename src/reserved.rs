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
//! resembles a reserved spelling is ordinary content.

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
}
