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
//! content share the name of the crate's own lock record.
//!
//! [`is_unaddressable_name`] is the ONE authority for "the crate may not name
//! this": the id rule ([`crate::id::valid_name`]) consults it, and the sync's
//! manifest-path model consults its path form ([`is_unaddressable_path`]), so
//! a spelling the crate refuses as an id is EXACTLY a spelling a whole-store
//! sync refuses to transfer or destroy. It refuses the crate's own TEMP shapes
//! (and their case aliases, F6) as well as the reserved/lock spellings, so the
//! documented recovery sweep ([`crate::atomic::is_crate_temp_name`]) can never
//! delete addressable content. The crate's mutating primitives consult
//! the lock-record subset ([`is_lock_record_name`]) through the ONE guard
//! authority (`crate::atomic::guard`), so the record's stable inode cannot be
//! unlinked, replaced, truncated, or renamed through the substrate's
//! name-mutating funnel. The RECURSIVE-REMOVAL primitives additionally consult
//! the RESIDUE subset ([`is_residue_name`]) at the same chokepoint, so the
//! crate's own `remove_dir_all`-shaped primitives can never walk over a
//! stranded aside that HOLDS an original; the one sanctioned break is the
//! explicit [`crate::sync::Residue::discard`].

use std::path::{Component, Path};

/// The claim-aside namespace: any name with this prefix belongs to the
/// claim-by-rename machinery and is excluded from both manifests before the
/// diff.
pub const ASIDE_PREFIX: &str = ".sync-aside.";

/// The operation-lock record spelling's suffix: `.<name>.operation.lock`.
pub const OPERATION_LOCK_SUFFIX: &str = ".operation.lock";

/// The ONE spelling of the residue refusal, shared by the sync's
/// [`crate::sync::ConflictReason::ResidueBelow`] and the atomic substrate's
/// refusal of an IMPLICIT recursive removal
/// ([`crate::atomic::remove_dir_all_path`] and its siblings). A consumer that
/// matches the reason on the sync side and the conflict token on the
/// substrate side therefore reads ONE vocabulary rather than two. The
/// substrate's refusal is an [`crate::error::Error::Conflict`] whose message
/// begins with this token.
pub const RESIDUE_BELOW: &str = "ResidueBelow";

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
/// reserved spelling, the application lock record, a case alias of either, a
/// crate TEMP shape ([`crate::atomic::is_crate_temp_name`]), or a CASE ALIAS
/// of a crate temp shape.
///
/// This is the predicate [`crate::id::valid_name`] consults, so an identity
/// the crate accepts can never alias a reserved entry on any filesystem the
/// crate supports NOR look like a crate temp a consumer's recovery sweep
/// ([`crate::atomic::is_crate_temp_name`]) is documented to REMOVE. The crate
/// owns the temp namespace, and an id that looked like its temp would be a
/// trap the consumer cannot see; refusing the shape at this ONE boundary makes
/// the documented sweep safe by construction (F-B). (While
/// [`is_reserved_name`] / [`is_reserved_path`] stay byte-exact for the sync's
/// reserved stripping.)
///
/// F6: the temp half is checked in CASE-FOLDED form too
/// ([`is_crate_temp_case_alias`]). The byte-exact recognizer
/// [`crate::atomic::is_crate_temp_name`] cannot see that `.FOO.TMP.1.0`
/// aliases `.foo.tmp.1.0` on a case-insensitive filesystem (macOS APFS,
/// Windows), so without this arm `valid_name(".FOO.TMP.1.0")` would be true
/// while the crate treats `.foo.tmp.1.0` as its own temp — the id rule's
/// stated purpose ("an accepted id can never alias the crate's own
/// bookkeeping on a supported filesystem") would then be false for that
/// family. Refusing the alias makes the purpose true. Linux cannot exhibit
/// the alias (its filesystem is case-sensitive), so the rule is deliberately
/// platform-INDEPENDENT: an id rule that changed with the host filesystem
/// would make a manifest mean different things on different hosts.
pub fn is_unaddressable_name(name: &str) -> bool {
    is_reserved_name(name)
        || is_application_lock_name(name)
        || is_reserved_case_alias(name)
        || crate::atomic::is_crate_temp_shape(name)
        || is_crate_temp_case_alias(name)
}

/// Whether `name` case-folds onto one of the crate's own TEMP shapes
/// ([`crate::atomic::is_crate_temp_shape`]) while being byte-different. See
/// [`is_unaddressable_name`] (F6).
fn is_crate_temp_case_alias(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let folded = name.to_lowercase();
    folded != name && crate::atomic::is_crate_temp_shape(&folded)
}

/// Whether ANY component of a canonical manifest path is UNADDRESSABLE
/// ([`is_unaddressable_name`]).
///
/// This is the PATH-level form of the SAME authority [`crate::id::valid_name`]
/// consults, and it is what a whole-store sync uses to decide whether a
/// manifest entry may be transferred or destroyed. It is deliberately
/// BROADER than [`is_reserved_path`], which stays byte-exact for callers that
/// need the historical reserved MATCH: a name the id rule refuses — the
/// application lock record `operation.lock` and every case alias of a reserved
/// spelling included — is also unaddressable as a manifest path, so the id
/// rule and the sync's manifest-path model can never disagree about what the
/// crate may not touch.
///
/// Components are split with [`Path::components`], never a literal-separator
/// split, so the answer is the same whether a manifest spells paths with `/`
/// (the canonical spelling on every platform) or with the platform separator.
pub fn is_unaddressable_path(path: &str) -> bool {
    Path::new(path)
        .components()
        .any(|component| match component {
            Component::Normal(name) => name.to_str().is_some_and(is_unaddressable_name),
            _ => false,
        })
}

/// Whether `name` is destination RESIDUE: an UNADDRESSABLE spelling
/// ([`is_unaddressable_name`]) that HOLDS something the sync must not destroy,
/// as opposed to a CRASHED TEMP. A crate temp can inherit the reserved
/// namespace (a destination whose own name begins `sync-aside.` yields
/// `.sync-aside.<name>.tmp.<pid>.<n>`) but holds NO original, so it is NOT
/// residue and stays ordinary destination content.
///
/// This is the DESTINATION-side stripping predicate the sync uses; the SOURCE
/// side strips every unaddressable path ([`is_unaddressable_path`]) so a crate
/// temp is never replicated. Exposed so a consumer building its own status on
/// the raw manifest primitives can strip EXACTLY what the engine strips (see
/// [`crate::sync::diff::apply_manifests`]).
///
/// The distinction is a test on the temp-name authority's own spelling:
/// [`crate::atomic::is_crate_temp_name`] is true exactly for the temporary and
/// claim names the crate's atomic primitives PRODUCE.
pub fn is_residue_name(name: &str) -> bool {
    is_unaddressable_name(name) && !crate::atomic::is_crate_temp_name(name)
}

/// Whether ANY component of a canonical manifest path is destination residue
/// ([`is_residue_name`]).
///
/// Components are split with [`Path::components`], never a literal-separator
/// split, so the answer is the same whether a manifest spells paths with `/`
/// (the canonical spelling on every platform) or with the platform separator.
pub fn is_residue_path(path: &str) -> bool {
    Path::new(path)
        .components()
        .any(|component| match component {
            Component::Normal(name) => name.to_str().is_some_and(is_residue_name),
            _ => false,
        })
}

/// Whether `name` is a LOCK-RECORD spelling: the application lock record
/// ([`APPLICATION_LOCK_NAME`]) or the sibling record spelling
/// [`is_reserved_name`] recognises (`.<name>.operation.lock`), in byte-exact,
/// case-ALIAS, or trailing-dot/space ALIAS form (the last two are the same
/// entry on a filesystem that folds case or ignores a trailing dot/space —
/// Win32 does the latter on a short absolute drive path).
///
/// Every name-mutating primitive of the [`crate::atomic`] SUBSTRATE consults
/// this spelling through the ONE guard authority (`atomic::guard`), which
/// now runs at the SYSCALL CHOKEPOINTS (`unlinkat`, `renameat`, `linkat`,
/// `symlinkat`, `mkdirat`, and a mutating `openat`) rather than by
/// enumerating call sites. The rel-path mutators
/// ([`crate::atomic::remove_file_fd`], [`crate::atomic::remove_dir_all_fd`]
/// and each entry its walk unlinks, [`crate::atomic::remove_dir_all_path`],
/// the PATH-BASED [`crate::atomic::write_atomic_replace`],
/// [`crate::atomic::write_atomic_replace_fd`],
/// [`crate::atomic::write_atomic_if_match_fd`],
/// [`crate::atomic::write_atomic_cas_fd`], [`crate::atomic::write_file_fd`],
/// [`crate::atomic::create_dir_fd`], [`crate::atomic::remove_dir_fd`],
/// [`crate::atomic::symlink_fd`], and [`crate::atomic::renameat_paths`] —
/// which additionally refuses a source SUBTREE containing a record) must
/// first mint the unforgeable [`crate::atomic::GuardedRel`] capability, whose
/// constructors run the guard; the low-level single-name syscall
/// wrappers guard the final name at the primitive. The record's STABLE INODE
/// is what makes two simultaneous holders impossible, so removing, replacing,
/// renaming, or truncating the record through the substrate would admit a
/// second holder.
///
/// The claim is deliberately NARROWED to the substrate's primitives. "Every
/// mutating primitive the crate exposes" would be FALSE, and the residual is:
///
/// * the crate's OWN lock protocol mutates a lock record on purpose.
///   [`crate::lock::FileLock::acquire`] creates/truncates the application
///   record, and the transport's ownership-token protocol
///   ([`crate::transport::Remote::remove_file_if`], and `durable_create_new`)
///   compare-and-deletes / re-creates the in-root lock, serialized through the
///   sidecar flock. Those operations MAKE and BREAK locks by design; guarding
///   them would break the protocol, not protect it. The protocol's reach is
///   bounded to the ONE record the layout OWNS: the transport's `*_if`
///   primitives mint [`crate::atomic::GuardedRel`] through
///   [`crate::atomic::GuardedRel::new_for_owned_lock_record`], which refuses
///   every lock-record spelling other than the record that IS the layout
///   lock's on-disk entry (identity — the resolved device/inode — with a
///   byte-exact spelling fallback only while that entry does not exist yet),
///   so a bare `operation.lock`, a nested `snapshots/.001.operation.lock`, a
///   case/dot alias that resolves to a DISTINCT entry, or any other spelling
///   can no longer be claimed away. The recognition is IDENTITY-based rather
///   than spelling-fold-based on purpose: a fold is sound for refusing a
///   spelling but unsound for authorizing a mutation, because it would grant
///   ownership of a different on-disk entry a live holder owns.
/// * the PATH-BASED helpers the manifest/retention machinery uses take an
///   ordinary path. `set_private`, `ensure_private_dir`,
///   `ensure_private_dir_durable`, the PATH-BASED `write_atomic_replace`, and
///   the descriptor-relative `set_private_fd` now consult the guard too; the
///   remaining unguarded `std::fs` mutations are the local transport's
///   crate-INTERNAL staged-publish rename/remove/create on its own temp/swap
///   names, the destination-root `create_dir_all`, and the ssh hostkey cache
///   — none of which a caller can steer to the record's spelling.
///   `copy_dir_recursive` is `#[cfg(test)]` on BOTH ports
///   (`src/atomic/unix.rs` and `src/atomic/windows.rs`), so it is a
///   test-only path-based copy and never reaches a production build on any
///   platform — the residual does not list it as a production hole. The
///   lock's assumption section already states that a caller acting outside
///   the substrate (a foreign process, a raw `std::fs` call the caller writes
///   itself) is not stopped.
/// * a foreign process, or a developer writing a brand-new direct `libc::`
///   mutation OUTSIDE the funnel module, is not stopped by the type system.
///   The crate carries two source audits
///   (`atomic::guard::tests::no_libc_reference_outside_the_funnel` and
///   `atomic::guard::tests::std_fs_name_mutation_counts_are_pinned`) that fail on ANY
///   new `libc` reference outside `src/atomic/unix.rs` — a mutating symbol, a
///   `use libc as alias` module alias, a braced self-alias, a re-export, a
///   glob, or a call broken across a newline — and when a `std::fs`
///   removal/replace/rename call in PRODUCTION code changes count. Their exact scope (and the holes no
///   text audit can close) is documented at the audits themselves; the
///   funnel wrappers themselves are private, so the "obvious way" to add a
///   mutation cannot bypass the guard.
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
    // ONE fold decides every spelling ALIAS: Unicode lowercase then strip
    // trailing `.`/` ` (see [`fold_lock_record_component`]). Byte-exact
    // matching is deliberately NOT used here — a trailing dot is a distinct
    // entry on macOS/Linux but Win32 strips it from a short absolute drive
    // path, so recognising the alias is correct everywhere and only load
    // bearing on Windows.
    let folded = fold_lock_record_component(name);
    sibling(&folded) || is_application_lock_name(&folded)
}

/// The ONE normalization used to DENY a lock-record spelling
/// ([`is_lock_record_name`]): Unicode lowercase (`str::to_lowercase`, the fold
/// the crate's case-alias model already uses) followed by stripping trailing
/// `.` and ` ` (the Win32 final-component normalization that removes a
/// trailing dot/space on a short absolute drive path; `is_lock_record_name`
/// must recognise that alias everywhere so a Windows path cannot slip a record
/// past the guard, and folding is harmless on a case-sensitive,
/// dot-preserving filesystem).
///
/// A fold may only ever make the crate REFUSE MORE. It is deliberately NOT used
/// to decide OWNERSHIP: folding two distinct on-disk entries together would
/// GRANT the protocol permission to mutate an entry a live holder owns. The
/// ownership decision is identity-based
/// ([`crate::atomic::OwnedLockRecord::owns`]).
fn fold_lock_record_component(name: &str) -> String {
    name.to_lowercase().trim_end_matches(['.', ' ']).to_string()
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

    /// The ID rule and the SYNC's manifest-path model consult ONE authority.
    /// The byte-exact reserved MATCH ([`is_reserved_path`]) deliberately leaves
    /// the application lock record alone, but the path-level UNADDRESSABLE
    /// predicate ([`is_unaddressable_path`]) refuses it and its aliases —
    /// exactly the names [`crate::id::valid_name`] refuses — so the two cannot
    /// disagree about which manifest paths the crate must never touch.
    #[test]
    fn the_manifest_path_authority_agrees_with_the_id_rule() {
        for path in [
            "state/operation.lock",
            "operation.lock",
            "OPERATION.LOCK",
            "nested/Operation.Lock",
            "snapshots/.001.operation.lock",
            ".DESTROOT.OPERATION.LOCK",
            ".SYNC-ASIDE.1",
        ] {
            assert!(
                is_unaddressable_path(path),
                "{path:?} must be unaddressable as a manifest path"
            );
            let final_name = path.rsplit('/').next().unwrap();
            assert!(
                is_unaddressable_name(final_name),
                "the path-level answer is the name authority's: {final_name:?}"
            );
        }
        // The byte-exact family is deliberately NARROWER: the application lock
        // record is not a byte-exact reserved spelling, so a caller that needs
        // the historical match still gets it.
        assert!(!is_reserved_path("state/operation.lock"));
        assert!(is_reserved_path("snapshots/.001.operation.lock"));
        // Every spelling the id rule accepts is NOT unaddressable as a path.
        for ok in ["s1", "production", "a/b/operation.lock.txt"] {
            assert!(!is_unaddressable_path(ok), "{ok:?} is ordinary");
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
    /// (so every mutating primitive can refuse them) without turning the
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

    /// G5: a trailing dot or space is stripped by Win32 from the final
    /// component of a short absolute drive path, so `operation.lock.` and
    /// `operation.lock` are the SAME entry on Windows and the predicate must
    /// fold the trailing dot/space (harmless on macOS/Linux, where a trailing
    /// dot is a genuinely distinct name). The on-disk Windows behaviour cannot
    /// be exercised here; THIS pins the predicate-level rule.
    #[test]
    fn lock_record_names_fold_trailing_dots_and_spaces() {
        for lock in [
            "operation.lock.",
            "operation.lock ",
            "operation.lock. . ",
            "OPERATION.LOCK.",
            ".001.operation.lock.",
            ".001.operation.lock ",
        ] {
            assert!(
                is_lock_record_name(lock),
                "{lock:?} aliases a lock record once the Win32 trailing dot/space is folded"
            );
        }
        // A genuinely distinct spelling — the dot/space is not trailing — is
        // left ordinary.
        for other in [
            "operation.lock.x",
            "operation.lock! ",
            ".operation.lock.",
            "operation. lock",
        ] {
            assert!(
                !is_lock_record_name(other),
                "{other:?} does not name a lock record"
            );
        }
    }

    /// FLIPPED, EXPLICITLY: the test that lived here asserted that
    /// `state/operation.lock.` / `state/operation.lock ` / `state/OPERATION.LOCK`
    /// were "the same record" as `state/operation.lock` because the lock-record
    /// fold maps them together. That is the UNSAFE half of the old rule — a fold
    /// is sound for REFUSING a spelling but unsound for GRANTING ownership, and
    /// on macOS/Linux a trailing-dot spelling is a DISTINCT on-disk entry, so the
    /// old assertion pinned the very two-holder hole. The permission predicate
    /// [`is_same_lock_record_path`] is removed; ownership is decided by identity
    /// in [`crate::atomic::OwnedLockRecord::owns`]. What survives from the old
    /// test, correctly, is the DENIAL fold, restated below. Removing the old
    /// assertion is not a coverage loss: the on-disk identity behaviour is pinned
    /// by `transport::tests::remove_file_if_grants_ownership_only_to_the_owned_inode`
    /// on both platforms, and the denial fold by `is_lock_record_name` here.
    #[test]
    fn lock_record_recognition_folds_for_denial_only() {
        // Denial: every case/trailing-dot/space alias of a lock record is
        // recognised as one and therefore refused by the guard. This is the
        // surviving, correct use of the fold.
        for denied in [
            "state/operation.lock",
            "state/OPERATION.LOCK",
            "STATE/Operation.Lock",
            "state/operation.lock.",
            "state/operation.lock ",
            "state/OPERATION.LOCK. ",
        ] {
            assert!(
                Path::new(denied)
                    .components()
                    .all(|c| matches!(c, Component::Normal(_))),
                "sanity: the denial spellings are plain relative paths"
            );
            let last = Path::new(denied)
                .components()
                .next_back()
                .and_then(|c| match c {
                    Component::Normal(n) => n.to_str(),
                    _ => None,
                })
                .expect("a final component");
            assert!(
                is_lock_record_name(last),
                "{denied:?} must be REFUSED as a lock-record spelling (denial fold)"
            );
        }
        // Near-misses stay ordinary, so the fold does not over-refuse. (The
        // DENIAL predicate is per final component; `operation.lock` itself IS
        // the application lock record and is correctly in the denied list
        // above, so it is not a near-miss here.)
        for ordinary in [
            "state/op.lock",
            "state/operation.lockx",
            "state/operation.locked",
            "x.operation.lock",
            ".operation.lock",
            ".operation.lock.",
        ] {
            let last = Path::new(ordinary)
                .components()
                .next_back()
                .and_then(|c| match c {
                    Component::Normal(n) => n.to_str(),
                    _ => None,
                })
                .expect("a final component");
            assert!(
                !is_lock_record_name(last),
                "{ordinary:?} is not a lock-record spelling"
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
