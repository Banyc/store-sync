//! The SEALED filesystem-ownership root ([`OwnedRoot`]): the canonical,
//! non-root, non-symlink directory a store owns, registered per resolved
//! endpoint so two owners can never overlap.
//!
//! Filesystem ownership is LEXICAL today: two stores (or two deployment
//! roots) can be created on the same directory, or on ancestor/descendant
//! directories of each other, and nothing rejects it — two owners over
//! overlapping state. The [`OwnedRoot`] closes that class:
//!
//! * **Sealed** — the fields are private and there is NO unchecked
//!   constructor; the ONLY construction path is [`OwnedRoot::parse`], which
//!   canonicalizes the path, rejects the filesystem root, and rejects a
//!   symlink root (the root must be a REAL directory, not a symlink).
//! * **Overlap refusal** — two [`OwnedRoot`]s on the same resolved endpoint
//!   (the physical host identity; for the local store the `local` marker)
//!   with EQUAL canonical roots, or with one an ANCESTOR/DESCENDANT of the
//!   other, are refused at construction — before any filesystem mutation.
//!   The refusal happens against the process-global ownership registry, and
//!   the registration is released when the owning [`OwnedRoot`] (and the
//!   store holding it) is dropped: two SIMULTANEOUS owners over overlapping
//!   state are refused, while a released root can be re-owned.
//!
//! The store's mutations are additionally descriptor-relative (see
//! [`crate::atomic`]'s `_fd` primitives): every mutation resolves
//! paths component-wise relative to the owned root's open directory
//! descriptor with `openat(O_NOFOLLOW)`, so a symlink injected into a path
//! component can never redirect a mutation outside the owned root.

use crate::error::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The physical host identity of a filesystem-ownership endpoint: a single
/// filesystem-safe ASCII token — non-empty, no path separators, no
/// whitespace or control characters — or the constant `local` marker for a
/// pathless local connection. This is the minimal domain-free stand-in for
/// the source application's `crate::identity::EndpointKey` (see
/// `EXTRACTION.md` slice-root): the ownership registry only needs a value
/// that identifies the endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EndpointKey(String);

impl EndpointKey {
    /// Validate the endpoint token (non-empty, no separators, no whitespace
    /// or control characters) and construct the key. The gate makes an
    /// invalid endpoint unconstructible.
    pub fn parse(s: &str) -> Result<EndpointKey> {
        let ok = !s.is_empty()
            && !s.contains('/')
            && !s.contains('\\')
            && !s.chars().any(|c| c.is_control() || c.is_whitespace());
        if !ok {
            return Err(Error::r#ref(format!(
                "invalid endpoint {:?}: must be a non-empty token with no separators, whitespace, or control characters",
                s
            )));
        }
        Ok(EndpointKey(s.to_string()))
    }

    /// The validated endpoint token.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EndpointKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The constant endpoint marker of the pathless LOCAL connection kind: a
/// local server has no SSH address, so its physical host identity is the
/// local marker itself and the deploy_dir is the sole physical root.
pub const LOCAL_ENDPOINT_MARKER: &str = "local";

/// THE overlap rule: whether two CANONICAL directories are EQUAL or one is an
/// ANCESTOR or DESCENDANT of the other. This is the SINGLE definition of the
/// overlap [`OwnedRoot::parse`] refuses; any caller that must relate two roots
/// (the sync's source and destination, say) reuses THIS predicate rather than
/// writing a second comparison, so the two can never drift apart. The
/// comparison is component-wise ([`Path::starts_with`]), so `a/bc` is not
/// treated as a descendant of `a/b`.
pub(crate) fn roots_overlap(a: &Path, b: &Path) -> bool {
    a == b || a.starts_with(b) || b.starts_with(a)
}

/// The process-global ownership registry: for each resolved endpoint, the
/// set of canonical roots currently owned by a LIVE [`OwnedRoot`]. A root
/// is registered at [`OwnedRoot::parse`] and released when the LAST live
/// [`OwnedRoot`] clone is dropped (the registration is REFCOUNTED — clones
/// share one registration token, so the registration is released exactly
/// once, when the last clone drops) — two SIMULTANEOUS owners over equal or
/// ancestor/descendant roots on the same endpoint are refused, while a
/// released root can be re-owned.
static OWNED_ROOTS: Mutex<BTreeMap<EndpointKey, BTreeSet<PathBuf>>> = Mutex::new(BTreeMap::new());

/// THE SEALED filesystem-ownership root: a canonical, non-root, non-symlink
/// directory, owned on one resolved endpoint. Private fields; the ONLY
/// construction path is [`OwnedRoot::parse`], which canonicalizes the path,
/// rejects the filesystem root and symlink roots, and refuses to register a
/// root that equals — or is an ancestor or descendant of — an already-owned
/// root on the same endpoint. The registration is REFCOUNTED: clones share
/// one registration token, and the registration is released when the LAST
/// clone is dropped (a root can be shared — e.g. every provisioned slot of
/// a validated project is bound to the project's store root — without
/// releasing the ownership while any clone is alive).
#[derive(Clone, Debug)]
pub struct OwnedRoot {
    /// The canonical, non-root, non-symlink directory.
    canonical: PathBuf,
    /// The resolved endpoint this root is owned on.
    endpoint: EndpointKey,
    /// The REFCOUNTED registration token: the registration is released when
    /// the LAST clone of this root drops (clones share the token). This
    /// field is a KEEP-ALIVE token — clones share the [`Arc`], and the
    /// release happens in the token's own `Drop` (never by reading this
    /// field), so the field is intentionally never read directly.
    #[allow(dead_code)] // keep-alive token: its Drop releases the ownership registration
    registration: Arc<OwnedRootRegistration>,
}

/// The refcounted registration token: holds the (endpoint, canonical)
/// pair whose registration it releases on the LAST drop.
#[derive(Debug)]
struct OwnedRootRegistration {
    endpoint: EndpointKey,
    canonical: PathBuf,
}

impl Drop for OwnedRootRegistration {
    fn drop(&mut self) {
        let mut registry = OWNED_ROOTS.lock().unwrap();
        if let Some(owned) = registry.get_mut(&self.endpoint) {
            owned.remove(&self.canonical);
            if owned.is_empty() {
                registry.remove(&self.endpoint);
            }
        }
    }
}

impl OwnedRoot {
    /// The local store's resolved endpoint: the `local` marker (the
    /// pathless local connection kind's physical host identity).
    pub fn local_endpoint() -> Result<EndpointKey> {
        EndpointKey::parse(LOCAL_ENDPOINT_MARKER)
    }

    /// Construct the owned root from a canonical, non-root, non-symlink
    /// directory on `endpoint`. The path must EXIST (canonicalization
    /// requires it); the directory must not be the filesystem root and must
    /// not be a symlink; and the canonical root must not equal — nor be an
    /// ancestor or descendant of — any already-owned root on the same
    /// endpoint. The refusal happens HERE, before any filesystem mutation
    /// (this constructor only reads and updates the in-memory registry).
    pub fn parse(endpoint: &EndpointKey, path: &Path) -> Result<OwnedRoot> {
        // The root must be a REAL directory, not a symlink: the final
        // component of the given path must not be a symlink (a symlink
        // root would let a later swap redirect the whole store).
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| Error::store(format!("stat {}: {e}", path.display())))?;
        if meta.file_type().is_symlink() {
            return Err(Error::store(format!(
                "refusing to own {}: the root must be a real directory, not a symlink",
                path.display()
            )));
        }
        if !meta.is_dir() {
            return Err(Error::store(format!(
                "refusing to own {}: the root must be a directory",
                path.display()
            )));
        }
        // Canonicalize: resolve every symlink in the path (intermediate
        // components included) to the real directory.
        let canonical = std::fs::canonicalize(path)
            .map_err(|e| Error::store(format!("canonicalize {}: {e}", path.display())))?;
        // Reject the filesystem root: a store can never own `/`.
        if canonical.parent().is_none() {
            return Err(Error::store(format!(
                "refusing to own {}: the filesystem root is not an ownable directory",
                canonical.display()
            )));
        }
        // Reject overlap on the same endpoint: equal, ancestor, or
        // descendant roots are refused (two owners over overlapping state).
        let mut registry = OWNED_ROOTS.lock().unwrap();
        if let Some(owned) = registry.get(endpoint) {
            for existing in owned {
                if roots_overlap(&canonical, existing) {
                    return Err(Error::store(format!(
                        "refusing to own {}: it overlaps the already-owned root {} on endpoint {}",
                        canonical.display(),
                        existing.display(),
                        endpoint.as_str()
                    )));
                }
            }
        }
        registry
            .entry(endpoint.clone())
            .or_default()
            .insert(canonical.clone());
        Ok(OwnedRoot {
            canonical: canonical.clone(),
            endpoint: endpoint.clone(),
            registration: Arc::new(OwnedRootRegistration {
                endpoint: endpoint.clone(),
                canonical,
            }),
        })
    }

    /// The canonical owned directory.
    pub fn canonical(&self) -> &Path {
        &self.canonical
    }

    /// The resolved endpoint this root is owned on.
    pub fn endpoint(&self) -> &EndpointKey {
        &self.endpoint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;
    use std::path::PathBuf;

    /// A unique endpoint per proptest case: derived from the generated tag,
    /// so the process-global registry never accumulates across cases and
    /// never collides with another test's endpoint (the store's `local`
    /// marker, or another case's tag).
    fn case_endpoint(tag: &str) -> EndpointKey {
        EndpointKey::parse(&format!("local-{tag}")).expect("a clean tag is a valid endpoint")
    }

    /// Snapshot the directory tree under `root` (every entry path, sorted)
    /// so a test can assert a refused registration created or deleted
    /// NOTHING. Symlinks are listed as entries, never followed.
    fn tree_snapshot(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let p = entry.path();
                out.push(p.clone());
                if entry.file_type().unwrap().is_dir() {
                    walk(&p, out);
                }
            }
        }
        walk(root, &mut out);
        out.sort();
        out
    }

    // -------------------------------------------------------------------
    // THE OWNERSHIP-REFUSAL PROPERTY (the review's acceptance): generate
    // EQUAL, NESTED (ancestor/descendant), TRAVERSAL (`..`), `/`, and
    // SYMLINK-INJECTED candidate roots against a first owned root; EVERY
    // candidate must be refused at construction, and the refusal must
    // happen BEFORE creating or deleting anything (the directory tree is
    // byte-for-byte unchanged after each failed construction). Bounded
    // `proptest_cases(16)` (full 16 with `STORE_SYNC_FULL_TESTS=1`, fast
    // default), fixed seed 0x5EED_5EED (house style), no persistence.
    // -------------------------------------------------------------------
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: crate::test_support::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn overlapping_roots_are_refused_before_any_mutation(tag in "[a-z0-9]{1,8}") {
            let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
            let root = dir.path().join("owned");
            std::fs::create_dir_all(&root).unwrap();
            let endpoint = case_endpoint(&tag);
            // The FIRST root is owned and stays alive for the whole case.
            let first = OwnedRoot::parse(&endpoint, &root).unwrap();
            assert_eq!(
                first.canonical(),
                std::fs::canonicalize(&root).unwrap(),
                "the owned root is the canonical directory"
            );

            // The candidate roots: equal, nested (child), nested (parent),
            // traversal (`..` — canonicalizes to the owned root), the
            // filesystem root, and symlink-injected (a final-component
            // symlink, and an intermediate-component symlink resolving to a
            // descendant of the owned root).
            let child = root.join("child");
            std::fs::create_dir_all(&child).unwrap();
            let parent = root.parent().unwrap().to_path_buf();
            let traversal = root.join("..").join(root.file_name().unwrap());
            let symlink_final = dir.path().join("link-final");
            std::os::unix::fs::symlink(&root, &symlink_final).unwrap();
            let symlink_mid = dir.path().join("link-mid");
            std::os::unix::fs::symlink(&root, &symlink_mid).unwrap();
            let symlink_child = symlink_mid.join("child");

            let before = tree_snapshot(dir.path());

            for candidate in [
                root.clone(),          // equal
                child.clone(),         // nested (descendant)
                parent.clone(),        // nested (ancestor)
                traversal,             // traversal -> equal after canonicalize
                PathBuf::from("/"),    // the filesystem root
                symlink_final,         // symlink root (final component)
                symlink_child,         // symlink-injected intermediate -> descendant
            ] {
                let res = OwnedRoot::parse(&endpoint, &candidate);
                assert!(
                    res.is_err(),
                    "candidate {:?} must be refused on endpoint {}",
                    candidate,
                    endpoint.as_str()
                );
            }

            // EVERY refusal happened BEFORE creating or deleting anything:
            // the directory tree is unchanged.
            assert_eq!(
                tree_snapshot(dir.path()),
                before,
                "a refused root must not create or delete anything"
            );
        }
    }

    /// A symlink root is refused at construction (the root must be a real
    /// directory, not a symlink), and the filesystem root is refused.
    #[test]
    fn symlink_and_filesystem_roots_are_refused() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let endpoint = case_endpoint("symlink-root");
        let err = OwnedRoot::parse(&endpoint, &link).expect_err("a symlink root must be refused");
        assert!(
            err.to_string().contains("not a symlink"),
            "the refusal must name the symlink rule, got: {err}"
        );
        let err = OwnedRoot::parse(&endpoint, Path::new("/"))
            .expect_err("the filesystem root must be refused");
        assert!(
            err.to_string().contains("filesystem root"),
            "the refusal must name the non-root rule, got: {err}"
        );
    }
}
