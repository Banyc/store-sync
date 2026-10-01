//! The validated relative path that crosses the transport boundary.
//!
//! Every path a [`Remote`](crate::transport::Remote) operation
//! receives is a [`RootedRelativePath`]: validated at construction to reject
//! ABSOLUTE paths, `.`/`..` components, and EMPTY paths, so a transport's
//! `root.join(rel)` is safe by construction — a caller can never escape the
//! deployment root through a transport operation, and a traversal path can
//! never be joined onto the root.
//!
//! The type deliberately carries NO `Default` (an empty path would be an
//! unrooted path constructible by anyone — the exact gap this hardening
//! closes) and NO `From<PathBuf>`/`From<&Path>` (a raw path must pass the
//! validated [`RootedRelativePath::parse`] — or the safe-by-construction
//! internal [`RootedRelativePath::from_validated`] used by the layout
//! builders, whose components are validated identities).

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

/// A validated RELATIVE path that stays inside the deployment root: never
/// empty, never absolute, and free of `.`/`..` components. A caller-supplied
/// [`Layout`](crate::transport::Layout) produces these from validated
/// identities; every path that crosses the
/// [`Remote`](crate::transport::Remote) trait boundary is one, so
/// `root.join(rel)` in a transport is safe by construction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RootedRelativePath(PathBuf);

impl RootedRelativePath {
    /// Validate `p` and construct. Rejects: an EMPTY path, an ABSOLUTE path,
    /// and any `.`/`..` component at any position (a traversal path can never
    /// cross the boundary).
    pub fn parse(p: &Path) -> Result<RootedRelativePath> {
        if p.as_os_str().is_empty() {
            return Err(Error::transport(format!(
                "invalid relative path {:?}: the path must not be empty",
                p
            )));
        }
        if p.is_absolute() {
            return Err(Error::transport(format!(
                "invalid relative path {:?}: absolute paths are not allowed",
                p
            )));
        }
        // Reject ANY traversal component (`.` or `..`) at ANY position.
        // `Path::components()` skips `.` segments, so the raw split is used
        // to catch them.
        for segment in p.to_string_lossy().split('/') {
            if segment == "." || segment == ".." {
                return Err(Error::transport(format!(
                    "invalid relative path {:?}: traversal components (`.`/`..`) are not allowed",
                    p
                )));
            }
        }
        Ok(RootedRelativePath(p.to_path_buf()))
    }

    /// Internal constructor for paths whose components are VALIDATED
    /// IDENTITIES (the layout builders) — the caller proves safety by
    /// construction: a validated identifier is a single safe path segment,
    /// so the built path is relative and traversal-free. Production callers
    /// must construct through the validated [`RootedRelativePath::parse`].
    pub(crate) fn from_validated(p: PathBuf) -> RootedRelativePath {
        RootedRelativePath(p)
    }

    /// The validated relative path.
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Join `component` onto this path and RE-VALIDATE the result: the
    /// joined path must still be relative and traversal-free (an absolute
    /// component or a `.`/`..` component is rejected).
    pub fn join(&self, component: impl AsRef<Path>) -> Result<RootedRelativePath> {
        RootedRelativePath::parse(&self.0.join(component))
    }

    /// The final component of the path, if any.
    pub fn file_name(&self) -> Option<&std::ffi::OsStr> {
        self.0.file_name()
    }

    /// The parent directory of the path, if any. `None` when the path has no
    /// parent that is itself a valid rooted relative path (a single-component
    /// path's parent is the empty path, which is not a valid
    /// [`RootedRelativePath`]).
    pub fn parent(&self) -> Option<RootedRelativePath> {
        self.0
            .parent()
            .and_then(|p| RootedRelativePath::parse(p).ok())
    }

    /// Replace the final component, re-validating the result.
    pub fn with_file_name(&self, name: impl AsRef<std::ffi::OsStr>) -> Result<RootedRelativePath> {
        RootedRelativePath::parse(&self.0.with_file_name(name))
    }

    /// The display form of the underlying path (for error messages).
    pub fn display(&self) -> std::path::Display<'_> {
        self.0.display()
    }
}

impl AsRef<Path> for RootedRelativePath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl std::fmt::Display for RootedRelativePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    /// The boundary rule: a validated relative path accepts every safe
    /// relative form and rejects every unsafe one (empty, absolute, `.`/`..`
    /// at any position).
    #[test]
    fn parse_accepts_safe_rejects_unsafe() {
        for ok in [
            "a",
            "a/b",
            "a/b/c.json",
            "generations/gen-1/assignment.json",
            "objects/sha256/abc/root",
            "a//b",
            "a/",
        ] {
            let p = RootedRelativePath::parse(Path::new(ok))
                .unwrap_or_else(|e| panic!("{ok:?} must parse: {e}"));
            assert_eq!(p.as_path(), Path::new(ok));
        }
        for bad in [
            "",
            "/",
            "//",
            "/abs",
            "/abs/rel",
            ".",
            "..",
            "./a",
            "a/.",
            "a/..",
            "../a",
            "a/../b",
            "a/b/../../c",
            "/a/../b",
        ] {
            assert!(
                RootedRelativePath::parse(Path::new(bad)).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    /// Joining re-validates: a safe component joins, an absolute or
    /// traversal component is rejected.
    #[test]
    fn join_revalidates() {
        let base = RootedRelativePath::parse(Path::new("a/b")).unwrap();
        assert_eq!(
            base.join("c.json").unwrap().as_path(),
            Path::new("a/b/c.json")
        );
        for bad in ["/abs", "..", "../x", ".", "/"] {
            base.join(bad)
                .expect_err(&format!("{bad:?} must be rejected"));
        }
    }

    /// Arbitrary untyped path text covering every unsafe class: empty,
    /// absolute, `.`/`..` at any position, separators, whitespace, unicode,
    /// control characters, and clean safe relative values.
    fn arbitrary_path_text() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                String::new(),
                "/".to_string(),
                "//".to_string(),
                "/abs".to_string(),
                "/abs/rel".to_string(),
                ".".to_string(),
                "..".to_string(),
                "./a".to_string(),
                "a/.".to_string(),
                "a/..".to_string(),
                "../a".to_string(),
                "a/../b".to_string(),
                "a/b/../../c".to_string(),
                "/a/../b".to_string(),
                "a".to_string(),
                "a/b".to_string(),
                "a/b/c.json".to_string(),
                "generations/gen-1/assignment.json".to_string(),
                "objects/sha256/abc/root".to_string(),
                "a//b".to_string(),
                "a/".to_string(),
                " x".to_string(),
                "x ".to_string(),
                "a\nb".to_string(),
                "α".to_string(),
                "a\u{0}b".to_string(),
            ]),
            prop::collection::vec(prop::char::any(), 0..48).prop_map(|v| v.into_iter().collect()),
        ]
    }

    proptest! {
        // THE BOUNDARY PROPERTY: over ARBITRARY untyped path text, the
        // validated parse accepts EXACTLY the safe relative forms and
        // rejects every unsafe one — a path that parses is relative,
        // non-empty, and free of `.`/`..` components; a path that is
        // rejected is absolute, empty, or traversal-bearing. Bounded 16
        // cases, fixed seed 0x5EED_5EED (house style), no failure
        // persistence.
        #![proptest_config(ProptestConfig {
            cases: crate::test_support::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn arbitrary_untyped_paths_are_rejected_or_safe(s in arbitrary_path_text()) {
            let p = Path::new(&s);
            match RootedRelativePath::parse(p) {
                Ok(r) => {
                    // A path that parses is SAFE: relative, non-empty, and
                    // every component is a NORMAL component (no `.`/`..`,
                    // no root).
                    prop_assert!(!r.as_path().is_absolute(), "{s:?} must not be absolute");
                    prop_assert!(!r.as_path().as_os_str().is_empty(), "{s:?} must not be empty");
                    for c in r.as_path().components() {
                        prop_assert!(
                            matches!(c, std::path::Component::Normal(_)),
                            "{s:?} has an unsafe component {:?}",
                            c
                        );
                    }
                }
                Err(_) => {
                    // A path that is rejected is UNSAFE: absolute, empty, or
                    // traversal-bearing (`.`/`..` at some position).
                    let unsafe_class = p.is_absolute()
                        || p.as_os_str().is_empty()
                        || s.split('/').any(|seg| seg == "." || seg == "..");
                    prop_assert!(
                        unsafe_class,
                        "rejected path {s:?} must be absolute, empty, or traversal-bearing"
                    );
                }
            }
        }
    }
}
