//! The validated relative path that crosses the transport boundary.
//!
//! Every path a [`Remote`](crate::transport::Remote) operation
//! receives is a [`RootedRelativePath`]: validated at construction to reject
//! ABSOLUTE paths, `.`/`..` components, and EMPTY paths, so a transport's
//! `root.join(rel)` is safe by construction — a caller can never escape the
//! deployment root through a transport operation, and a traversal path can
//! never be joined onto the root.
//!
//! The traversal/absolute decision is made with the PLATFORM's own path
//! model ([`Path::components`]) rather than a hardcoded separator, so a `\`
//! is a separator exactly where the platform says it is: on Windows
//! `..\escape` is a traversal and is refused, while on Unix it is one legal
//! filename byte and is accepted (this crate preserves the names of the
//! trees it manages; a Unix tree may legitimately contain it).
//!
//! The type deliberately carries NO `Default` (an empty path would be an
//! unrooted path constructible by anyone — the exact gap this hardening
//! closes) and NO `From<PathBuf>`/`From<&Path>` (a raw path must pass the
//! validated [`RootedRelativePath::parse`] — or the safe-by-construction
//! internal [`RootedRelativePath::from_validated`] used by the layout
//! builders, whose components are validated identities).

use crate::error::{Error, Result};
use std::path::{Component, Path, PathBuf};

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
    ///
    /// The traversal/absolute decision is made with the PLATFORM's own path
    /// model, [`Path::components`], never with a hardcoded `'/'`: only
    /// [`Component::Normal`] is admitted, so `RootDir`/`Prefix` (an absolute
    /// path, or a Windows `\`-root that `Path::join` uses to REPLACE the
    /// deployment root), `ParentDir`, and `CurDir` are all refused — and on
    /// Windows a `\` IS a separator, so `..\escape`, `\absolute`, and
    /// `a\..\b` are seen for what they are. On Unix a `\` is an ordinary
    /// filename byte, so those same spellings are each ONE literal component
    /// and are ACCEPTED: this crate preserves the names of the trees it
    /// manages, and refusing them would reject legal trees.
    ///
    /// [`Path::components`] also erases a `.` segment that is not at the
    /// start (`a/.`, `a/./b`), so the raw spelling is scanned as well for a
    /// literal `.` segment. That scan splits on [`std::path::is_separator`] —
    /// the same platform predicate [`Path::components`] uses — so it inherits
    /// the platform's separator model instead of introducing a second one.
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
        // The platform's component model is the ONE authority on what is a
        // traversal, a root, or a prefix. Anything that is not a plain name
        // is refused: `ParentDir` walks above the root; `RootDir`/`Prefix`
        // name an absolute location (and on Windows `Path::join` REPLACES
        // the base for a rooted/`\`-leading path, cancelling the deployment
        // root entirely); `CurDir` names a directory rather than an entry.
        if !p.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(Error::transport(format!(
                "invalid relative path {:?}: traversal components (`.`/`..`) and absolute paths are not allowed",
                p
            )));
        }
        // A non-leading `.` segment never reaches the loop above because
        // `Path::components` erases it, so refuse a literal `.` segment
        // textually too. The split uses the platform's separator predicate
        // (never a hardcoded '/'), so a `\`-bearing name is one segment on
        // Unix while Windows sees the `.`/`..` segment it really is.
        for segment in p.to_string_lossy().split(std::path::is_separator) {
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
                    // A path that is rejected is UNSAFE under the SAME
                    // platform component model `parse` uses: absolute, empty,
                    // any non-Normal component (`ParentDir`/`CurDir`/
                    // `RootDir`/`Prefix`), or a literal `.`/`..` segment on a
                    // platform separator (which `Path::components` would
                    // erase when it is a non-leading `.`). The classification
                    // must NOT hardcode '/': on Windows `..\x` is one
                    // `ParentDir`-bearing path even though it has no '/', and
                    // `s.split('/')` would miss it.
                    let unsafe_class = p.is_absolute()
                        || p.as_os_str().is_empty()
                        || p.components()
                            .any(|c| !matches!(c, std::path::Component::Normal(_)))
                        || s.split(std::path::is_separator)
                            .any(|seg| seg == "." || seg == "..");
                    prop_assert!(
                        unsafe_class,
                        "rejected path {s:?} must be absolute, empty, or traversal-bearing"
                    );
                }
            }
        }
    }

    /// The property the boundary exists for: for EVERY path [`RootedRelativePath::parse`]
    /// accepts, `root.join(rel)` cannot resolve outside `root`.
    ///
    /// THE ARGUMENT (lexical, and identical on every platform):
    /// `Path::join` either REPLACES the base — only when the joined path is
    /// absolute or carries a root/prefix — or APPENDS its components. `parse`
    /// refuses absolute paths, every non-`Normal` component, and every
    /// literal `.`/`..` segment, so an accepted `rel` contributes only plain
    /// names. Therefore the joined components are exactly the root's
    /// components followed by `Normal` names: no `..` can walk above the
    /// root and no root/prefix can reset it, so the resolved path stays
    /// strictly under the root.
    ///
    /// RUNS ON BOTH PLATFORMS. The Windows arm cannot be RUN here (Windows
    /// is type-checked only), so this pins the Unix behavior by construction
    /// and the Windows behavior by the same component-model argument; no
    /// runtime Windows claim is made.
    #[test]
    fn accepted_paths_join_cannot_escape_the_root() {
        let root = std::env::temp_dir().join("store-sync-rooted-join-property");
        // The accepted set is platform-specific: on Unix a `\` is an ordinary
        // name byte, so a `\`-bearing spelling is ONE legal component and
        // must be accepted (and must still not escape); on Windows those
        // spellings are traversal/root-bearing and `parse` REFUSES them, so
        // they are not in the accepted set there.
        #[cfg(unix)]
        let accepted = [
            "a",
            "a/b",
            "a/b/c.json",
            "a//b",
            "a/",
            "generations/gen-1/assignment.json",
            r"..\escape",
            r"a\..\b",
            r"\absolute",
            r"..\x",
        ];
        #[cfg(not(unix))]
        let accepted = [
            "a",
            "a/b",
            "a/b/c.json",
            "a//b",
            "a/",
            "generations/gen-1/assignment.json",
        ];

        for text in accepted {
            let rel = RootedRelativePath::parse(Path::new(text))
                .unwrap_or_else(|e| panic!("{text:?} must be accepted: {e}"));
            let joined = root.join(rel.as_path());

            // (1) The joined path is anchored at the root...
            assert!(
                joined.starts_with(&root),
                "{text:?}: {joined:?} must start with {root:?}"
            );
            // (2) ...the join APPENDED rather than replaced the base
            //     (component counts add up exactly)...
            assert_eq!(
                joined.components().count(),
                root.components().count() + rel.as_path().components().count(),
                "{text:?}: join must append to, not replace, the root"
            );
            // (3) ...and every appended component is a plain NAME, so none
            //     can walk above the root or reset it.
            let tail: Vec<std::path::Component> = joined
                .components()
                .skip(root.components().count())
                .collect();
            assert!(!tail.is_empty(), "{text:?}: the join contributed nothing");
            assert!(
                tail.iter()
                    .all(|c| matches!(c, std::path::Component::Normal(_))),
                "{text:?}: every appended component must be a Normal name, got {tail:?}"
            );
        }
    }

    /// UNIX: a backslash is an ordinary filename byte, NOT a separator, so a
    /// name that merely LOOKS like a traversal or an absolute path is ONE
    /// legal component and stays accepted — pinning this crate's name
    /// fidelity. The genuine unsafe spellings are still refused.
    ///
    /// THIS ARM RUNS HERE (macOS is Unix). The Windows arm below is compiled
    /// only on Windows and is NOT run in this environment.
    #[cfg(unix)]
    #[test]
    fn unix_backslash_is_an_ordinary_name_byte() {
        for ok in [r"..\escape", r"a\..\b", r"\absolute", r"..\x", r"a\b"] {
            let p = RootedRelativePath::parse(Path::new(ok))
                .unwrap_or_else(|e| panic!("{ok:?} is one legal Unix name and must parse: {e}"));
            assert_eq!(p.as_path(), Path::new(ok), "{ok:?} must round-trip");
            // Exactly one component, and it is a plain name.
            let comps: Vec<_> = p.as_path().components().collect();
            assert_eq!(comps.len(), 1, "{ok:?} must be a single component");
            assert!(matches!(comps[0], std::path::Component::Normal(_)));
        }
        // The same refusals as before: genuine `.`/`..` components (however
        // spelled with `/`), absolute paths, and the empty path.
        for bad in [
            "", ".", "..", "./a", "a/.", "a/..", "../a", "a/../b", "/", "/abs", "/a/../b",
        ] {
            assert!(
                RootedRelativePath::parse(Path::new(bad)).is_err(),
                "{bad:?} must still be refused on Unix"
            );
        }
    }

    /// WINDOWS (compiled only on Windows; NOT run in this environment —
    /// Windows is type-checked only, so this is an UNVERIFIED-at-runtime
    /// assertion, not a measured result): on Windows `\` IS a separator, so
    /// the platform component model sees the traversal/root and `parse`
    /// REFUSES these spellings that a hardcoded `'/'` split would miss.
    #[cfg(windows)]
    #[test]
    fn windows_backslash_is_a_separator_so_traversal_is_refused() {
        for bad in [r"..\x", r"\x", r"a\..\b", r".\a", r"a\."] {
            assert!(
                RootedRelativePath::parse(Path::new(bad)).is_err(),
                "{bad:?} must be refused on Windows"
            );
        }
        // And the ordinary relative spellings still parse.
        for ok in ["a", "a/b", r"a\b", r"a\b\c.json"] {
            RootedRelativePath::parse(Path::new(ok))
                .unwrap_or_else(|e| panic!("{ok:?} must parse on Windows: {e}"));
        }
    }

    /// UNIX: name fidelity end to end — a source file literally named
    /// `..\escape` (and `a\..\b`) round-trips through the filesystem as ONE
    /// directory entry, and `root.join(rel)` addresses exactly that entry.
    /// This is what would break if the fix refused backslash-bearing names.
    #[cfg(unix)]
    #[test]
    fn unix_backslash_name_round_trips_through_the_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        for name in [r"..\escape", r"a\..\b", r"\absolute"] {
            let rel = RootedRelativePath::parse(Path::new(name)).unwrap();
            let on_disk = dir.path().join(rel.as_path());
            std::fs::write(&on_disk, name.as_bytes()).unwrap();
            // Reading it back by the plain path proves the join addresses the
            // same entry the name denotes.
            assert_eq!(
                std::fs::read(dir.path().join(name)).unwrap(),
                name.as_bytes()
            );
            // It is exactly ONE entry whose name is the whole backslash-bearing
            // string — not `..` followed by `escape`.
            let entries: Vec<std::ffi::OsString> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert_eq!(entries, vec![std::ffi::OsString::from(name)], "{name:?}");
            std::fs::remove_file(&on_disk).unwrap();
        }
    }
}
