//! H1 through the public `sync` API: a case-insensitive DESTINATION must not
//! be able to resolve a source link's target component onto a destination
//! symlink the source view never saw.
//!
//! The source holds ONLY the escaping link (`dir/link -> STRASSE/../../outside`)
//! and does NOT hold `dir/straße`, so the strict SOURCE manifest accepts it (the
//! spelled `STRASSE` has no source entry). The destination already holds
//! `dir/straße -> ../other`, a destination-only entry that survives the run
//! (`push` is `Extraneous::Keep`). Once the link is installed, a
//! case-insensitive kernel resolves `STRASSE` onto that surviving symlink and
//! the link leaves the root. The destination result-view preflight
//! (`src/sync/apply.rs`) must refuse it, and the canary a sibling of the
//! destination root must stay unreachable.
//!
//! Before the fold fix the crate's containment fold was `str::to_lowercase`,
//! which does NOT map `STRASSE` to `straße` (nor `FILE` to `ﬁle`, nor `Σ` to
//! `ς`), so the preflight answered `Absent` and `push` returned `Ok`. The full
//! Unicode case fold matches them, so `push` now returns `Err`.

#![cfg(unix)]

use store_sync::env::SysEnv;
use store_sync::sync::{ReplaceAll, push};
use store_sync::transport::{Layout, LocalTransport};

/// Build the destination-only escape shape for a full-case-fold pair and
/// require the SOURCE manifest to ACCEPT the tree while `push` REFUSES it,
/// with the canary unreachable.
fn push_refuses_a_destination_only_fold_escape(on_disk: &str, spelled: &str) {
    let base = tempfile::tempdir().expect("tempdir");
    let src = base.path().join("src");
    let dst = base.path().join("dst");

    // The source holds ONLY the escaping link; `dir/<on_disk>` is absent.
    std::fs::create_dir_all(src.join("dir")).unwrap();
    std::os::unix::fs::symlink(format!("{spelled}/../../outside"), src.join("dir/link")).unwrap();

    // The SOURCE alone is lawful: the spelled component has no source entry.
    store_sync::manifest::canonicalize_tree(&src)
        .expect("the source alone must be accepted (the escaping component is destination-only)");

    // The destination holds the symlink the installed link would walk THROUGH.
    std::fs::create_dir_all(dst.join("dir")).unwrap();
    std::fs::create_dir_all(dst.join("other")).unwrap();
    std::fs::write(dst.join("other/file"), b"inside").unwrap();
    std::os::unix::fs::symlink("../other", dst.join("dir").join(on_disk)).unwrap();
    // The canary is a sibling of the destination root: the link's `..` after
    // the symlink component reaches the destination root's parent.
    std::fs::create_dir_all(base.path().join("outside")).unwrap();
    std::fs::write(base.path().join("outside/secret"), b"SECRET").unwrap();

    let transport =
        LocalTransport::new(&SysEnv::from_process(), dst.clone(), Layout::empty()).expect("build");
    let err = push(&src, &transport, &ReplaceAll).expect_err(
        "a push whose installed link would resolve through a destination symlink must be refused",
    );
    assert!(
        err.to_string()
            .contains("cannot be shown to stay inside the destination root"),
        "the refusal must be the destination result-view preflight, got: {err}"
    );
    assert!(
        !dst.join("dir/link").exists(),
        "the escaping link must never be installed"
    );
    assert!(
        std::fs::read(dst.join("dir/link/secret")).is_err(),
        "the canary must be unreachable after the refused push"
    );
}

/// H1, `ß`/`SS` through the destination preflight and `push`.
#[test]
fn push_refuses_a_sharp_s_destination_only_fold_escape() {
    push_refuses_a_destination_only_fold_escape("stra\u{df}e", "STRASSE");
}

/// H1, the `ﬁ`/`FI` ligature through the destination preflight and `push`.
#[test]
fn push_refuses_a_ligature_destination_only_fold_escape() {
    push_refuses_a_destination_only_fold_escape("\u{fb01}le", "FILE");
}

/// H1, final sigma through the destination preflight and `push`.
#[test]
fn push_refuses_a_final_sigma_destination_only_fold_escape() {
    push_refuses_a_destination_only_fold_escape("\u{3c2}", "\u{3a3}");
}

/// H1, the SOURCE side through the public API: when the source itself holds
/// the symlink component, the strict source manifest refuses and `push` returns
/// `Err`; the destination is untouched and the canary stays unreachable.
#[test]
fn push_refuses_a_source_contained_fold_escape() {
    let base = tempfile::tempdir().expect("tempdir");
    let src = base.path().join("src");
    let dst = base.path().join("dst");
    std::fs::create_dir_all(src.join("dir")).unwrap();
    std::fs::create_dir_all(src.join("other")).unwrap();
    std::fs::write(src.join("other/file"), b"inside").unwrap();
    std::os::unix::fs::symlink("../other", src.join("dir/stra\u{df}e")).unwrap();
    std::os::unix::fs::symlink("STRASSE/../../outside", src.join("dir/link")).unwrap();
    std::fs::create_dir_all(base.path().join("outside")).unwrap();
    std::fs::write(base.path().join("outside/secret"), b"SECRET").unwrap();

    let transport =
        LocalTransport::new(&SysEnv::from_process(), dst.clone(), Layout::empty()).expect("build");
    let err = push(&src, &transport, &ReplaceAll)
        .expect_err("a source that holds the fold-equal symlink component must be refused");
    assert!(
        err.to_string().contains("escaping symlink"),
        "the refusal must name the escape, got: {err}"
    );
    assert!(std::fs::read(dst.join("dir/link/secret")).is_err());
}
