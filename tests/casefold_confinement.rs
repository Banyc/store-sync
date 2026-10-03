//! H1 and the fold-ORDER fix through the public API: a case-insensitive
//! DESTINATION must not be able to resolve a source link's target component
//! onto a destination symlink the source view never saw.
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
//!
//! ORDER fix (this revision): the fold then took its input to NFC *before*
//! case-folding, but Unicode caseless matching is NFD-based. That under-folded
//! exactly the three Greek precomposed perispomeni+ypogegrammeni forms
//! (U+1FB7/U+1FC7/U+1FF7) whose canonically-related capital spellings
//! (U+1FBC U+0342, U+1FCC U+0342, U+1FFC U+0342, and the fully decomposed
//! U+0391/U+0397/U+03A9 U+0342 U+0345 family) a folding host resolves onto the
//! same entry. The fold now runs `NFD -> case_fold -> NFC`, so both spellings
//! merge and every view refuses. The `greek_*` tests below fail on the parent
//! revision.

#![cfg(unix)]

use store_sync::env::SysEnv;
use store_sync::manifest::{
    canonicalize_remote_entries, canonicalize_tree, remote_tree_verify_script,
};
use store_sync::sync::{ReplaceAll, push};
use store_sync::transport::{Layout, LocalTransport};

/// Run the production remote manifest script and return its raw listing.
fn remote_listing(root: &std::path::Path) -> String {
    let out = std::process::Command::new("perl")
        .args(["-e", remote_tree_verify_script()])
        .arg(root)
        .output()
        .expect("perl must run");
    assert!(
        out.status.success(),
        "remote script failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Whether THIS filesystem resolves `written` and `spelled` onto the SAME
/// entry (probed with a real write and a cross-spelling lookup, never a
/// platform guess).
fn host_folds_pair(written: &str, spelled: &str) -> bool {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(written), b"probe").unwrap();
    std::fs::symlink_metadata(dir.path().join(spelled)).is_ok()
}

/// Build the destination-only escape shape for a full-case-fold pair and
/// require the SOURCE manifest to ACCEPT the tree while `push` REFUSES it,
/// with the canary unreachable.
///
/// PRE-FIX, when the fold missed the pair, `push` returned `Ok`; the test then
/// READS the destination canary and panics with the leaked bytes, so the escape
/// is observed rather than merely asserted.
fn push_refuses_a_destination_only_fold_escape(on_disk: &str, spelled: &str) {
    let base = tempfile::tempdir().expect("tempdir");
    let src = base.path().join("src");
    let dst = base.path().join("dst");

    // The source holds ONLY the escaping link; `dir/<on_disk>` is absent.
    std::fs::create_dir_all(src.join("dir")).unwrap();
    std::os::unix::fs::symlink(format!("{spelled}/../../outside"), src.join("dir/link")).unwrap();

    // The SOURCE alone is lawful: the spelled component has no source entry.
    canonicalize_tree(&src)
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
    let outcome = push(&src, &transport, &ReplaceAll);
    if outcome.is_ok() {
        let leaked = std::fs::read(dst.join("dir/link/secret"));
        panic!(
            "PRE-FIX ESCAPE OBSERVED for on_disk={on_disk:?} spelled={spelled:?}: the push was \
             ACCEPTED and the destination canary reads {leaked:?}"
        );
    }
    let err = outcome.expect_err(
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

/// A SOURCE-held escape: `dir/<on_disk> -> ../other` (a real symlink the source
/// manifest SEES) plus `dir/link -> <spelled>/../../outside`. On a host that
/// folds `<spelled>` onto `<on_disk>` the resolution walks the symlink and
/// leaves the root, so the LOCAL walk, the WIRE assembler, and `push` (whose
/// canonicalizer IS the source walk) must all refuse naming `<spelled>`, and
/// the DESTINATION canary must stay unreachable. PRE-FIX all three accepted and
/// `push` installed the link; this helper then READS the destination canary and
/// panics with the leaked bytes.
fn source_escape_refused_by_all_views(on_disk: &str, spelled: &str) {
    let base = tempfile::tempdir().expect("tempdir");
    let root = base.path().join("R");
    std::fs::create_dir_all(root.join("dir")).unwrap();
    std::fs::create_dir_all(root.join("other")).unwrap();
    std::fs::write(root.join("other/file"), b"inside").unwrap();
    std::fs::create_dir_all(base.path().join("outside")).unwrap();
    std::fs::write(base.path().join("outside/secret"), b"SECRET").unwrap();
    std::os::unix::fs::symlink("../other", root.join("dir").join(on_disk)).unwrap();
    std::os::unix::fs::symlink(format!("{spelled}/../../outside"), root.join("dir/link")).unwrap();

    if host_folds_pair(on_disk, spelled) {
        assert_eq!(
            std::fs::read(root.join("dir/link/secret")).unwrap(),
            b"SECRET",
            "the escape must be REAL on this host for this test to mean anything"
        );
    }

    let local = canonicalize_tree(&root);
    let remote = canonicalize_remote_entries(&remote_listing(&root), &root);
    let dst = base.path().join("dst");
    let transport =
        LocalTransport::new(&SysEnv::from_process(), dst.clone(), Layout::empty()).expect("build");
    let pushed = push(&root, &transport, &ReplaceAll);

    if local.is_ok() || remote.is_ok() || pushed.is_ok() {
        panic!(
            "PRE-FIX ESCAPE OBSERVED for on_disk={on_disk:?} spelled={spelled:?}: local_ok={} \
             wire_ok={} push_ok={} destination_canary={:?}",
            local.is_ok(),
            remote.is_ok(),
            pushed.is_ok(),
            std::fs::read(dst.join("dir/link/secret"))
        );
    }

    // `Debug`-escape the spelling the same way the refusal message does
    // (grapheme-extending U+0342/U+0345 become `\u{...}`).
    let escaped: String = spelled.chars().flat_map(|c| c.escape_debug()).collect();
    let local_msg = local.unwrap_err().to_string();
    assert!(
        local_msg.contains("escaping symlink") && local_msg.contains(&escaped),
        "the local walk must refuse and name {spelled:?}, got: {local_msg}"
    );
    let remote_msg = remote.unwrap_err().to_string();
    assert!(
        remote_msg.contains("escaping symlink") && remote_msg.contains(&escaped),
        "the wire assembler must refuse and name {spelled:?}, got: {remote_msg}"
    );
    let push_msg = pushed.unwrap_err().to_string();
    assert!(
        push_msg.contains("escaping symlink") && push_msg.contains(&escaped),
        "push must refuse the source escape and name {spelled:?}, got: {push_msg}"
    );
    assert!(
        std::fs::read(dst.join("dir/link/secret")).is_err(),
        "the destination canary must be unreachable after the refused push"
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

/// ORDER fix, `U+1FB7` (small alpha with perispomeni and ypogegrammeni): both
/// capital witness spellings through the LOCAL walk, the WIRE assembler, and
/// `push`.
#[test]
fn greek_alpha_perispomeni_ypogegrammeni_escape_is_refused_by_all_views() {
    for capital in ["\u{1fbc}\u{0342}", "\u{0391}\u{0342}\u{0345}"] {
        source_escape_refused_by_all_views("\u{1fb7}", capital);
    }
}

/// ORDER fix, `U+1FC7` (small eta form): both capital witness spellings.
#[test]
fn greek_eta_perispomeni_ypogegrammeni_escape_is_refused_by_all_views() {
    for capital in ["\u{1fcc}\u{0342}", "\u{0397}\u{0342}\u{0345}"] {
        source_escape_refused_by_all_views("\u{1fc7}", capital);
    }
}

/// ORDER fix, `U+1FF7` (small omega form): both capital witness spellings.
#[test]
fn greek_omega_perispomeni_ypogegrammeni_escape_is_refused_by_all_views() {
    for capital in ["\u{1ffc}\u{0342}", "\u{03a9}\u{0342}\u{0345}"] {
        source_escape_refused_by_all_views("\u{1ff7}", capital);
    }
}

/// ORDER fix, the destination result-view preflight for all three Greek pairs
/// in both capital witness spellings: the destination holds the small-form
/// symlink, the source spells the capital form, and once the link is installed
/// the kernel walks through the surviving destination symlink and leaves the
/// root. `push` must refuse via the destination preflight, the link must never
/// be installed, and the canary must stay unreachable.
#[test]
fn greek_pairs_through_the_destination_preflight_and_push() {
    for (on_disk, spelled) in [
        ("\u{1fb7}", "\u{1fbc}\u{0342}"),
        ("\u{1fb7}", "\u{0391}\u{0342}\u{0345}"),
        ("\u{1fc7}", "\u{1fcc}\u{0342}"),
        ("\u{1fc7}", "\u{0397}\u{0342}\u{0345}"),
        ("\u{1ff7}", "\u{1ffc}\u{0342}"),
        ("\u{1ff7}", "\u{03a9}\u{0342}\u{0345}"),
    ] {
        push_refuses_a_destination_only_fold_escape(on_disk, spelled);
    }
}
