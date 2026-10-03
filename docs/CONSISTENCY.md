# Consistency

A defect in this file is **two things that must agree, disagreeing**. That is the
whole method, and it is deliberately bounded: a disagreement is deterministic, so
it can be found by a sweep, decided by reading two definitions, and fixed without
enumerating the space around it.

**Out of scope by decision:** races, interleavings, and TOCTOU windows. They cost
unbounded effort to chase and produce findings that are stated residuals anyway.
Where one is known it is recorded as a residual with the window named, not
pursued. The identity-based overlap refusal is correct when it runs; a mount
installed between the check and the walk is that kind of residual.

## The axes

| # | Two things that must agree | Examples this has caught |
|---|---|---|
| A | a doc claim ↔ the code | path-limit formula, `O(D²)` vs the measured exponent, "carries the refusal", "at least as broad as the host's fold", the removed `remove_dir_all` remedy, a stale line citation |
| B | `foo` ↔ `foo_fd` (one spelling guarded, the other not) | the lock-record guard, the residue guard, `validate_rel`/`parse` |
| C | local view ↔ wire view ↔ copy view | three accepted out-of-root escapes |
| D | a predicate's name ↔ the question it answers | `is_reserved_name` offered as an oracle; the temp/id overlap; the trailing-dot id hole |
| E | what `parse` accepts ↔ what every operation does with it | totality gaps |
| F | a constant ↔ its derivation ↔ the resource's limit | `NAME_MAX` temp overflow, the `sun_path` reserve, the path-limit parity |
| G | an error class ↔ the condition it reports | legacy marker vs corruption; `Err(_) => Absent`; a removal-worded message on a create |
| H | a test's name ↔ the failure it can express | a tautological assertion; a false proof in `id_macro.rs`; a count-based bound test blind to quadratic |
| I | an audit pin ↔ the actual count | the funnel `openat` count |
| J | the `unix` ↔ `windows` twin surface | a public function present on one platform only |
| K | the revision you are READING ↔ the revision you BELIEVE you are reading | a `pub fn` count and a gate read from a checkout still parented to the previous tip |
| L | the platform you COMPILE ↔ the platform you claim to support | a call site inside `#[cfg(target_os = "linux")]` that a macOS-only gate never compiles, so a signature change silently missed it |

## Findings

**A — line-number citations drift.** The README cited `src/atomic/unix.rs:2031`
and `:2309` for two primitives; those lines are now doc text. A stale citation
reads as verified, and this class has already recurred once (a `:2302` citation
that was seven lines off). **Fixed** by citing items by NAME everywhere in
`README.md`; line numbers are no longer used.

**B/D — the one gate answered to two names, one of them misleading.**
`atomic::refuse_lock_record_mutation` was `refuse_reserved_mutation(rel,
Sanction::None)` — it runs BOTH the lock-record half and the residue half — while
its own doc block said there was deliberately no lock-only function. Call sites
were split between the two names, so a reader asking "does this primitive also
refuse a stranded aside?" could not tell from the call. **Fixed:** all 23 call
sites were verified to be `Sanction::None` — no site intended only the lock half,
which is what the design says cannot exist — so the alias was deleted and every
site now names `refuse_reserved_mutation(…, Sanction::None)`.

**D — one concept, two types. FIXED.** `sync::apply::UnsupportedDestination` was
a field-for-field copy of `manifest::UnsupportedEntry` (`path`, `reason`), built
by mapping one to the other, and its own doc said the values were *"preserved
verbatim from `crate::manifest::UnsupportedEntry`"*. Two names for one thing
meant any distinction typed on the manifest side had to be added twice or lost
in transit — which is exactly what happened when the tolerated reason gained a
kind. The duplicate was deleted; the report now carries the manifest type, so a
consumer sees the kind, and one `map(…clone…)` step disappeared with it.

**F — a duplicated constant across the platform twins.** `MAX_ANCESTRY` was
defined independently in `atomic/unix.rs` and `atomic/windows.rs`, both `1 << 16`.
The two ports enforce the same rule, so the values must agree; two literals are
free to drift. **Fixed:** single-sourced as `atomic::MAX_ANCESTRY`, referenced by
both ports.

**F (resolved, no action) — `SUN_PATH_BYTES` ×2 is correct.** One definition is
`#[cfg(unix)]` and computed from the platform's `sockaddr_un`; the other is the
`#[cfg(not(unix))]` placeholder so the module compiles everywhere. A `cfg`-gated
alternative is not a duplication.

**G — two candidates reviewed, BOTH conservative by construction. No defect.**
A removal path computes `confirmed = match rooted(&path) { Ok(rel) => …, Err(_) =>
false }`, and `RenamedEntryLocation::Unknown` collapses every probe error into
one variant. Both read like fail-open — an error becoming permission — and are
the opposite: `false` here means "not confirmed PRESENT", and the caller's
response to unconfirmed is to drop the candidate and emit *"its location is
unknown and it may be at <both spellings>, which must be checked by hand"*;
`Unknown` asserts nothing about location and pushes an `UnconfirmedMove` naming
both spellings. An unconfirmable probe therefore degrades to an explicitly
reported indeterminate state, never to a destructive decision.

The entry stays in this list as a RESOLVED false positive rather than being
deleted, because the shape is a trap for the next reader: the meaning of `false`
is only settled by reading the consumer, and the honest rule it demonstrates is
that "cannot determine" must be a state the caller reports, not a value that
silently feeds a branch.

**J — the public surface was not the same on both platforms. FIXED.**
The crate exposed unix-only public names while both ports `pub use …::*` into the
same namespaces, so a consumer using one compiled on unix and failed on windows.
The set was `atomic::{fsync_dir_fd, openat_no_follow, openat_no_follow_io}`
(`remove_dir_all_path` had already left the surface with API constraint #1) plus
`transport::kill_process_group`.

Every one of them turned out to be reachable only from inside the crate — the
`tests/confinement.rs` mention of `openat_no_follow` is prose, not a call — so
the fix is not to document the platform in the API but to stop exposing the
names: all three `atomic` primitives became `pub(crate)`, `kill_process_group`
stays public on neither port (it is the SSH runner's kill path, so it became
`pub(crate)` under the same `#[cfg(unix)]`), `RealKill` stays public because BOTH
ports implement it, and a dead transport-level re-export of `kill_process_group`
was removed outright.

Verified by re-running the sweep: the unix-only and windows-only public sets in
`atomic` are now both EMPTY. The crate's public-function total fell 186 → 174
across this and API constraint #1 — the constraint's real product is a smaller
surface, not a longer document.

**K — a reading taken from the wrong revision.** A `pub fn` surface count and a
full `cargo test --lib` were both run from a checkout whose working copy was
still parented to the PREVIOUS tip, so they described a tree that no longer
existed: the counts said the surface had not shrunk (34/30, not 29/26) and the
tree lacked `src/relpath.rs` entirely. The change's own `jj diff --stat`
contradicted the reading, and re-parenting the checkout showed the agent's
numbers were right. This is the checkout sibling of the stale-binary rule: a
green gate and a bad count are both only meaningful for a NAMED revision.

**L — a signature change missed a platform-gated call site. FIXED.** API
constraint #1 made every root-relative mutation take `RootedRelativePath`. The
macOS gate was green and stayed green; the Linux gate failed to **compile the
integration tests**, because the bind-mount regression lives in a
`#[cfg(target_os = "linux")]` block that macOS never compiles and it still
passed a `&Path`. The instance was one line; the class is that a platform-gated
call site is only ever built on ONE platform, so a signature change is
half-checked until the other gate runs. The fix is not a rule about care — it is
the Linux gate itself, which compiles what macOS cannot, which is why "a green
gate on one platform is not evidence for another" is mechanical here.

**E — the accepted set and the operations over it.** `validate_rel` accepts
`a/./b`, `a/b/` and `a//b`; `RootedRelativePath::parse` refuses a literal `.`
segment. Any primitive that takes a raw path therefore re-validates against a
rule STRICTER OR LOOSER than the one at the boundary. **Fixed** by API
constraint #1: the boundary is the type, `validate_rel` is deleted, and the
delta was measured to be **one-directional** — the type refuses a strict
superset, the only newly-refused inputs being spellings with a non-leading
literal `.` segment. No input the guard refused is now accepted.

**I — an audit pin moved, deliberately.** When `remove_dir_all_path` left
production the pinned `std::fs`/`libc` counts dropped with it (`remove_file`,
`rmdir`, `open`). That is the pin doing its job: the count changed, so the
change had to say so.

**D — the unconfined replace answered to the crate's DEFAULT name. FIXED.**
`atomic::write_atomic_replace` took a raw `&Path` and resolved every component
by that path (so an intermediate symlink was followed), yet its unqualified
name read as the crate's default atomic replace — the confined form is
`write_atomic_replace_fd`. It stayed public because an integration test used
it, which is not a consumer reason. **Fixed** by API constraint #8: it is now
`pub(crate)` (test-only on Unix, where no production body needs it; the body
of the fd surface on Windows), with a `compile_fail` doctest in `atomic`'s
module docs proving a caller cannot name the unconfined form. The integration
test's assertions are unchanged; it now drives the confined PUBLIC primitive
(`write_atomic_replace_fd`). This removed the LAST public mutation that did
not take `(&RootDir, &RootedRelativePath)`, completing constraint #1's stated
rule. A rename to a name stating the weakness was the alternative; demotion was
chosen because the only reason it was public was a test, and the constraint's
real product is a smaller surface.

**D — an existence probe answered a question it could not answer. FIXED.**
`Remote::exists` returned `bool`: a permission error, an I/O fault and a
genuine absence all read as `false`. Its own trait documentation said callers
must never consult it, and the crate's production code never did — it was a
public trap. **Fixed** by deleting it from the trait; `Remote::metadata_opt`
(the typed `Ok(Some)` / `Ok(None)` / `Err` probe) is the only existence
primitive, and the few tests that used `exists` now branch on that distinction
(one assertion got STRONGER: a symlinked parent is now asserted as `Err`, not
as "not present").

**D (stated residual, no action) — `is_reserved_name` is narrower than the
name rule.** `reserved::is_reserved_name` / `is_reserved_path` answer a
byte-exact reserved MATCH (what the sync strips), not "may I use this name" —
the authority is `is_unaddressable_name` / `is_unaddressable_path`. The names
do not say "narrow", but the README names the authority and the narrower pair
at the same place; renaming them would touch every call site for a predicate
whose distinction is already stated. Recorded as a residual rather than fixed.

**I — an audit pin moved again, deliberately (API constraint #8).** Making the
unconfined `write_atomic_replace` `#[cfg(test)]` on Unix removed its
`std::fs::rename` from the production count, so the pin entry
`("src/atomic/unix.rs", "rename", 1)` was removed in the same change, with the
reason recorded AT the pin. The guard still runs on the function; the call is
simply no longer production code, which is exactly what the audit excludes.
