//! Host-identity verification and pinning: a strict known-hosts file or a
//! pre-verified fingerprint pinned into a managed cache (`ssh-keyscan`),
//! never trust-on-first-use.

use crate::env::SysEnv;
use crate::error::{Error, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::runner::{OpKind, RunError, SSH_CONNECT_TIMEOUT_SECS, SshRunner, leftover_pipe_note};

/// Build the `ssh-keyscan` argument vector (port, connect timeout, key
/// types, bare host). The bare address is used (not `user@address`) because
/// `ssh-keyscan` expects a hostname/address, and the configured port is
/// passed via `-p`. `-T N` is the canonical ssh-keyscan connection timeout:
/// it is supported by both OpenSSH (Linux) and the LibreSSL/macOS build
/// (which REJECTS the nonexistent `-O timeout=` variant — `-O` only
/// carries `hashalg=`). [`pin_known_hosts`] additionally
/// enforces the same N-second bound at the process level, so a keyscan
/// implementation that ignores `-T` still cannot hang the pin step.
pub(crate) fn keyscan_args(port: u16, address: &str) -> Vec<String> {
    vec![
        "-p".into(),
        port.to_string(),
        "-T".into(),
        SSH_CONNECT_TIMEOUT_SECS.to_string(),
        "-t".into(),
        "ed25519,ecdsa,rsa".into(),
        address.to_string(),
    ]
}

/// Pin the host key for `target` (the `user@host` connection string) in a
/// managed known-hosts file under the private cache directory, verifying it
/// against the configured `fingerprint` (fetched from `address` on `port`
/// via `ssh-keyscan`). Fails closed if the key cannot be fetched or does
/// not match. Returns the pinned file's path; the transport stores it for
/// use as `UserKnownHostsFile` in later ssh invocations.
///
/// `cache_dir` is the RESOLVED pin-cache directory (resolved once at the
/// transport-construction boundary from the environment snapshot — never
/// read from the process env here), and `env` is the snapshot whose
/// variables ride the `ssh-keygen` fingerprint-verification child.
pub(crate) fn pin_known_hosts(
    fingerprint: &str,
    target: &str,
    address: &str,
    port: u16,
    cache_dir: &Path,
    env: &SysEnv,
    runner: &SshRunner,
) -> Result<PathBuf> {
    let expected = fingerprint.trim().to_lowercase();

    // Pinned keys live in a private (0700) cache directory owned by this
    // user, rather than a predictable world-readable temp file name, so a
    // locally pre-created file cannot be trusted blindly. The cache root is
    // resolved at the boundary (the snapshot's `DEPLOY_SSH_KNOWNHOSTS_DIR`,
    // else `<temp_dir>/deploy-ssh-knownhosts`) and passed in — each test
    // points it at its own isolated cache.
    let cache_dir = cache_dir.to_path_buf();
    std::fs::create_dir_all(&cache_dir).map_err(|e| {
        Error::transport(format!(
            "create known_hosts cache {}: {e}",
            cache_dir.display()
        ))
    })?;
    crate::platform::chmod(&cache_dir, 0o700).map_err(|e| {
        Error::transport(format!(
            "chmod known_hosts cache {}: {e}",
            cache_dir.display()
        ))
    })?;
    let path = pin_file_path(&cache_dir, target, port);

    // Validate any existing cached file against the configured fingerprint
    // before reusing it: a changed key (or a locally pre-created file) is
    // never trusted without re-verification.
    if path.exists()
        && let Ok(text) = std::fs::read_to_string(&path)
        && fingerprints_match(&text, &expected, env)
    {
        return Ok(path);
    }
    if path.exists() {
        // Stale, unreadable, or mismatched cache: drop and re-pin below.
        let _ = std::fs::remove_file(&path);
    }

    // Fetch the host keys using the bare address and configured port. The
    // spawn runs through THE shared runner ([`SshRunner`]): the keyscan is
    // bounded at the process level by the runner's connect deadline (the
    // same `SSH_CONNECT_TIMEOUT_SECS` as the native `-T` option), and on
    // deadline the child is killed and reaped — a dead or unresponsive host
    // fails the pin step fast even if the local `ssh-keyscan` ignores its
    // native `-T` option.
    let mut argv = vec!["ssh-keyscan".to_string()];
    argv.extend(keyscan_args(port, address));
    let scan = runner
        .run(OpKind::KeyscanPin, &argv, None, None)
        .map_err(|e| match e {
            RunError::Spawn(m) => Error::transport(format!("ssh-keyscan {} spawn: {m}", address)),
            RunError::StdinWrite(m) => {
                Error::transport(format!("ssh-keyscan {} stdin write: {m}", address))
            }
            RunError::Wait(m) => Error::transport(format!("ssh-keyscan {} wait: {m}", address)),
            RunError::Background(m) => Error::transport(format!("ssh-keyscan {}: {m}", address)),
            RunError::Timeout {
                after,
                leftover_pipes,
            } => Error::transport(format!(
                "ssh-keyscan {} timed out after {after:?}{} (host unreachable?)",
                address,
                leftover_pipe_note(&leftover_pipes)
            )),
        })?;
    if !scan.status.success() {
        return Err(Error::transport(format!(
            "ssh-keyscan {} failed: {}",
            address,
            String::from_utf8_lossy(&scan.stderr)
        )));
    }
    let text = String::from_utf8_lossy(&scan.stdout);

    // For each fetched key, compute its fingerprint and keep the ones whose
    // fingerprint matches the configured value.
    let mut matched: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if key_matches_fingerprint(line, &expected, env) {
            matched.push(line.to_string());
        }
    }

    if matched.is_empty() {
        return Err(Error::transport(format!(
            "no host key for {} matched configured fingerprint {}",
            address, expected
        )));
    }

    // Exclusive (O_EXCL) creation with 0600 permissions so a concurrent or
    // pre-existing file cannot be silently overwritten or read by others.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| {
            Error::transport(format!("create pinned known_hosts {}: {e}", path.display()))
        })?;
    use std::io::Write;
    f.write_all(matched.join("\n").trim_end().as_bytes())
        .and_then(|_| f.write_all(b"\n"))
        .map_err(|e| Error::transport(format!("write known_hosts {}: {e}", path.display())))?;
    drop(f);
    crate::platform::chmod(&path, 0o600)
        .map_err(|e| Error::transport(format!("chmod known_hosts {}: {e}", path.display())))?;
    Ok(path)
}

/// Pipe a single key line into `ssh-keygen -lf` and return whether its
/// fingerprint (the second whitespace-separated field) matches `expected`.
/// The child receives the environment snapshot as its ENTIRE environment
/// ([`SysEnv::apply_to_command`]: `env_clear` + the snapshot's variables) so
/// its `PATH` (and any fake-bin variable) is the deterministic hermetic
/// snapshot.
pub(crate) fn key_matches_fingerprint(line: &str, expected: &str, env: &SysEnv) -> bool {
    let mut cmd = Command::new("ssh-keygen");
    env.apply_to_command(&mut cmd);
    let mut keygen = match cmd
        .arg("-lf")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(k) => k,
        Err(_) => return false,
    };
    use std::io::Write;
    if keygen
        .stdin
        .as_mut()
        .unwrap()
        .write_all(line.as_bytes())
        .is_err()
    {
        return false;
    }
    let out = match keygen.wait_with_output() {
        Ok(o) => o,
        Err(_) => return false,
    };
    if !out.status.success() {
        return false;
    }
    let fp = String::from_utf8_lossy(&out.stdout);
    let fp_field = fp.split_whitespace().nth(1).unwrap_or("").to_lowercase();
    fp_field == expected
}

/// The path of the managed known-hosts pin file for `target` on `port`.
///
/// The key is the PAIR `(target, port)`, never `target` alone. The pinned
/// content is the key `ssh-keyscan -p <port>` returned, so two sshd instances
/// reached at DIFFERENT ports on one host can serve DIFFERENT host keys (and
/// different fingerprints). Keying on `user@host` alone made both ports share
/// ONE pin file: each transport's fingerprint check would then discard and
/// re-pin the other's file, and a pinned key could momentarily clash between
/// ports. Including the port keeps each pinned content under its own key; the
/// target stays in the key so two accounts never share a pin either.
pub(crate) fn pin_file_path(cache_dir: &Path, target: &str, port: u16) -> PathBuf {
    cache_dir.join(format!(
        "knownhosts-{}.txt",
        simple_hash(&format!("{target}:{port}"))
    ))
}

/// Return true if any key line in `text` matches `expected` fingerprint.
pub(crate) fn fingerprints_match(text: &str, expected: &str, env: &SysEnv) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        !line.is_empty() && !line.starts_with('#') && key_matches_fingerprint(line, expected, env)
    })
}

/// Stable, filesystem-safe hash of a string for building temp-file names and
/// identity cache keys.
///
/// This is full-strength SHA-256, not a 64-bit FNV-1a. The hash is a SECURITY
/// boundary here: a collision between two distinct connection identities would
/// make them derive the SAME `ControlPath`, and a reused ControlMaster skips
/// the second connection's host-key check and key selection. At 64 bits a
/// collision is merely unlikely; at 256 bits it is infeasible, and the cost is
/// one SHA-256 over a short string once per connection. A caller that must fit
/// the result into a length-limited field (the mux socket name, bounded by
/// `sockaddr_un.sun_path`) uses a LEADING HEX PREFIX of this value, never a
/// weaker hash — see `SshTransport::mux_identity_hash`.
pub(crate) fn simple_hash(s: &str) -> String {
    crate::digest::sha256_bytes(s.as_bytes())
}

#[cfg(test)]
mod tests_hostkey {
    use super::*;

    /// The pin cache key includes the PORT: two ports on one host derive
    /// different pin files (their `ssh-keyscan` content can differ), while an
    /// identical (target, port) is stable so the pin is reused.
    #[test]
    fn pin_path_is_keyed_on_target_and_port() {
        let dir = Path::new("/cache");
        let a = pin_file_path(dir, "deploy@db.example.com", 22);
        let b = pin_file_path(dir, "deploy@db.example.com", 2222);
        assert_ne!(
            a, b,
            "two ports on one host must not share a pinned known-hosts file"
        );
        assert_eq!(
            a,
            pin_file_path(dir, "deploy@db.example.com", 22),
            "an identical (target, port) must reuse the same pin file"
        );
        assert_ne!(
            a,
            pin_file_path(dir, "other@db.example.com", 22),
            "two accounts must not share a pin file"
        );
        let name = a.file_name().unwrap().to_string_lossy();
        assert!(
            name.starts_with("knownhosts-") && name.ends_with(".txt"),
            "got {name}"
        );
    }

    /// The identity hash is full-strength SHA-256 (256 bits), not a 64-bit
    /// FNV-1a: a ControlPath collision between two distinct identities would
    /// let one reuse the other's authenticated master. Pinned against the
    /// SHA-256 `abc` vector so a future "simplification" cannot quietly
    /// weaken it.
    #[test]
    fn simple_hash_is_sha256() {
        assert_eq!(
            simple_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(simple_hash("abc").len(), 64);
        assert_ne!(simple_hash("a"), simple_hash("b"));
    }

    // Finding 1: the configured port is propagated to ssh-keyscan, and the
    // bare host is passed (not `user@address`).
    #[test]
    fn keyscan_uses_bare_host_and_port() {
        let args = keyscan_args(2222, "db.example.com");
        assert_eq!(args[0], "-p");
        assert_eq!(args[1], "2222");
        assert!(args.contains(&"db.example.com".to_string()));
        // The connection target (`user@host`) must NOT be passed to ssh-keyscan.
        assert!(!args.iter().any(|a| a.contains('@')));
        // The keyscan carries the same connect timeout as ssh. `-T N` is the
        // canonical ssh-keyscan connection timeout (OpenSSH and the
        // LibreSSL/macOS build both support it; `-O timeout=` does not exist).
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-T" && w[1] == SSH_CONNECT_TIMEOUT_SECS.to_string()),
            "keyscan args must carry -T {SSH_CONNECT_TIMEOUT_SECS}, got: {args:?}"
        );
    }
}
