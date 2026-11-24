//! bipnip, fork-only (upstream MostroP2P/mostro#1014, whose shared fix is upstream PR #890): the
//! daemon does not start while a file that holds a secret can be read by another user of the
//! machine, or while its settings directory can be written by one.
//!
//! The files: `settings.toml` and `.env` (either may hold the nsec), the LND macaroon named in the
//! settings (it can spend), and the database with its WAL and shared-memory files (escrow
//! preimages, trade keys). Each must be readable by its owner alone. The macaroon is usually
//! LND's own file: copy it for the daemon's user with `install -m 600`.

use std::path::{Path, PathBuf};

use mostro_core::error::{MostroError, MostroError::MostroInternalErr, ServiceError};

/// What is wrong with the files' modes, one line each; empty when nothing is.
#[cfg(unix)]
pub fn loose(settings_dir: &Path, macaroon: &str, db_file: &str) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt;

    let mode = |path: &Path| {
        std::fs::metadata(path)
            .ok()
            .map(|m| m.permissions().mode() & 0o777)
    };
    let mut found = Vec::new();
    if let Some(m) = mode(settings_dir) {
        if m & 0o022 != 0 {
            found.push(format!(
                "{} is mode {m:03o}: others can replace the files in it; chmod 700 it",
                settings_dir.display()
            ));
        }
    }
    let mut files: Vec<PathBuf> = vec![
        settings_dir.join("settings.toml"),
        settings_dir.join(".env"),
    ];
    if !macaroon.trim().is_empty() {
        files.push(PathBuf::from(macaroon.trim()));
    }
    let db = settings_dir.join(db_file);
    for suffix in ["-wal", "-shm"] {
        files.push(PathBuf::from(format!("{}{suffix}", db.display())));
    }
    files.push(db);
    for file in files {
        if let Some(m) = mode(&file) {
            if m & 0o077 != 0 {
                found.push(format!(
                    "{} is mode {m:03o}: others can read it; chmod 600 it (a macaroon: install -m 600 a copy this user owns)",
                    file.display()
                ));
            }
        }
    }
    found
}

#[cfg(not(unix))]
pub fn loose(_settings_dir: &Path, _macaroon: &str, _db_file: &str) -> Vec<String> {
    Vec::new()
}

/// Refuses to go on while [`loose`] finds anything.
pub fn refuse_loose(settings_dir: &Path, macaroon: &str, db_file: &str) -> Result<(), MostroError> {
    let found = loose(settings_dir, macaroon, db_file);
    if found.is_empty() {
        return Ok(());
    }
    Err(MostroInternalErr(ServiceError::IOError(format!(
        "files that hold secrets are open to other users, so mostrod will not start:\n  {}",
        found.join("\n  ")
    ))))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bipnipd-modes-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn file(path: &Path, mode: u32) {
        std::fs::write(path, "x").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn owner_only_files_pass_and_missing_ones_are_not_asked_for() {
        let dir = dir("tight");
        file(&dir.join("settings.toml"), 0o600);
        file(&dir.join("mostro.db"), 0o600);
        let macaroon = dir.join("admin.macaroon");
        file(&macaroon, 0o400);
        // No .env, no WAL yet, and a macaroon that is not configured: nothing to say.
        assert!(loose(&dir, macaroon.to_str().unwrap(), "mostro.db").is_empty());
        assert!(loose(&dir, "", "mostro.db").is_empty());
        assert!(refuse_loose(&dir, "", "mostro.db").is_ok());
    }

    #[test]
    fn each_secret_file_open_to_others_is_named() {
        let dir = dir("loose");
        file(&dir.join("settings.toml"), 0o644);
        file(&dir.join(".env"), 0o640);
        file(&dir.join("mostro.db"), 0o600);
        file(&dir.join("mostro.db-wal"), 0o604);
        let macaroon = dir.join("admin.macaroon");
        file(&macaroon, 0o644);
        let found = loose(&dir, macaroon.to_str().unwrap(), "mostro.db");
        assert_eq!(found.len(), 4, "{found:?}");
        for name in ["settings.toml", ".env", "mostro.db-wal", "admin.macaroon"] {
            assert!(found.iter().any(|f| f.contains(name)), "{name}: {found:?}");
        }
        let refused = refuse_loose(&dir, macaroon.to_str().unwrap(), "mostro.db").unwrap_err();
        assert!(refused.to_string().contains("will not start"), "{refused}");
    }

    #[test]
    fn a_settings_directory_others_can_write_is_refused() {
        let dir = dir("open-dir");
        file(&dir.join("settings.toml"), 0o600);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let found = loose(&dir, "", "mostro.db");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("chmod 700"), "{found:?}");
        // Readable by others is fine for the directory: its files are not.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(loose(&dir, "", "mostro.db").is_empty());
    }
}
