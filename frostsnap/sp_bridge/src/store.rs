use crate::{decode, encode, Engine};
use anyhow::{ensure, Context, Result};
use frostsnap_core::{
    coordinator::{keys::KeyMutation, FrostCoordinator, Mutation},
    device::KeyPurpose,
};
use rusqlite::{params, Connection, OpenFlags};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs::{File, OpenOptions as FsOptions},
    path::Path,
};

pub struct Store {
    pub core: FrostCoordinator,
    pub engine: Engine,
    db: Connection,
    _lock: File,
}
impl Store {
    pub fn open(directory: &Path) -> Result<Self> {
        if !directory.exists() {
            std::fs::create_dir(directory)?;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
        }
        ensure!(
            std::fs::metadata(directory)?.permissions().mode() & 0o077 == 0,
            "state directory must be private (chmod 700)"
        );
        let lock = FsOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(directory.join("bridge.lock"))?;
        lock.try_lock()
            .context("another bridge owns this state directory")?;
        let path = directory.join("bridge.sqlite");
        if !path.exists() {
            FsOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
        }
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE;
            CREATE TABLE IF NOT EXISTS bridge_mutations (id INTEGER PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS bridge_engine (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS bridge_version (id INTEGER PRIMARY KEY CHECK(id=1), revision TEXT NOT NULL);")?;
        db.execute(
            "INSERT OR IGNORE INTO bridge_version VALUES(1,?1)",
            [crate::CORE_REVISION],
        )?;
        let revision: String =
            db.query_row("SELECT revision FROM bridge_version WHERE id=1", [], |r| {
                r.get(0)
            })?;
        ensure!(
            revision == crate::CORE_REVISION,
            "state belongs to a different core revision"
        );
        let mut core = FrostCoordinator::new();
        {
            let mut stmt = db.prepare("SELECT payload FROM bridge_mutations ORDER BY id")?;
            for row in stmt.query_map([], |r| r.get::<_, String>(0))? {
                core.apply_mutation(decode::<Mutation>(&row?)?);
            }
        }
        let engine = db.query_row("SELECT payload FROM bridge_engine WHERE id=1", [], |r| {
            r.get::<_, String>(0)
        });
        let engine = match engine {
            Ok(value) => serde_json::from_str(&value)?,
            Err(rusqlite::Error::QueryReturnedNoRows) => Engine::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            core,
            engine,
            db,
            _lock: lock,
        })
    }

    /// Import ONLY key metadata and encrypted root-public-key material. NEVER copy nonce
    /// caches/reservations from another coordinator. Fresh streams are requested over USB.
    /// The source app DB is opened read-only and is never migrated or modified.
    pub fn import_app(&mut self, path: &Path) -> Result<usize> {
        ensure!(
            self.core.iter_keys().next().is_none(),
            "bridge already initialized"
        );
        let source = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut core = FrostCoordinator::new();
        let mut stmt =
            source.prepare("SELECT mutation,version FROM fs_coordinator_mutations ORDER BY id")?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)))? {
            let (bytes, version) = row?;
            ensure!(version == 0, "unsupported app database version");
            // Keygen is variant zero in both the setup build and PR #640. Other variants
            // may have changed; do not deserialize/import their nonce or restoration state.
            if bytes.first() == Some(&0) {
                let m: Mutation = decode(&frostsnap_core::hex::encode(&bytes))?;
                ensure!(matches!(m, Mutation::Keygen(_)), "unexpected key record");
                core.apply_mutation(m);
            }
        }
        let mutations: Vec<_> = core
            .iter_keys()
            .filter(|k| k.purpose == KeyPurpose::Bitcoin(bitcoin::Network::Signet))
            .map(|k| {
                Mutation::Keygen(KeyMutation::NewKey {
                    key_name: k.key_name.clone(),
                    purpose: k.purpose,
                    complete_key: k.complete_key.clone(),
                })
            })
            .collect();
        ensure!(
            !mutations.is_empty(),
            "no compatible signet wallet in app database"
        );
        let tx = self.db.transaction()?;
        for m in &mutations {
            tx.execute(
                "INSERT INTO bridge_mutations(payload) VALUES(?1)",
                [encode(m)?],
            )?;
        }
        tx.commit()?;
        for m in &mutations {
            self.core.apply_mutation(m.clone());
        }
        Ok(mutations.len())
    }

    /// Even a rejected operation may stage nonce mutations. Commit them and the session
    /// metadata atomically BEFORE any reply or USB request leaves this process.
    /// Outer error is fatal: caller must stop rather than use unpersisted in-memory state.
    pub fn transaction<T>(
        &mut self,
        f: impl FnOnce(&mut FrostCoordinator, &mut Engine) -> Result<T>,
    ) -> Result<Result<T>> {
        let result = f(&mut self.core, &mut self.engine);
        let updates = self.core.take_staged_mutations();
        let tx = self.db.transaction()?;
        for m in updates {
            tx.execute(
                "INSERT INTO bridge_mutations(payload) VALUES(?1)",
                [encode(&m)?],
            )?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO bridge_engine VALUES(1,?1)",
            params![serde_json::to_string(&self.engine)?],
        )?;
        tx.commit()?;
        Ok(result)
    }
}
