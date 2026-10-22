//! Fixed private result ledger and held filesystem sources. No signer API.
use super::frank_result_authority::{Error, FrankResultMode, Output, Result, StoredCapture};
use crate::work_private_files as private;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous},
    Connection, Row, SqliteConnection,
};
use std::{
    cell::{Cell, RefCell},
    fs::{File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};

pub(super) struct Root {
    pub path: PathBuf,
    held: private::Directory,
    identity: (u64, u64),
    ancestors: Vec<(PathBuf, u64, u64)>,
}
impl Root {
    pub fn open(path: &Path) -> Result<Self> {
        if path.as_os_str().len() > 4096 || path.components().count() > 129 {
            return Err(Error);
        }
        let held = private::Directory::open(path).map_err(|_| Error)?;
        let m = held.descriptor().metadata().map_err(|_| Error)?;
        let mut ancestors = Vec::new();
        for p in path.ancestors() {
            let m = std::fs::symlink_metadata(p).map_err(|_| Error)?;
            if !m.is_dir() {
                return Err(Error);
            }
            ancestors.push((p.to_owned(), m.dev(), m.ino()));
        }
        Ok(Self {
            path: path.to_owned(),
            held,
            identity: (m.dev(), m.ino()),
            ancestors,
        })
    }
    pub fn check(&self) -> Result<()> {
        let fresh = private::Directory::open(&self.path).map_err(|_| Error)?;
        for f in [self.held.descriptor(), fresh.descriptor()] {
            let m = f.metadata().map_err(|_| Error)?;
            if (m.dev(), m.ino()) != self.identity {
                return Err(Error);
            }
        }
        for (p, d, i) in &self.ancestors {
            let m = std::fs::symlink_metadata(p).map_err(|_| Error)?;
            if !m.is_dir() || (m.dev(), m.ino()) != (*d, *i) {
                return Err(Error);
            }
        }
        Ok(())
    }
    pub fn file(&self, name: &str, max: u64) -> Result<HeldFile> {
        self.check()?;
        if name.contains('/') || name == "." || name == ".." {
            return Err(Error);
        }
        HeldFile::open(&self.path.join(name), max)
    }
    pub fn lock(&self, name: &str, exclusive: bool) -> Result<HeldFile> {
        let f = self.file(name, 0)?;
        if unsafe {
            libc::flock(
                f.file.as_raw_fd(),
                libc::LOCK_NB
                    | if exclusive {
                        libc::LOCK_EX
                    } else {
                        libc::LOCK_SH
                    },
            )
        } != 0
        {
            return Err(Error);
        }
        f.check()?;
        self.check()?;
        Ok(f)
    }
}
pub(super) struct HeldFile {
    path: PathBuf,
    file: File,
    max: u64,
    pub bytes: Vec<u8>,
    identity: (u64, u64),
}
impl HeldFile {
    fn read(file: &File, max: u64) -> Result<Vec<u8>> {
        let before = file.metadata().map_err(|_| Error)?;
        if before.len() > max {
            return Err(Error);
        }
        let mut b = vec![0; usize::try_from(before.len()).map_err(|_| Error)?];
        file.read_exact_at(&mut b, 0).map_err(|_| Error)?;
        let after = file.metadata().map_err(|_| Error)?;
        if (
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ) {
            return Err(Error);
        }
        Ok(b)
    }
    pub fn open(path: &Path, max: u64) -> Result<Self> {
        let file = private::open(path, max).map_err(|_| Error)?;
        let m = file.metadata().map_err(|_| Error)?;
        let bytes = Self::read(&file, max)?;
        Ok(Self {
            path: path.to_owned(),
            file,
            max,
            bytes,
            identity: (m.dev(), m.ino()),
        })
    }
    pub fn check(&self) -> Result<()> {
        let current = private::open(&self.path, self.max).map_err(|_| Error)?;
        let m = current.metadata().map_err(|_| Error)?;
        if (m.dev(), m.ino()) != self.identity
            || Self::read(&current, self.max)? != self.bytes
            || Self::read(&self.file, self.max)? != self.bytes
        {
            return Err(Error);
        }
        Ok(())
    }
}
type CaptureRow = (String, String, Vec<u8>);
type AttestationRow = (Vec<u8>, String, String, String, Vec<u8>, String);
const MAX_ROWS: i64 = 32;
const MAX_LOGICAL: i64 = 32 * 1024 * 1024;
const PAGE_LIMIT: i64 = 8192;
const DB: &str = "results.sqlite3";
const MARKER: &str = "journal.initialized";
const MARKER_BYTES: &[u8] = b"frank.result.journal.v1\n";
const SCHEMA:&str="CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL CHECK(version=1), high_water INTEGER NOT NULL, seal BLOB NOT NULL); INSERT INTO meta VALUES(1,1,0,x''); CREATE TABLE captures(effect TEXT PRIMARY KEY, id TEXT NOT NULL UNIQUE, original BLOB NOT NULL); CREATE TABLE attestations(selector BLOB PRIMARY KEY, capture TEXT NOT NULL, parent TEXT NOT NULL, envelope_hash TEXT NOT NULL UNIQUE, record BLOB NOT NULL, replay TEXT NOT NULL UNIQUE, UNIQUE(capture,parent));";
pub(super) struct Store {
    root: Root,
    lock_source: HeldFile,
    database: Cell<Option<(u64, u64)>>,
    marker: RefCell<Option<HeldFile>>,
}
struct Clock {
    floor: Cell<u64>,
    failed: Cell<bool>,
}
impl Clock {
    fn new(floor: u64) -> Self {
        Self {
            floor: Cell::new(floor),
            failed: Cell::new(false),
        }
    }
    fn sample(&self) -> Result<u64> {
        let n = crate::clock::failclosed_unix_seconds();
        if self.failed.get() || n == 0 || n > 9_007_199_254_740_991 || n < self.floor.get() {
            self.failed.set(true);
            return Err(Error);
        }
        self.floor.set(n);
        Ok(n)
    }
}
impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let root = Root::open(path)?;
        let lock_source = root.file("journal.lock", 0)?;
        let database = if path.join(DB).try_exists().map_err(|_| Error)? {
            let f = private::open(&path.join(DB), 32 * 1024 * 1024).map_err(|_| Error)?;
            let m = f.metadata().map_err(|_| Error)?;
            Some((m.dev(), m.ino()))
        } else {
            None
        };
        let marker = if path.join(MARKER).try_exists().map_err(|_| Error)? {
            let marker = root.file(MARKER, MARKER_BYTES.len() as u64)?;
            if marker.bytes != MARKER_BYTES {
                return Err(Error);
            }
            Some(marker)
        } else {
            None
        };
        if marker.is_some() != database.is_some() {
            return Err(Error);
        }
        Ok(Self {
            root,
            lock_source,
            database: Cell::new(database),
            marker: RefCell::new(marker),
        })
    }
    fn physical(&self) -> Result<()> {
        self.root.check()?;
        self.lock_source.check()?;
        if let Some(marker) = self.marker.borrow().as_ref() {
            marker.check()?;
        }
        let mut total = 0u64;
        for e in std::fs::read_dir(&self.root.path).map_err(|_| Error)? {
            let e = e.map_err(|_| Error)?;
            let name = e.file_name();
            let limit = match name.to_str() {
                Some("journal.lock") => 0,
                Some(MARKER) => 4096,
                Some(DB) => 32 * 1024 * 1024,
                Some("results.sqlite3-journal") => 33 * 1024 * 1024,
                _ => return Err(Error),
            };
            let file = private::open(&e.path(), limit).map_err(|_| Error)?;
            let m = file.metadata().map_err(|_| Error)?;
            if name.to_str() == Some(DB)
                && self
                    .database
                    .get()
                    .is_some_and(|id| id != (m.dev(), m.ino()))
            {
                return Err(Error);
            }
            let charge = m.len().max(m.blocks().checked_mul(512).ok_or(Error)?);
            if charge > limit {
                return Err(Error);
            }
            total = total.checked_add(charge).ok_or(Error)?;
        }
        if total > 65 * 1024 * 1024 {
            return Err(Error);
        }
        // An expected DB must still exist: a directory enumeration can omit a
        // deleted entry. Never admit a cached output solely on an inode check
        // that ran only when the entry happened to be enumerated.
        if let Some(expected) = self.database.get() {
            let file =
                private::open(&self.root.path.join(DB), 32 * 1024 * 1024).map_err(|_| Error)?;
            let metadata = file.metadata().map_err(|_| Error)?;
            if (metadata.dev(), metadata.ino()) != expected {
                return Err(Error);
            }
        }
        Ok(())
    }
    async fn connect(&self, lock: &HeldFile, create: bool) -> Result<(SqliteConnection, bool)> {
        self.physical()?;
        lock.check()?;
        let path = self.root.path.join(DB);
        let fresh = !path.try_exists().map_err(|_| Error)?;
        let missing_marker = self.marker.borrow().is_none();
        if fresh {
            if !create || self.database.get().is_some() || self.marker.borrow().is_some() {
                return Err(Error);
            }
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
                .map_err(|_| Error)?
                .sync_all()
                .map_err(|_| Error)?;
            let mut marker = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(self.root.path.join(MARKER))
                .map_err(|_| Error)?;
            marker.write_all(MARKER_BYTES).map_err(|_| Error)?;
            marker.sync_all().map_err(|_| Error)?;
            self.marker
                .replace(Some(self.root.file(MARKER, MARKER_BYTES.len() as u64)?));
            self.root.held.descriptor().sync_all().map_err(|_| Error)?;
        } else if missing_marker {
            // This instance may predate another instance's bootstrap. Bind
            // the exact existing marker under the original journal lock before
            // first adopting the existing DB, then retain it through export.
            let marker = self.root.file(MARKER, MARKER_BYTES.len() as u64)?;
            if marker.bytes != MARKER_BYTES {
                return Err(Error);
            }
            marker.check()?;
            lock.check()?;
            self.root.check()?;
            self.marker.replace(Some(marker));
        }
        let file = private::open(&path, 32 * 1024 * 1024).map_err(|_| Error)?;
        let m = file.metadata().map_err(|_| Error)?;
        let id = (m.dev(), m.ino());
        if self.database.get().is_some_and(|old| old != id) {
            return Err(Error);
        }
        self.database.set(Some(id));
        let empty = m.len() == 0;
        if empty && !fresh {
            return Err(Error);
        }
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(false)
            .journal_mode(SqliteJournalMode::Delete)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_millis(250));
        let mut c = SqliteConnection::connect_with(&options)
            .await
            .map_err(|_| Error)?;
        let setup = async {
            for sql in [
                "PRAGMA temp_store=MEMORY".to_owned(),
                "PRAGMA cache_spill=OFF".into(),
                "PRAGMA secure_delete=ON".into(),
                format!("PRAGMA max_page_count={PAGE_LIMIT}"),
                format!("PRAGMA cache_size={}", PAGE_LIMIT + 32),
            ] {
                sqlx::query(&sql).execute(&mut c).await.map_err(|_| Error)?;
            }
            for (name, value) in [
                ("page_size", 4096),
                ("max_page_count", PAGE_LIMIT),
                ("temp_store", 2),
                ("cache_spill", 0),
                ("synchronous", 2),
            ] {
                let got: i64 = sqlx::query_scalar(&format!("PRAGMA {name}"))
                    .fetch_one(&mut c)
                    .await
                    .map_err(|_| Error)?;
                if got != value {
                    return Err(Error);
                }
            }
            if fresh {
                sqlx::raw_sql(SCHEMA)
                    .execute(&mut c)
                    .await
                    .map_err(|_| Error)?;
            }
            let names: Vec<String> = sqlx::query_scalar(
                "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .fetch_all(&mut c)
            .await
            .map_err(|_| Error)?;
            if names != ["attestations", "captures", "meta"] {
                return Err(Error);
            }
            let check: String = sqlx::query_scalar("PRAGMA quick_check(1)")
                .fetch_one(&mut c)
                .await
                .map_err(|_| Error)?;
            if check != "ok" {
                return Err(Error);
            }
            lock.check()?;
            self.physical()?;
            Ok(())
        }
        .await;
        if setup.is_err() {
            let _ = c.close().await;
            return Err(Error);
        }
        Ok((c, fresh))
    }
    async fn snapshot(c: &mut SqliteConnection) -> Result<Ledger> {
        for table in ["captures", "attestations"] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
                .fetch_one(&mut *c)
                .await
                .map_err(|_| Error)?;
            if !(0..=MAX_ROWS).contains(&count) {
                return Err(Error);
            }
        }
        let meta = sqlx::query("SELECT id,version,high_water,seal FROM meta LIMIT 2")
            .fetch_all(&mut *c)
            .await
            .map_err(|_| Error)?;
        if meta.len() != 1
            || meta[0].try_get::<i64, _>("id").map_err(|_| Error)? != 1
            || meta[0].try_get::<i64, _>("version").map_err(|_| Error)? != 1
        {
            return Err(Error);
        }
        let floor: i64 = meta[0].try_get("high_water").map_err(|_| Error)?;
        if !(0..=9_007_199_254_740_991).contains(&floor) {
            return Err(Error);
        }
        let captures: Vec<CaptureRow> = sqlx::query_as(
            "SELECT effect,id,original FROM captures ORDER BY effect COLLATE BINARY",
        )
        .fetch_all(&mut *c)
        .await
        .map_err(|_| Error)?;
        let records:Vec<AttestationRow>=sqlx::query_as("SELECT selector,capture,parent,envelope_hash,record,replay FROM attestations ORDER BY selector").fetch_all(&mut *c).await.map_err(|_|Error)?;
        if captures.len() > MAX_ROWS as usize || records.len() > MAX_ROWS as usize {
            return Err(Error);
        }
        let mut bytes = 0usize;
        for (effect, id, original) in &captures {
            bytes = bytes
                .checked_add(effect.len() + id.len() + original.len())
                .ok_or(Error)?;
        }
        for (selector, id, parent, hash, record, replay) in &records {
            bytes = bytes
                .checked_add(
                    selector.len()
                        + id.len()
                        + parent.len()
                        + hash.len()
                        + record.len()
                        + replay.len(),
                )
                .ok_or(Error)?;
        }
        if bytes > MAX_LOGICAL as usize {
            return Err(Error);
        }
        Ok(Ledger {
            floor: floor as u64,
            seal: meta[0].try_get("seal").map_err(|_| Error)?,
            captures,
            records,
            bytes,
        })
    }
    async fn save_floor(
        c: &mut SqliteConnection,
        floor: u64,
        key: &ed25519_dalek::SigningKey,
        configuration: &[u8; 32],
    ) -> Result<()> {
        use ed25519_dalek::Signer;
        let mut state = Self::snapshot(c).await?;
        if floor < state.floor {
            return Err(Error);
        }
        state.floor = floor;
        let signature = key.sign(&state.message(configuration)?).to_bytes();
        let changed = sqlx::query("UPDATE meta SET high_water=?,seal=? WHERE id=1")
            .bind(floor as i64)
            .bind(signature.as_slice())
            .execute(&mut *c)
            .await
            .map_err(|_| Error)?;
        if changed.rows_affected() != 1 {
            return Err(Error);
        }
        Ok(())
    }
    // One fixed private transaction boundary; no public generic journal API.
    #[allow(clippy::too_many_arguments)]
    pub async fn exchange<C: StoredCapture>(
        &self,
        mode: FrankResultMode,
        selector: &[u8],
        capture: &C,
        parent: &str,
        key: &ed25519_dalek::SigningKey,
        configuration: &[u8; 32],
        make: impl Fn(u64) -> Result<Output>,
        guard: impl Fn(&Output) -> Result<()>,
    ) -> Result<Vec<u8>> {
        self.lock_source.check()?;
        let lock = self.root.lock("journal.lock", true)?;
        let (mut c, fresh) = self.connect(&lock, mode == FrankResultMode::Attest).await?;
        let clock = Clock::new(0);
        let mut audited = false;
        let mut committed = false;
        let operation = async {
            sqlx::query("BEGIN IMMEDIATE")
                .execute(&mut c)
                .await
                .map_err(|_| Error)?;
            let ledger = Self::snapshot(&mut c).await?;
            ledger.check(fresh, key, configuration)?;
            clock.floor.set(ledger.floor);
            audited = true;
            clock.sample()?;
            let retained = ledger
                .captures
                .iter()
                .find(|(effect, _, _)| effect == capture.effect());
            if let Some((_, id, original)) = retained {
                if id != capture.id() || original.as_slice() != capture.original() {
                    return Err(Error);
                }
            }
            let existing = ledger
                .records
                .iter()
                .find(|(raw, id, p, _, _, _)| raw == selector && id == capture.id() && p == parent);
            let out = if mode == FrankResultMode::Resume {
                if retained.is_none() {
                    return Err(Error);
                }
                Output::decode(&existing.ok_or(Error)?.4)?
            } else {
                if existing.is_some() || ledger.records.len() >= MAX_ROWS as usize {
                    return Err(Error);
                }
                if mode == FrankResultMode::Attest {
                    if !parent.is_empty() || retained.is_some() {
                        return Err(Error);
                    }
                } else {
                    if retained.is_none() || parent.is_empty() {
                        return Err(Error);
                    }
                    let chain: Vec<_> = ledger
                        .records
                        .iter()
                        .filter(|(_, id, _, _, _, _)| id == capture.id())
                        .collect();
                    if chain.len() >= 16 {
                        return Err(Error);
                    }
                    let prior = chain
                        .iter()
                        .find(|(_, _, _, hash, _, _)| hash == parent)
                        .ok_or(Error)?;
                    if chain.iter().any(|(_, _, p, _, _, _)| p == parent) {
                        return Err(Error);
                    }
                    // Authenticate old signature/body/current owners, not its old expiry.
                    let old = Output::decode(&prior.4)?;
                    guard(&old)?;
                }
                let output = make(clock.sample()?)?;
                clock.floor.set(clock.floor.get().max(output.issued()));
                guard(&output)?;
                let record = output.encode()?;
                let replay = output.replay()?;
                let envelope_hash = output.envelope_hash();
                let charge = record.len()
                    + selector.len()
                    + capture.id().len()
                    + parent.len()
                    + envelope_hash.len()
                    + replay.len()
                    + if retained.is_none() {
                        capture.original().len() + capture.id().len() + capture.effect().len()
                    } else {
                        0
                    };
                if charge > MAX_LOGICAL as usize - ledger.bytes {
                    return Err(Error);
                }
                if retained.is_none() {
                    sqlx::query("INSERT INTO captures VALUES(?,?,?)")
                        .bind(capture.effect())
                        .bind(capture.id())
                        .bind(capture.original())
                        .execute(&mut c)
                        .await
                        .map_err(|_| Error)?;
                }
                sqlx::query("INSERT INTO attestations VALUES(?,?,?,?,?,?)")
                    .bind(selector)
                    .bind(capture.id())
                    .bind(parent)
                    .bind(envelope_hash)
                    .bind(record)
                    .bind(replay)
                    .execute(&mut c)
                    .await
                    .map_err(|_| Error)?;
                output
            };
            guard(&out)?;
            let final_time = clock.sample()?;
            out.window(final_time)?;
            Self::save_floor(&mut c, final_time, key, configuration).await?;
            sqlx::query("COMMIT")
                .execute(&mut c)
                .await
                .map_err(|_| Error)?;
            committed = true;
            Ok(out)
        }
        .await;
        if operation.is_err() {
            let rolled_back = sqlx::query("ROLLBACK").execute(&mut c).await.is_ok();
            // Preserve the primary denial. A successfully audited prior ledger can
            // retain observed time after rollback; no failed/corrupt state is sealed.
            if audited && rolled_back && !committed {
                let saved = async {
                    sqlx::query("BEGIN IMMEDIATE")
                        .execute(&mut c)
                        .await
                        .map_err(|_| Error)?;
                    let prior = Self::snapshot(&mut c).await?;
                    prior.check(fresh, key, configuration)?;
                    Self::save_floor(
                        &mut c,
                        clock.floor.get().max(prior.floor),
                        key,
                        configuration,
                    )
                    .await?;
                    sqlx::query("COMMIT")
                        .execute(&mut c)
                        .await
                        .map_err(|_| Error)?;
                    Ok::<(), Error>(())
                }
                .await;
                if saved.is_err() {
                    let _ = sqlx::query("ROLLBACK").execute(&mut c).await;
                }
            }
        }
        let closed = c.close().await.map_err(|_| Error);
        let out = operation?;
        closed?;
        // Owners/key remain held across close. Each advancing post-close sample
        // is durably sealed before a further complete owner check and export.
        let mut persisted = clock.floor.get();
        for _ in 0..3 {
            self.physical()?;
            lock.check()?;
            guard(&out)?;
            let now = clock.sample()?;
            let window = out.window(now);
            if now == persisted {
                window?;
                return Ok(out.envelope.clone());
            }
            let (mut c, _) = self.connect(&lock, false).await?;
            let saved = async {
                sqlx::query("BEGIN IMMEDIATE")
                    .execute(&mut c)
                    .await
                    .map_err(|_| Error)?;
                let prior = Self::snapshot(&mut c).await?;
                prior.check(false, key, configuration)?;
                if prior.floor != persisted {
                    return Err(Error);
                }
                Self::save_floor(&mut c, now, key, configuration).await?;
                sqlx::query("COMMIT")
                    .execute(&mut c)
                    .await
                    .map_err(|_| Error)?;
                Ok::<(), Error>(())
            }
            .await;
            if saved.is_err() {
                let _ = sqlx::query("ROLLBACK").execute(&mut c).await;
            }
            let closed = c.close().await.map_err(|_| Error);
            saved?;
            closed?;
            persisted = now;
            window?;
        }
        Err(Error)
    }
}
struct Ledger {
    floor: u64,
    seal: Vec<u8>,
    captures: Vec<CaptureRow>,
    records: Vec<AttestationRow>,
    bytes: usize,
}
impl Ledger {
    fn message(&self, configuration: &[u8; 32]) -> Result<Vec<u8>> {
        let state = bincode::serialize(&(1u8, self.floor, &self.captures, &self.records))
            .map_err(|_| Error)?;
        let mut message = b"frank.result.private-ledger.v1\0".to_vec();
        message.extend_from_slice(configuration);
        message.extend_from_slice(&super::frank_result_authority::hash(&state));
        Ok(message)
    }
    fn check(
        &self,
        fresh: bool,
        key: &ed25519_dalek::SigningKey,
        configuration: &[u8; 32],
    ) -> Result<()> {
        use super::frank_result_contract as contract;
        use std::collections::{BTreeMap, BTreeSet};
        if fresh
            && self.floor == 0
            && self.seal.is_empty()
            && self.captures.is_empty()
            && self.records.is_empty()
        {
            return Ok(());
        }
        key.verifying_key()
            .verify_strict(
                &self.message(configuration)?,
                &ed25519_dalek::Signature::from_slice(&self.seal).map_err(|_| Error)?,
            )
            .map_err(|_| Error)?;
        if self.floor == 0 {
            return Err(Error);
        }
        let mut captures = BTreeMap::new();
        let mut effects = BTreeSet::new();
        for (effect, id, original) in &self.captures {
            contract::digest(effect)?;
            contract::digest(id)?;
            if !effects.insert(effect) || captures.insert(id, original).is_some() {
                return Err(Error);
            }
        }
        let mut selectors = BTreeSet::new();
        let mut replays = BTreeSet::new();
        let mut edges = BTreeMap::new();
        let mut children = BTreeMap::new();
        for (selector, id, parent, envelope_hash, record, replay) in &self.records {
            super::frank_result_authority::check_stored_selector(selector, id, parent)?;
            if !selectors.insert(selector) || !replays.insert(replay) {
                return Err(Error);
            }
            contract::digest(envelope_hash)?;
            contract::digest(replay)?;
            if !parent.is_empty() {
                contract::digest(parent)?;
            }
            let original = captures.get(id).ok_or(Error)?;
            let effect = self
                .captures
                .iter()
                .find(|(_, capture, _)| capture == id)
                .ok_or(Error)?
                .0
                .as_str();
            let out = Output::decode(record)?;
            out.ledger_check(id, effect, original, &key.verifying_key())?;
            if out.envelope_hash() != *envelope_hash
                || out.replay() != Ok(replay.clone())
                || out.issued() > self.floor
                || edges
                    .insert(envelope_hash.clone(), (id.clone(), parent.clone()))
                    .is_some()
                || children
                    .insert((id.clone(), parent.clone()), envelope_hash.clone())
                    .is_some()
            {
                return Err(Error);
            }
        }
        for id in captures.keys() {
            let root = children.get(&((*id).clone(), String::new())).ok_or(Error)?;
            let mut current = root;
            let mut visited = BTreeSet::new();
            loop {
                if !visited.insert(current) || visited.len() > 16 {
                    return Err(Error);
                }
                match children.get(&((*id).clone(), current.clone())) {
                    Some(next) => current = next,
                    None => break,
                }
            }
            if visited.len()
                != self
                    .records
                    .iter()
                    .filter(|(_, capture, _, _, _, _)| capture == *id)
                    .count()
            {
                return Err(Error);
            }
        }
        // A signed snapshot is domain-separated and includes every original byte,
        // selector, relation, replay identity and clock floor. No history eviction.
        Ok(())
    }
}

#[cfg(test)]
mod store_boundary_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().canonicalize().unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("journal");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("journal.lock"))
            .unwrap();
        (temp, root)
    }

    #[tokio::test]
    async fn late_bootstrap_marker_remains_bound_after_close() {
        for mutation in ["contents", "inode"] {
            let (_temp, root) = fixture();
            let bootstrap = Store::open(&root).unwrap();
            let later = Store::open(&root).unwrap();
            let bootstrap_lock = bootstrap.root.lock("journal.lock", true).unwrap();
            let (connection, fresh) = bootstrap.connect(&bootstrap_lock, true).await.unwrap();
            assert!(fresh);
            connection.close().await.unwrap();
            drop(bootstrap_lock);

            let later_lock = later.root.lock("journal.lock", true).unwrap();
            let (connection, fresh) = later.connect(&later_lock, false).await.unwrap();
            assert!(!fresh);
            connection.close().await.unwrap();
            later.physical().unwrap();
            let path = root.join(MARKER);
            if mutation == "contents" {
                std::fs::write(&path, vec![b'x'; MARKER_BYTES.len()]).unwrap();
            } else {
                std::fs::rename(&path, root.parent().unwrap().join("displaced-marker")).unwrap();
                let mut replacement = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .unwrap();
                replacement.write_all(MARKER_BYTES).unwrap();
                replacement.sync_all().unwrap();
            }
            assert!(
                later.physical().is_err(),
                "accepted changed {mutation} after adopting an existing DB"
            );
            later_lock.check().unwrap();
        }
    }

    #[tokio::test]
    async fn expected_database_absence_denies_after_close() {
        let (_temp, root) = fixture();
        let store = Store::open(&root).unwrap();
        let lock = store.root.lock("journal.lock", true).unwrap();
        let (connection, fresh) = store.connect(&lock, true).await.unwrap();
        assert!(fresh);
        connection.close().await.unwrap();
        store.physical().unwrap();
        std::fs::remove_file(root.join(DB)).unwrap();
        assert!(
            store.physical().is_err(),
            "missing bound DB passed final admission"
        );
        lock.check().unwrap();
    }
}
