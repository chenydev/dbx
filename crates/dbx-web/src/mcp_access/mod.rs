//! Web-only MCP API keys bound to teams of connections.
//!
//! The master Web MCP token keeps full access. Each API key authenticates as
//! its own principal and gets a backend whose policy is narrowed to the union
//! of its teams (see [`scope`]). Keys and teams live in one JSON document in
//! the `state_store` table. Authentication compares SHA-256 hashes; the secret
//! is additionally kept as an AES-GCM envelope under the data-directory key so
//! administrators can copy it again from the management page.

pub mod backend;
pub mod model;
pub mod scope;

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};

use dbx_core::persistence::secret_codec::SecretCodec;
use dbx_core::storage::Storage;
use dbx_mcp::{McpKeyResolver, McpPrincipal, McpPrincipalKind};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use model::{
    IssuedKey, KeyBatchInput, KeyInput, McpAccessDocument, McpApiKeyRecord, McpApiKeyView, McpTeam, RevealedKey,
    TeamInput,
};

const STATE_KEY: &str = "web_mcp_access.v1";
const ENVELOPE_NAMESPACE: &str = "web_mcp_api_key";
pub const DEFAULT_KEY_PREFIX: &str = "dbxk";
/// Random hex characters after the prefix that are shown to identify a key.
const KEY_DISPLAY_RANDOM_LEN: usize = 8;
const MAX_KEY_PREFIX_LEN: usize = 24;
/// Longest token worth hashing: the longest prefix, `_`, and 64 hex digits.
const MAX_SECRET_LEN: usize = MAX_KEY_PREFIX_LEN + 1 + 64;
const MAX_NAME_LEN: usize = 100;
const MAX_DESCRIPTION_LEN: usize = 500;
pub const MAX_BATCH_KEYS: usize = 100;

pub struct McpAccessStore {
    storage: Storage,
    doc: RwLock<McpAccessDocument>,
    /// Last-used timestamps recorded on the request path and persisted in
    /// batches so authentication never waits on a database write.
    usage: Mutex<HashMap<String, i64>>,
    write: tokio::sync::Mutex<()>,
    /// Encrypts secrets for later copying; `None` when no data key is
    /// available, in which case new keys are shown once only.
    codec: Option<SecretCodec>,
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub fn hash_secret(secret: &str) -> String {
    format!("{:x}", Sha256::digest(secret.as_bytes()))
}

fn generate_secret(prefix: &str) -> String {
    format!("{prefix}_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// Leading `<prefix>_xxxxxxxx` of a secret, shown to identify the key.
fn display_prefix(secret: &str) -> String {
    let random_start = secret.rfind('_').map_or(0, |index| index + 1);
    secret[..(random_start + KEY_DISPLAY_RANDOM_LEN).min(secret.len())].to_string()
}

/// Custom prefix of a stored key, recovered from its display prefix.
fn record_key_prefix(record: &McpApiKeyRecord) -> &str {
    record.prefix.rsplit_once('_').map_or(DEFAULT_KEY_PREFIX, |(prefix, _)| prefix)
}

/// Empty stays empty (meaning "use the default"); otherwise 1-24 ASCII
/// letters, digits, `-` or `_`, starting with a letter or digit.
pub fn clean_key_prefix(prefix: &str) -> Result<String, String> {
    let prefix = prefix.trim().trim_end_matches('_');
    if prefix.is_empty() {
        return Ok(String::new());
    }
    let valid_chars = prefix.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    let valid_start = prefix.chars().next().is_some_and(|c| c.is_ascii_alphanumeric());
    if !valid_chars || !valid_start || prefix.len() > MAX_KEY_PREFIX_LEN {
        return Err(format!(
            "Key prefix must be 1-{MAX_KEY_PREFIX_LEN} letters, digits, '-' or '_' and start with a letter or digit"
        ));
    }
    Ok(prefix.to_string())
}

fn clean_name(name: &str, what: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(format!("{what} name is required"));
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(format!("{what} name must be at most {MAX_NAME_LEN} characters"));
    }
    Ok(name.to_string())
}

fn clean_ids(ids: Vec<String>) -> Vec<String> {
    let mut ids = ids.into_iter().map(|id| id.trim().to_string()).filter(|id| !id.is_empty()).collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

impl McpAccessStore {
    pub fn new(storage: Storage, doc: McpAccessDocument, codec: Option<SecretCodec>) -> Self {
        Self {
            storage,
            doc: RwLock::new(doc),
            usage: Mutex::new(HashMap::new()),
            write: tokio::sync::Mutex::new(()),
            codec,
        }
    }

    pub async fn load(storage: Storage, codec: Option<SecretCodec>) -> Result<Self, String> {
        let doc = match storage.load_state(STATE_KEY).await? {
            Some((bytes, _)) => serde_json::from_slice::<McpAccessDocument>(&bytes)
                .map_err(|error| format!("invalid Web MCP access document: {error}"))?,
            None => McpAccessDocument::default(),
        };
        Ok(Self::new(storage, doc, codec))
    }

    fn seal(&self, key_id: &str, secret: &str) -> Result<Option<String>, String> {
        self.codec.as_ref().map(|codec| codec.encrypt(ENVELOPE_NAMESPACE, key_id, secret)).transpose()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, McpAccessDocument> {
        self.doc.read().unwrap_or_else(|error| error.into_inner())
    }

    /// Current document with pending usage timestamps applied.
    pub fn snapshot(&self) -> McpAccessDocument {
        let mut doc = self.read().clone();
        let usage = self.usage.lock().unwrap_or_else(|error| error.into_inner()).clone();
        apply_usage(&mut doc, &usage);
        doc
    }

    pub fn key_views(&self) -> Vec<McpApiKeyView> {
        let now = now_ms();
        self.snapshot().keys.iter().map(|key| McpApiKeyView::from_record(key, now)).collect()
    }

    /// Teams of a usable key, or `None` once the key is deleted, disabled or
    /// expired. Checked on every backend call so changes apply to live sessions.
    pub fn teams_for_key(&self, key_id: &str) -> Option<Vec<McpTeam>> {
        let doc = self.read();
        let key = doc.keys.iter().find(|key| key.id == key_id && key.is_usable(now_ms()))?;
        Some(doc.teams.iter().filter(|team| key.team_ids.contains(&team.id)).cloned().collect())
    }

    async fn mutate<T>(&self, change: impl FnOnce(&mut McpAccessDocument) -> Result<T, String>) -> Result<T, String> {
        let _guard = self.write.lock().await;
        let usage = std::mem::take(&mut *self.usage.lock().unwrap_or_else(|error| error.into_inner()));
        let mut next = self.read().clone();
        apply_usage(&mut next, &usage);
        let result = change(&mut next);
        let persisted = match &result {
            Ok(_) => self.persist(&next).await,
            Err(_) => Ok(()),
        };
        if result.is_err() || persisted.is_err() {
            // Keep usage for the next successful write instead of losing it.
            let mut pending = self.usage.lock().unwrap_or_else(|error| error.into_inner());
            for (key_id, used_at) in usage {
                let entry = pending.entry(key_id).or_insert(used_at);
                *entry = (*entry).max(used_at);
            }
        }
        persisted?;
        let value = result?;
        *self.doc.write().unwrap_or_else(|error| error.into_inner()) = next;
        Ok(value)
    }

    async fn persist(&self, doc: &McpAccessDocument) -> Result<(), String> {
        let bytes = serde_json::to_vec(doc).map_err(|error| error.to_string())?;
        self.storage.save_state(STATE_KEY, &bytes, "application/json").await
    }

    pub async fn flush_usage(&self) -> Result<(), String> {
        if self.usage.lock().unwrap_or_else(|error| error.into_inner()).is_empty() {
            return Ok(());
        }
        self.mutate(|_| Ok(())).await
    }

    pub async fn create_team(&self, input: TeamInput) -> Result<McpTeam, String> {
        let now = now_ms();
        let team = McpTeam {
            id: Uuid::new_v4().to_string(),
            name: clean_name(&input.name, "Team")?,
            description: clean_description(input.description)?,
            connection_ids: clean_ids(input.connection_ids),
            group_ids: clean_ids(input.group_ids),
            access: input.access,
            key_prefix: clean_key_prefix(&input.key_prefix)?,
            created_at: now,
            updated_at: now,
        };
        self.mutate(|doc| {
            ensure_unique_team_name(doc, &team.name, None)?;
            doc.teams.push(team.clone());
            Ok(team)
        })
        .await
    }

    pub async fn update_team(&self, id: &str, input: TeamInput) -> Result<McpTeam, String> {
        let name = clean_name(&input.name, "Team")?;
        let description = clean_description(input.description)?;
        let key_prefix = clean_key_prefix(&input.key_prefix)?;
        self.mutate(|doc| {
            ensure_unique_team_name(doc, &name, Some(id))?;
            let team = doc.teams.iter_mut().find(|team| team.id == id).ok_or("Team not found")?;
            team.name = name;
            team.description = description;
            team.connection_ids = clean_ids(input.connection_ids);
            team.group_ids = clean_ids(input.group_ids);
            team.access = input.access;
            team.key_prefix = key_prefix;
            team.updated_at = now_ms();
            Ok(team.clone())
        })
        .await
    }

    pub async fn delete_team(&self, id: &str) -> Result<(), String> {
        self.mutate(|doc| {
            let before = doc.teams.len();
            doc.teams.retain(|team| team.id != id);
            if doc.teams.len() == before {
                return Err("Team not found".to_string());
            }
            for key in &mut doc.keys {
                key.team_ids.retain(|team_id| team_id != id);
            }
            Ok(())
        })
        .await
    }

    pub async fn create_key(&self, input: KeyInput) -> Result<IssuedKey, String> {
        let batch = KeyBatchInput {
            names: vec![input.name],
            team_ids: input.team_ids,
            enabled: input.enabled,
            expires_at: input.expires_at,
            prefix: None,
        };
        self.create_keys(batch).await?.pop().ok_or_else(|| "Key name is required".to_string())
    }

    /// Creates one key per name atomically: either all are stored or none.
    pub async fn create_keys(&self, input: KeyBatchInput) -> Result<Vec<IssuedKey>, String> {
        let now = now_ms();
        let names = input.names.iter().map(|name| clean_name(name, "Key")).collect::<Result<Vec<_>, _>>()?;
        if names.is_empty() {
            return Err("Key name is required".to_string());
        }
        if names.len() > MAX_BATCH_KEYS {
            return Err(format!("At most {MAX_BATCH_KEYS} keys can be created at once"));
        }
        if let Some(name) = names.iter().enumerate().find_map(|(index, name)| {
            names[..index].iter().any(|other| other.eq_ignore_ascii_case(name)).then_some(name)
        }) {
            return Err(format!("Duplicate key name \"{name}\""));
        }
        let team_ids = clean_ids(input.team_ids);
        ensure_future(input.expires_at, now)?;
        let requested_prefix = input.prefix.as_deref().map(clean_key_prefix).transpose()?;
        self.mutate(|doc| {
            ensure_teams_exist(doc, &team_ids)?;
            for name in &names {
                ensure_unique_key_name(doc, name, None)?;
            }
            let prefix = requested_prefix
                .filter(|prefix| !prefix.is_empty())
                .or_else(|| {
                    team_ids.iter().find_map(|team_id| {
                        doc.teams
                            .iter()
                            .find(|team| team.id == *team_id && !team.key_prefix.is_empty())
                            .map(|team| team.key_prefix.clone())
                    })
                })
                .unwrap_or_else(|| DEFAULT_KEY_PREFIX.to_string());
            let mut issued = Vec::with_capacity(names.len());
            for name in names {
                let id = Uuid::new_v4().to_string();
                let secret = generate_secret(&prefix);
                let record = McpApiKeyRecord {
                    prefix: display_prefix(&secret),
                    key_hash: hash_secret(&secret),
                    secret_envelope: self.seal(&id, &secret)?,
                    id,
                    name,
                    team_ids: team_ids.clone(),
                    enabled: input.enabled,
                    expires_at: input.expires_at,
                    created_at: now,
                    updated_at: now,
                    last_used_at: None,
                };
                issued.push(IssuedKey { key: McpApiKeyView::from_record(&record, now), secret });
                doc.keys.push(record);
            }
            Ok(issued)
        })
        .await
    }

    /// Decrypts the secrets of the given keys, in the order requested.
    pub fn reveal_secrets(&self, ids: &[String]) -> Result<Vec<RevealedKey>, String> {
        let doc = self.read();
        ids.iter()
            .map(|id| {
                let key =
                    doc.keys.iter().find(|key| key.id == *id).ok_or_else(|| format!("API key not found: {id}"))?;
                let secret = match (&key.secret_envelope, &self.codec) {
                    (Some(envelope), Some(codec)) => Some(codec.decrypt(ENVELOPE_NAMESPACE, &key.id, envelope)?),
                    _ => None,
                };
                Ok(RevealedKey { id: key.id.clone(), name: key.name.clone(), secret })
            })
            .collect()
    }

    pub async fn update_key(&self, id: &str, input: KeyInput) -> Result<McpApiKeyView, String> {
        let name = clean_name(&input.name, "Key")?;
        let team_ids = clean_ids(input.team_ids);
        self.mutate(|doc| {
            ensure_teams_exist(doc, &team_ids)?;
            ensure_unique_key_name(doc, &name, Some(id))?;
            let key = doc.keys.iter_mut().find(|key| key.id == id).ok_or("API key not found")?;
            let now = now_ms();
            if input.expires_at != key.expires_at {
                ensure_future(input.expires_at, now)?;
            }
            key.name = name;
            key.team_ids = team_ids;
            key.enabled = input.enabled;
            key.expires_at = input.expires_at;
            key.updated_at = now;
            Ok(McpApiKeyView::from_record(key, now))
        })
        .await
    }

    pub async fn rotate_key(&self, id: &str) -> Result<IssuedKey, String> {
        self.mutate(|doc| {
            let key = doc.keys.iter_mut().find(|key| key.id == id).ok_or("API key not found")?;
            let now = now_ms();
            let secret = generate_secret(record_key_prefix(key));
            key.prefix = display_prefix(&secret);
            key.key_hash = hash_secret(&secret);
            key.secret_envelope = self.seal(&key.id, &secret)?;
            key.updated_at = now;
            key.last_used_at = None;
            Ok(IssuedKey { key: McpApiKeyView::from_record(key, now), secret })
        })
        .await
    }

    pub async fn delete_key(&self, id: &str) -> Result<(), String> {
        self.mutate(|doc| {
            let before = doc.keys.len();
            doc.keys.retain(|key| key.id != id);
            if doc.keys.len() == before {
                return Err("API key not found".to_string());
            }
            Ok(())
        })
        .await
    }
}

impl McpKeyResolver for McpAccessStore {
    fn resolve(&self, token: &str) -> Option<McpPrincipal> {
        if token.len() > MAX_SECRET_LEN {
            return None;
        }
        let hash = hash_secret(token);
        let now = now_ms();
        let principal = {
            let doc = self.read();
            let key = doc.keys.iter().find(|key| key.key_hash == hash && key.is_usable(now))?;
            McpPrincipal {
                id: key.id.clone(),
                label: format!("api-key:{} ({})", key.name, key.prefix),
                kind: McpPrincipalKind::ApiKey,
            }
        };
        self.usage.lock().unwrap_or_else(|error| error.into_inner()).insert(principal.id.clone(), now);
        Some(principal)
    }
}

fn apply_usage(doc: &mut McpAccessDocument, usage: &HashMap<String, i64>) {
    for key in &mut doc.keys {
        if let Some(used_at) = usage.get(&key.id) {
            key.last_used_at = Some(key.last_used_at.map_or(*used_at, |previous| previous.max(*used_at)));
        }
    }
}

fn clean_description(description: String) -> Result<String, String> {
    let description = description.trim().to_string();
    if description.chars().count() > MAX_DESCRIPTION_LEN {
        return Err(format!("Description must be at most {MAX_DESCRIPTION_LEN} characters"));
    }
    Ok(description)
}

fn ensure_unique_team_name(doc: &McpAccessDocument, name: &str, except: Option<&str>) -> Result<(), String> {
    if doc.teams.iter().any(|team| Some(team.id.as_str()) != except && team.name.eq_ignore_ascii_case(name)) {
        return Err(format!("A team named \"{name}\" already exists"));
    }
    Ok(())
}

fn ensure_unique_key_name(doc: &McpAccessDocument, name: &str, except: Option<&str>) -> Result<(), String> {
    if doc.keys.iter().any(|key| Some(key.id.as_str()) != except && key.name.eq_ignore_ascii_case(name)) {
        return Err(format!("An API key named \"{name}\" already exists"));
    }
    Ok(())
}

fn ensure_teams_exist(doc: &McpAccessDocument, team_ids: &[String]) -> Result<(), String> {
    match team_ids.iter().find(|id| !doc.teams.iter().any(|team| team.id == **id)) {
        Some(id) => Err(format!("Team not found: {id}")),
        None => Ok(()),
    }
}

fn ensure_future(expires_at: Option<i64>, now: i64) -> Result<(), String> {
    if expires_at.is_some_and(|expires_at| expires_at <= now) {
        return Err("Expiration time must be in the future".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::model::TeamAccess;
    use super::*;

    async fn store() -> (tempfile::TempDir, Storage, McpAccessStore) {
        let dir = tempfile::tempdir().unwrap();
        let storage = dbx_core::persistence::test_storage::open(&dir.path().join("dbx.db")).await.unwrap();
        let store = McpAccessStore::load(storage.clone(), Some(codec())).await.unwrap();
        (dir, storage, store)
    }

    fn codec() -> SecretCodec {
        SecretCodec::new([7; 32])
    }

    fn team_input(name: &str) -> TeamInput {
        TeamInput {
            name: name.to_string(),
            description: String::new(),
            connection_ids: vec!["c1".into(), " c1 ".into(), "".into()],
            group_ids: vec![],
            access: TeamAccess::ReadOnly,
            key_prefix: String::new(),
        }
    }

    fn batch_input(names: &[&str], team_ids: Vec<String>, prefix: Option<&str>) -> KeyBatchInput {
        KeyBatchInput {
            names: names.iter().map(|name| name.to_string()).collect(),
            team_ids,
            enabled: true,
            expires_at: None,
            prefix: prefix.map(ToOwned::to_owned),
        }
    }

    fn key_input(name: &str, team_ids: Vec<String>) -> KeyInput {
        KeyInput { name: name.to_string(), team_ids, enabled: true, expires_at: None }
    }

    #[tokio::test]
    async fn keys_resolve_by_secret_and_persist_only_hashes_and_envelopes() {
        let (_dir, storage, store) = store().await;
        let team = store.create_team(team_input("Data")).await.unwrap();
        assert_eq!(team.connection_ids, ["c1"]);
        let issued = store.create_key(key_input("ci", vec![team.id.clone()])).await.unwrap();
        assert!(issued.secret.starts_with("dbxk_"));
        assert_eq!(issued.secret.len(), "dbxk_".len() + 64);
        assert_eq!(issued.key.prefix.len(), "dbxk_".len() + KEY_DISPLAY_RANDOM_LEN);
        assert!(issued.secret.starts_with(&issued.key.prefix));
        assert!(issued.key.copyable);

        let principal = store.resolve(&issued.secret).unwrap();
        assert_eq!(principal.id, issued.key.id);
        assert_eq!(principal.kind, McpPrincipalKind::ApiKey);
        assert!(!principal.label.contains(&issued.secret));
        assert!(store.resolve("dbxk_wrong").is_none());
        assert!(store.resolve("master-token").is_none());

        store.flush_usage().await.unwrap();
        let (bytes, _) = storage.load_state(STATE_KEY).await.unwrap().unwrap();
        let raw = String::from_utf8(bytes).unwrap();
        assert!(!raw.contains(&issued.secret));
        assert!(raw.contains(&hash_secret(&issued.secret)));

        let reloaded = McpAccessStore::load(storage.clone(), Some(codec())).await.unwrap();
        assert_eq!(reloaded.resolve(&issued.secret).unwrap().id, issued.key.id);
        let revealed = reloaded.reveal_secrets(std::slice::from_ref(&issued.key.id)).unwrap();
        assert_eq!(revealed[0].secret.as_deref(), Some(issued.secret.as_str()));

        // Without the data key the envelope stays sealed, but auth still works.
        let keyless = McpAccessStore::load(storage, None).await.unwrap();
        assert_eq!(keyless.resolve(&issued.secret).unwrap().id, issued.key.id);
        assert_eq!(keyless.reveal_secrets(std::slice::from_ref(&issued.key.id)).unwrap()[0].secret, None);
        assert!(reloaded.key_views()[0].last_used_at.is_some());
        assert_eq!(reloaded.teams_for_key(&issued.key.id).unwrap(), vec![team]);
    }

    #[tokio::test]
    async fn disabled_expired_rotated_and_deleted_keys_stop_resolving() {
        let (_dir, _storage, store) = store().await;
        let issued = store.create_key(key_input("k", vec![])).await.unwrap();
        let id = issued.key.id.clone();
        assert_eq!(store.teams_for_key(&id), Some(vec![]));

        store.update_key(&id, KeyInput { enabled: false, ..key_input("k", vec![]) }).await.unwrap();
        assert!(store.resolve(&issued.secret).is_none());
        assert!(store.teams_for_key(&id).is_none());

        store.update_key(&id, key_input("k", vec![])).await.unwrap();
        let rotated = store.rotate_key(&id).await.unwrap();
        assert!(store.resolve(&issued.secret).is_none());
        assert_eq!(store.resolve(&rotated.secret).unwrap().id, id);

        {
            let mut doc = store.doc.write().unwrap();
            doc.keys[0].expires_at = Some(now_ms() - 1);
        }
        assert!(store.resolve(&rotated.secret).is_none());
        assert!(store.key_views()[0].expired);

        store.delete_key(&id).await.unwrap();
        assert!(store.teams_for_key(&id).is_none());
    }

    #[tokio::test]
    async fn validation_and_team_deletion_unbinds_keys() {
        let (_dir, _storage, store) = store().await;
        assert!(store.create_team(team_input("  ")).await.is_err());
        let team = store.create_team(team_input("Ops")).await.unwrap();
        assert!(store.create_team(team_input("ops")).await.is_err());
        assert!(store.create_key(key_input("k", vec!["missing".into()])).await.is_err());
        assert!(store
            .create_key(KeyInput { expires_at: Some(now_ms() - 1000), ..key_input("k", vec![]) })
            .await
            .is_err());

        let issued = store.create_key(key_input("k", vec![team.id.clone()])).await.unwrap();
        store.delete_team(&team.id).await.unwrap();
        assert!(store.key_views()[0].team_ids.is_empty());
        assert_eq!(store.teams_for_key(&issued.key.id), Some(vec![]));
    }

    #[tokio::test]
    async fn batch_creation_uses_prefixes_and_is_atomic() {
        let (_dir, _storage, store) = store().await;
        let plain = store.create_team(team_input("Plain")).await.unwrap();
        let sales = store.create_team(TeamInput { key_prefix: "sales_".into(), ..team_input("Sales") }).await.unwrap();
        assert_eq!(sales.key_prefix, "sales");
        assert!(store.create_team(TeamInput { key_prefix: "-bad".into(), ..team_input("Bad") }).await.is_err());
        assert!(store.create_team(TeamInput { key_prefix: "has space".into(), ..team_input("Bad") }).await.is_err());

        // The first selected team with a prefix wins over the default.
        let issued = store
            .create_keys(batch_input(&["alice", "bob"], vec![plain.id.clone(), sales.id.clone()], None))
            .await
            .unwrap();
        assert_eq!(issued.len(), 2);
        for key in &issued {
            assert!(key.secret.starts_with("sales_"), "{}", key.secret);
            assert_eq!(key.secret.len(), "sales_".len() + 64);
            assert_eq!(key.key.prefix.len(), "sales_".len() + KEY_DISPLAY_RANDOM_LEN);
            assert_eq!(store.resolve(&key.secret).unwrap().id, key.key.id);
        }
        assert_ne!(issued[0].secret, issued[1].secret);

        // An explicit prefix wins over the teams; rotation keeps it.
        let custom = store.create_keys(batch_input(&["carol"], vec![sales.id.clone()], Some("ops-1"))).await.unwrap();
        assert!(custom[0].secret.starts_with("ops-1_"));
        let rotated = store.rotate_key(&custom[0].key.id).await.unwrap();
        assert!(rotated.secret.starts_with("ops-1_"));
        let ids = vec![rotated.key.id.clone(), issued[0].key.id.clone()];
        let revealed = store.reveal_secrets(&ids).unwrap();
        assert_eq!(revealed[0].secret.as_deref(), Some(rotated.secret.as_str()));
        assert_eq!(revealed[1].name, "alice");
        assert!(store.reveal_secrets(&["missing".to_string()]).is_err());

        // Duplicates (within the batch or with existing keys) reject the whole batch.
        assert!(store.create_keys(batch_input(&["dave", "Dave"], vec![], None)).await.is_err());
        assert!(store.create_keys(batch_input(&["erin", "ALICE"], vec![], None)).await.is_err());
        assert!(store.create_keys(batch_input(&[], vec![], None)).await.is_err());
        assert!(store.create_keys(batch_input(&["x"], vec![], Some("bad prefix"))).await.is_err());
        assert_eq!(store.key_views().len(), 3);
        assert!(store.update_key(&issued[1].key.id, key_input("alice", vec![])).await.is_err());
    }

    #[tokio::test]
    async fn keys_without_envelopes_are_not_copyable() {
        let (_dir, storage, _) = store().await;
        let store = McpAccessStore::load(storage, None).await.unwrap();
        let issued = store.create_key(key_input("legacy", vec![])).await.unwrap();
        assert!(!issued.key.copyable);
        assert_eq!(store.reveal_secrets(std::slice::from_ref(&issued.key.id)).unwrap()[0].secret, None);
        assert_eq!(store.resolve(&issued.secret).unwrap().id, issued.key.id);
    }
}
