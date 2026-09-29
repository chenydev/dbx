use serde::{Deserialize, Serialize};

/// Highest execution mode a team grants on its connections. Ordered from
/// narrowest to widest so the union across teams is `max()`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TeamAccess {
    #[default]
    ReadOnly,
    ReadWrite,
    ReadWriteDangerous,
}

impl TeamAccess {
    /// `(read_only, allow_dangerous_sql)` ceiling, or `None` when the team
    /// leaves the global policy untouched.
    pub fn ceiling(self) -> Option<(bool, bool)> {
        match self {
            Self::ReadOnly => Some((true, false)),
            Self::ReadWrite => Some((false, false)),
            Self::ReadWriteDangerous => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpTeam {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Connections granted directly.
    #[serde(default)]
    pub connection_ids: Vec<String>,
    /// Sidebar groups whose current descendant connections are granted.
    #[serde(default)]
    pub group_ids: Vec<String>,
    #[serde(default)]
    pub access: TeamAccess,
    /// Default prefix for keys created for this team; empty uses `dbxk`.
    #[serde(default)]
    pub key_prefix: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Persisted API key. Authentication matches the SHA-256 of the secret; the
/// secret itself is kept only as an AES-GCM envelope so admins can copy it
/// again. Keys created before envelopes existed have none and must be rotated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpApiKeyRecord {
    pub id: String,
    pub name: String,
    /// Non-secret leading characters shown in the UI to identify the key.
    pub prefix: String,
    pub key_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_envelope: Option<String>,
    #[serde(default)]
    pub team_ids: Vec<String>,
    pub enabled: bool,
    #[serde(default)]
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default)]
    pub last_used_at: Option<i64>,
}

impl McpApiKeyRecord {
    pub fn is_usable(&self, now: i64) -> bool {
        self.enabled && self.expires_at.is_none_or(|expires_at| expires_at > now)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpAccessDocument {
    #[serde(default)]
    pub teams: Vec<McpTeam>,
    #[serde(default)]
    pub keys: Vec<McpApiKeyRecord>,
}

/// API view of a key: no hash and no secret.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpApiKeyView {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub team_ids: Vec<String>,
    pub enabled: bool,
    pub expired: bool,
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
    /// Whether the secret can be revealed again.
    pub copyable: bool,
}

impl McpApiKeyView {
    pub fn from_record(record: &McpApiKeyRecord, now: i64) -> Self {
        Self {
            id: record.id.clone(),
            name: record.name.clone(),
            prefix: record.prefix.clone(),
            team_ids: record.team_ids.clone(),
            enabled: record.enabled,
            expired: record.expires_at.is_some_and(|expires_at| expires_at <= now),
            expires_at: record.expires_at,
            created_at: record.created_at,
            updated_at: record.updated_at,
            last_used_at: record.last_used_at,
            copyable: record.secret_envelope.is_some(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamInput {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub connection_ids: Vec<String>,
    #[serde(default)]
    pub group_ids: Vec<String>,
    #[serde(default)]
    pub access: TeamAccess,
    #[serde(default)]
    pub key_prefix: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInput {
    pub name: String,
    #[serde(default)]
    pub team_ids: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

/// Creates one key per name with shared settings. Without `prefix` the first
/// selected team that defines one is used, then `dbxk`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyBatchInput {
    pub names: Vec<String>,
    #[serde(default)]
    pub team_ids: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub prefix: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Returned once when a key is created or rotated.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedKey {
    pub key: McpApiKeyView,
    pub secret: String,
}

/// Secret of an existing key; `None` when the key predates stored envelopes.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealedKey {
    pub id: String,
    pub name: String,
    pub secret: Option<String>,
}
