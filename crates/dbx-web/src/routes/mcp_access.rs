use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::mcp_access::model::{IssuedKey, KeyBatchInput, KeyInput, McpApiKeyView, McpTeam, TeamInput};
use crate::mcp_access::MAX_BATCH_KEYS;
use crate::routes::app_settings::ensure_web_mcp_management_allowed;
use crate::state::WebState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpAccessOverview {
    /// Keys only work while the Web MCP endpoint itself is enabled.
    pub endpoint_enabled: bool,
    pub endpoint_path: String,
    pub teams: Vec<McpTeam>,
    pub keys: Vec<McpApiKeyView>,
    pub connections: Vec<ConnectionOption>,
    pub groups: Vec<GroupOption>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionOption {
    pub id: String,
    pub name: String,
    pub db_type: String,
    pub group_path: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupOption {
    pub id: String,
    pub name: String,
}

fn no_store<T: Serialize>(value: T) -> impl IntoResponse {
    ([(header::CACHE_CONTROL, "no-store")], Json(value))
}

pub async fn overview(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Result<impl IntoResponse, AppError> {
    ensure_web_mcp_management_allowed(&state, &headers).await?;
    let layout = state.app.storage.load_sidebar_layout().await.map_err(AppError::from)?;
    let group_paths = layout
        .as_ref()
        .map(dbx_core::mcp_policy::connection_group_paths)
        .transpose()
        .unwrap_or_default()
        .unwrap_or_default();
    let groups = layout
        .as_ref()
        .and_then(|layout| layout.get("groups"))
        .and_then(|groups| groups.as_array())
        .map(|groups| {
            groups
                .iter()
                .filter_map(|group| {
                    Some(GroupOption {
                        id: group.get("id")?.as_str()?.to_string(),
                        name: group.get("name")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let mut connections = state
        .app
        .storage
        .load_connections()
        .await
        .map_err(AppError::from)?
        .into_iter()
        .map(|connection| ConnectionOption {
            db_type: serde_json::to_value(connection.db_type)
                .ok()
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .unwrap_or_default(),
            group_path: group_paths.get(&connection.id).map(|path| path.names.clone()).unwrap_or_default(),
            id: connection.id,
            name: connection.name,
        })
        .collect::<Vec<_>>();
    connections.sort_by(|a, b| a.group_path.cmp(&b.group_path).then_with(|| a.name.cmp(&b.name)));

    let doc = state.mcp_access.snapshot();
    Ok(no_store(McpAccessOverview {
        endpoint_enabled: state.web_mcp.auth().enabled() && !state.demo_mode,
        endpoint_path: if state.public_base_path == "/" {
            "/mcp".to_string()
        } else {
            format!("{}/mcp", state.public_base_path)
        },
        teams: doc.teams,
        keys: state.mcp_access.key_views(),
        connections,
        groups,
    }))
}

pub async fn create_team(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(input): Json<TeamInput>,
) -> Result<Json<McpTeam>, AppError> {
    ensure_web_mcp_management_allowed(&state, &headers).await?;
    state.mcp_access.create_team(input).await.map(Json).map_err(AppError::bad_request)
}

pub async fn update_team(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<TeamInput>,
) -> Result<Json<McpTeam>, AppError> {
    ensure_web_mcp_management_allowed(&state, &headers).await?;
    state.mcp_access.update_team(&id, input).await.map(Json).map_err(AppError::bad_request)
}

pub async fn delete_team(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    ensure_web_mcp_management_allowed(&state, &headers).await?;
    state.mcp_access.delete_team(&id).await.map_err(AppError::bad_request)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn create_key(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(input): Json<KeyInput>,
) -> Result<impl IntoResponse, AppError> {
    ensure_web_mcp_management_allowed(&state, &headers).await?;
    let issued: IssuedKey = state.mcp_access.create_key(input).await.map_err(AppError::bad_request)?;
    Ok(no_store(issued))
}

pub async fn create_keys(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(input): Json<KeyBatchInput>,
) -> Result<impl IntoResponse, AppError> {
    ensure_web_mcp_management_allowed(&state, &headers).await?;
    let issued = state.mcp_access.create_keys(input).await.map_err(AppError::bad_request)?;
    tracing::info!(count = issued.len(), "Web MCP API keys created");
    Ok(no_store(issued))
}

#[derive(Deserialize)]
pub struct RevealKeysInput {
    pub ids: Vec<String>,
}

/// Returns stored secrets for copying. POST keeps the ids out of URLs and
/// access logs; the response is never cached.
pub async fn reveal_keys(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(input): Json<RevealKeysInput>,
) -> Result<impl IntoResponse, AppError> {
    ensure_web_mcp_management_allowed(&state, &headers).await?;
    if input.ids.is_empty() || input.ids.len() > MAX_BATCH_KEYS * 10 {
        return Err(AppError::bad_request("Select between 1 and 1000 API keys"));
    }
    let revealed = state.mcp_access.reveal_secrets(&input.ids).map_err(AppError::bad_request)?;
    tracing::info!(count = revealed.len(), "Web MCP API key secrets revealed");
    Ok(no_store(revealed))
}

pub async fn update_key(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<KeyInput>,
) -> Result<Json<McpApiKeyView>, AppError> {
    ensure_web_mcp_management_allowed(&state, &headers).await?;
    state.mcp_access.update_key(&id, input).await.map(Json).map_err(AppError::bad_request)
}

pub async fn rotate_key(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    ensure_web_mcp_management_allowed(&state, &headers).await?;
    let issued = state.mcp_access.rotate_key(&id).await.map_err(AppError::bad_request)?;
    Ok(no_store(issued))
}

pub async fn delete_key(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    ensure_web_mcp_management_allowed(&state, &headers).await?;
    state.mcp_access.delete_key(&id).await.map_err(AppError::bad_request)?;
    Ok(StatusCode::NO_CONTENT)
}
