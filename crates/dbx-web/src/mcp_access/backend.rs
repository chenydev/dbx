use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use dbx_core::agent_events::ToolResult;
use dbx_core::agent_tools::AgentSqlPermissions;
use dbx_core::connection::SalesforceCurrentUser;
use dbx_core::db::{redis_driver::RedisCommandResult, ColumnInfo, TableInfo};
use dbx_core::history::HistoryEntry;
use dbx_core::mcp_policy::McpConnectionGroupPath;
use dbx_core::models::connection::ConnectionConfig;
use dbx_core::storage::McpGlobalPolicy;
use dbx_mcp::backend::{BatchStatementResult, DocsSnapshotOptions};
use dbx_mcp::mongo::MongoCommand;
use dbx_mcp::transaction::TransactionOwner;
use dbx_mcp::DbxBackend;
use serde_json::Value;

use super::model::TeamAccess;
use super::{scope, McpAccessStore};

const OUT_OF_SCOPE: &str = "CONNECTION_OUT_OF_SCOPE: this connection is not available to the API key";

/// Backend for one API key's MCP session. Policy and connection listings are
/// narrowed to the key's teams on every call, so edits, disabling and
/// deletion apply to sessions that are already open. Everything else is
/// delegated after re-checking that the target connection is still visible.
pub struct KeyScopedBackend {
    inner: Arc<dyn DbxBackend>,
    store: Arc<McpAccessStore>,
    key_id: String,
    builtin_tools: Arc<Vec<String>>,
}

struct KeyView {
    policy: McpGlobalPolicy,
    visible: BTreeMap<String, TeamAccess>,
    connections: Vec<ConnectionConfig>,
}

impl KeyScopedBackend {
    pub fn new(
        inner: Arc<dyn DbxBackend>,
        store: Arc<McpAccessStore>,
        key_id: String,
        builtin_tools: Arc<Vec<String>>,
    ) -> Self {
        Self { inner, store, key_id, builtin_tools }
    }

    async fn view(&self) -> Result<KeyView, String> {
        let teams = self.store.teams_for_key(&self.key_id).unwrap_or_default();
        let global = self.inner.load_mcp_global_policy().await?;
        let connections = self.inner.load_connections().await?;
        let groups = if teams.iter().any(|team| !team.group_ids.is_empty())
            || dbx_core::mcp_policy::policy_uses_connection_groups(&global)
        {
            self.inner.load_connection_group_details().await?
        } else {
            HashMap::new()
        };
        let team_refs = teams.iter().collect::<Vec<_>>();
        let visible = scope::visible_connections(&global, &team_refs, &connections, &groups);
        let policy = scope::narrow_policy(&global, &visible, &groups, &self.builtin_tools);
        let connections = connections.into_iter().filter(|connection| visible.contains_key(&connection.id)).collect();
        Ok(KeyView { policy, visible, connections })
    }

    async fn ensure_visible(&self, connection_id: &str) -> Result<(), String> {
        if self.view().await?.visible.contains_key(connection_id) {
            Ok(())
        } else {
            Err(OUT_OF_SCOPE.to_string())
        }
    }
}

#[async_trait]
impl DbxBackend for KeyScopedBackend {
    async fn load_mcp_global_policy(&self) -> Result<McpGlobalPolicy, String> {
        Ok(self.view().await?.policy)
    }

    async fn load_connections(&self) -> Result<Vec<ConnectionConfig>, String> {
        Ok(self.view().await?.connections)
    }

    async fn save_history_entry(&self, entry: &HistoryEntry) -> Result<(), String> {
        self.inner.save_history_entry(entry).await
    }

    async fn list_databases(&self, connection: &ConnectionConfig) -> Result<Vec<String>, String> {
        self.ensure_visible(&connection.id).await?;
        self.inner.list_databases(connection).await
    }

    async fn load_connection_group_paths(&self) -> Result<HashMap<String, Vec<String>>, String> {
        self.inner.load_connection_group_paths().await
    }

    async fn load_connection_group_details(&self) -> Result<HashMap<String, McpConnectionGroupPath>, String> {
        self.inner.load_connection_group_details().await
    }

    async fn execute_agent_tool(
        &self,
        connection: &ConnectionConfig,
        database: &str,
        tool_name: &str,
        arguments: Value,
        permissions: AgentSqlPermissions,
    ) -> ToolResult {
        if let Err(error) = self.ensure_visible(&connection.id).await {
            return ToolResult {
                tool_call_id: String::new(),
                tool_name: tool_name.to_string(),
                content: format!("Error: {error}"),
                is_error: true,
                explain_data: None,
            };
        }
        self.inner.execute_agent_tool(connection, database, tool_name, arguments, permissions).await
    }

    #[cfg(feature = "mq-admin")]
    async fn send_message(
        &self,
        connection: &ConnectionConfig,
        request: dbx_core::mq::SendMessageRequest,
    ) -> Result<dbx_core::mq::SendMessageResponse, String> {
        self.ensure_visible(&connection.id).await?;
        self.inner.send_message(connection, request).await
    }

    #[cfg(feature = "mq-admin")]
    async fn peek_messages(
        &self,
        connection: &ConnectionConfig,
        topic: dbx_core::mq::TopicRef,
        count: u32,
        options: dbx_core::mq::PeekMessagesOptions,
    ) -> Result<dbx_core::mq::PeekMessagesResult, String> {
        self.ensure_visible(&connection.id).await?;
        self.inner.peek_messages(connection, topic, count, options).await
    }

    async fn execute_query(
        &self,
        connection: &ConnectionConfig,
        database: &str,
        sql: &str,
        max_rows: Option<usize>,
        timeout_secs: Option<u64>,
    ) -> Result<dbx_core::db::QueryResult, String> {
        self.ensure_visible(&connection.id).await?;
        self.inner.execute_query(connection, database, sql, max_rows, timeout_secs).await
    }

    async fn open_transaction_owner(
        &self,
        connection: &ConnectionConfig,
        database: &str,
        client_session_id: &str,
    ) -> Result<Arc<TransactionOwner>, String> {
        self.ensure_visible(&connection.id).await?;
        self.inner.open_transaction_owner(connection, database, client_session_id).await
    }

    async fn execute_batch(
        &self,
        connection: &ConnectionConfig,
        database: &str,
        schema: Option<&str>,
        sql: &str,
        options: dbx_core::query::QueryExecutionOptions,
    ) -> Result<Vec<BatchStatementResult>, String> {
        self.ensure_visible(&connection.id).await?;
        self.inner.execute_batch(connection, database, schema, sql, options).await
    }

    async fn execution_plan(
        &self,
        connection: &ConnectionConfig,
        database: &str,
        sql: &str,
    ) -> dbx_core::sql::SqlExecutionPlan {
        self.inner.execution_plan(connection, database, sql).await
    }

    async fn add_connection_for_mcp(&self, _config: ConnectionConfig) -> Result<ConnectionConfig, String> {
        Err("TOOL_OUT_OF_SCOPE: API keys cannot manage connections".to_string())
    }

    async fn duplicate_connection_for_mcp(
        &self,
        _source_id: &str,
        _copy_id: &str,
        _copy_name: &str,
    ) -> Result<ConnectionConfig, String> {
        Err("TOOL_OUT_OF_SCOPE: API keys cannot manage connections".to_string())
    }

    async fn remove_connection_for_mcp(&self, _connection_id: &str) -> Result<bool, String> {
        Err("TOOL_OUT_OF_SCOPE: API keys cannot manage connections".to_string())
    }

    async fn list_tables(
        &self,
        connection: &ConnectionConfig,
        database: &str,
        schema: &str,
    ) -> Result<Vec<TableInfo>, String> {
        self.ensure_visible(&connection.id).await?;
        self.inner.list_tables(connection, database, schema).await
    }

    async fn get_columns(
        &self,
        connection: &ConnectionConfig,
        database: &str,
        schema: &str,
        table: &str,
    ) -> Result<Vec<ColumnInfo>, String> {
        self.ensure_visible(&connection.id).await?;
        self.inner.get_columns(connection, database, schema, table).await
    }

    async fn list_routines(
        &self,
        connection: &ConnectionConfig,
        database: &str,
        schema: &str,
        routine_types: Option<&[String]>,
    ) -> Result<Vec<dbx_core::db::ObjectInfo>, String> {
        self.ensure_visible(&connection.id).await?;
        self.inner.list_routines(connection, database, schema, routine_types).await
    }

    async fn get_routine_source(
        &self,
        connection: &ConnectionConfig,
        database: &str,
        schema: &str,
        name: &str,
        object_type: &str,
        signature: Option<&str>,
    ) -> Result<dbx_core::db::ObjectSource, String> {
        self.ensure_visible(&connection.id).await?;
        self.inner.get_routine_source(connection, database, schema, name, object_type, signature).await
    }

    async fn execute_redis_command(
        &self,
        connection: &ConnectionConfig,
        database: u32,
        command: &str,
        skip_safety_check: bool,
    ) -> Result<RedisCommandResult, String> {
        self.ensure_visible(&connection.id).await?;
        self.inner.execute_redis_command(connection, database, command, skip_safety_check).await
    }

    async fn execute_mongo_command(
        &self,
        connection: &ConnectionConfig,
        database: &str,
        command: &MongoCommand,
    ) -> Result<dbx_core::db::QueryResult, String> {
        self.ensure_visible(&connection.id).await?;
        self.inner.execute_mongo_command(connection, database, command).await
    }

    async fn salesforce_current_user(&self, connection: &ConnectionConfig) -> Result<SalesforceCurrentUser, String> {
        self.ensure_visible(&connection.id).await?;
        self.inner.salesforce_current_user(connection).await
    }

    async fn close_client_session(
        &self,
        connection_id: &str,
        database: &str,
        client_session_id: &str,
    ) -> Result<bool, String> {
        // Cleanup stays allowed after the key loses access so pinned pools
        // and transactions are always released.
        self.inner.close_client_session(connection_id, database, client_session_id).await
    }

    async fn bridge_request(&self, _path: &str, _body: Value) -> Result<(), String> {
        Err("DBX UI bridge operations are not available to API keys".to_string())
    }

    async fn collect_docs_snapshot(
        &self,
        connection: &ConnectionConfig,
        database: &str,
        options: DocsSnapshotOptions,
    ) -> Result<dbx_core::docs::SchemaSnapshot, String> {
        self.ensure_visible(&connection.id).await?;
        self.inner.collect_docs_snapshot(connection, database, options).await
    }
}
