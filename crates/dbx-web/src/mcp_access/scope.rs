//! Narrows the global MCP policy to what one API key may reach. Every
//! transformation here is monotonic: it can hide connections, remove tools, or
//! lower execution modes, but never widen anything the global policy allows.

use std::collections::{BTreeMap, HashMap};

use dbx_core::mcp_policy::{policy_allows_connection, McpConnectionGroupPath, MCP_EXECUTION_POLICY_VERSION};
use dbx_core::models::connection::ConnectionConfig;
use dbx_core::storage::{McpConnectionPolicy, McpDatabaseScope, McpGlobalPolicy};

use super::model::{McpTeam, TeamAccess};

/// Connection management would let a key create or copy connections outside
/// its teams, so it stays reserved for the master token.
pub const KEY_FORBIDDEN_TOOLS: [&str; 3] = ["dbx_add_connection", "dbx_duplicate_connection", "dbx_remove_connection"];

/// Access of every connection the key can see, keyed by connection id.
/// A connection reachable through several teams gets the widest team access.
pub fn visible_connections(
    global: &McpGlobalPolicy,
    teams: &[&McpTeam],
    connections: &[ConnectionConfig],
    groups: &HashMap<String, McpConnectionGroupPath>,
) -> BTreeMap<String, TeamAccess> {
    let mut visible = BTreeMap::new();
    for connection in connections {
        let path = groups.get(&connection.id);
        if !policy_allows_connection(global, path, &connection.id) {
            continue;
        }
        let access = teams
            .iter()
            .filter(|team| {
                team.connection_ids.iter().any(|id| *id == connection.id)
                    || path.is_some_and(|path| path.ids.iter().any(|id| team.group_ids.contains(id)))
            })
            .map(|team| team.access)
            .max();
        if let Some(access) = access {
            visible.insert(connection.id.clone(), access);
        }
    }
    visible
}

pub fn narrow_policy(
    global: &McpGlobalPolicy,
    visible: &BTreeMap<String, TeamAccess>,
    groups: &HashMap<String, McpConnectionGroupPath>,
    builtin_tools: &[String],
) -> McpGlobalPolicy {
    let mut policy = global.clone();
    // Groups are expanded to concrete ids so a global group grant cannot
    // re-admit connections outside the key's teams.
    policy.allowed_connection_ids = Some(visible.keys().cloned().collect());
    policy.allowed_group_ids = Vec::new();
    policy.connection_policies.retain(|rule| visible.contains_key(&rule.connection_id));

    for (connection_id, access) in visible {
        let Some(ceiling) = access.ceiling() else { continue };
        let group_ids = groups.get(connection_id).map(|path| path.ids.as_slice()).unwrap_or_default();
        match policy.connection_policies.iter_mut().find(|rule| rule.connection_id == *connection_id) {
            Some(rule) => clamp_rule(rule, inherited_mode(global, group_ids), ceiling),
            None => policy.connection_policies.push(ceiling_rule(connection_id, ceiling)),
        }
    }

    let tools = global.allowed_tool_names.clone().unwrap_or_else(|| builtin_tools.to_vec());
    policy.allowed_tool_names =
        Some(tools.into_iter().filter(|name| !KEY_FORBIDDEN_TOOLS.contains(&name.as_str())).collect());
    policy
}

/// Mode a versioned rule without a configured execution mode inherits:
/// the global default overridden by the closest configured group.
fn inherited_mode(global: &McpGlobalPolicy, group_ids: &[String]) -> (bool, bool) {
    let mut effective = (global.read_only, global.allow_dangerous_sql);
    for group_id in group_ids {
        if let Some(rule) = global.group_policies.iter().find(|rule| rule.group_id == *group_id) {
            effective = (rule.read_only, !rule.read_only && rule.allow_dangerous_sql);
        }
    }
    effective
}

fn apply_ceiling(current: (bool, bool), ceiling: (bool, bool)) -> (bool, bool) {
    let read_only = current.0 || ceiling.0;
    (read_only, !read_only && current.1 && ceiling.1)
}

fn clamp_rule(rule: &mut McpConnectionPolicy, inherited: (bool, bool), ceiling: (bool, bool)) {
    let versioned = rule.execution_mode_policy_version == Some(MCP_EXECUTION_POLICY_VERSION);
    let current = if rule.execution_mode_configured {
        (rule.read_only, rule.allow_dangerous_sql)
    } else if versioned {
        // Versioned rules without a mode inherit; pin the inherited mode so the
        // ceiling can apply. Legacy rules without a mode become a pure ceiling.
        inherited
    } else {
        (false, true)
    };
    (rule.read_only, rule.allow_dangerous_sql) = apply_ceiling(current, ceiling);
    rule.execution_mode_configured = true;
    // Versioned database rules override the connection mode and legacy ones
    // are ceilings; clamping both keeps each at or below the key ceiling.
    for database in &mut rule.database_policies {
        (database.read_only, database.allow_dangerous_sql) =
            apply_ceiling((database.read_only, database.allow_dangerous_sql), ceiling);
    }
    if ceiling.0 {
        rule.allow_salesforce_dml = false;
    }
}

/// A legacy (unversioned) rule is interpreted as a ceiling on the inherited
/// mode, which is exactly the "never widen" semantics a key needs.
fn ceiling_rule(connection_id: &str, ceiling: (bool, bool)) -> McpConnectionPolicy {
    McpConnectionPolicy {
        connection_id: connection_id.to_string(),
        read_only: ceiling.0,
        allow_dangerous_sql: ceiling.1,
        execution_mode_configured: true,
        execution_mode_policy_version: None,
        database_scope: McpDatabaseScope::All,
        allowed_databases: Vec::new(),
        database_policies: Vec::new(),
        allow_salesforce_dml: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbx_core::mcp_policy::effective_database_execution_policy_with_groups;
    use dbx_core::storage::{McpDatabasePolicy, McpGroupPolicy};

    fn connection(id: &str) -> ConnectionConfig {
        serde_json::from_value(serde_json::json!({
            "id": id, "name": id, "db_type": "mysql", "host": "127.0.0.1", "port": 3306,
            "username": "root", "password": ""
        }))
        .unwrap()
    }

    fn team(id: &str, connections: &[&str], groups: &[&str], access: TeamAccess) -> McpTeam {
        McpTeam {
            id: id.to_string(),
            name: id.to_string(),
            description: String::new(),
            connection_ids: connections.iter().map(|id| id.to_string()).collect(),
            group_ids: groups.iter().map(|id| id.to_string()).collect(),
            access,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn groups() -> HashMap<String, McpConnectionGroupPath> {
        HashMap::from([
            (
                "in-group".to_string(),
                McpConnectionGroupPath { ids: vec!["g-root".into(), "g-child".into()], names: vec![] },
            ),
            ("other-group".to_string(), McpConnectionGroupPath { ids: vec!["g-other".into()], names: vec![] }),
        ])
    }

    fn all() -> Vec<ConnectionConfig> {
        ["a", "b", "in-group", "other-group"].into_iter().map(connection).collect()
    }

    fn tools() -> Vec<String> {
        ["dbx_list_connections", "dbx_execute_query", "dbx_add_connection", "dbx_remove_connection"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }

    fn mode(policy: &McpGlobalPolicy, connection: &str, database: &str) -> (bool, bool) {
        let group_ids = groups().get(connection).map(|path| path.ids.clone()).unwrap_or_default();
        effective_database_execution_policy_with_groups(policy, &group_ids, connection, database)
    }

    #[test]
    fn keys_see_union_of_teams_and_expand_nested_groups() {
        let global = McpGlobalPolicy::default();
        let t1 = team("t1", &["a"], &[], TeamAccess::ReadOnly);
        let t2 = team("t2", &["a"], &["g-child"], TeamAccess::ReadWrite);
        let visible = visible_connections(&global, &[&t1, &t2], &all(), &groups());
        assert_eq!(
            visible.into_iter().collect::<Vec<_>>(),
            [("a".to_string(), TeamAccess::ReadWrite), ("in-group".to_string(), TeamAccess::ReadWrite)]
        );
    }

    #[test]
    fn global_allowlist_still_bounds_team_connections() {
        let global = McpGlobalPolicy { allowed_connection_ids: Some(vec!["b".into()]), ..Default::default() };
        let t = team("t", &["a", "b"], &["g-root"], TeamAccess::ReadWriteDangerous);
        let visible = visible_connections(&global, &[&t], &all(), &groups());
        assert_eq!(visible.keys().collect::<Vec<_>>(), ["b"]);

        let narrowed = narrow_policy(
            &McpGlobalPolicy { allowed_group_ids: vec!["g-other".into()], ..global },
            &visible,
            &groups(),
            &tools(),
        );
        assert_eq!(narrowed.allowed_connection_ids, Some(vec!["b".to_string()]));
        assert!(narrowed.allowed_group_ids.is_empty());
        assert!(!policy_allows_connection(&narrowed, groups().get("other-group"), "other-group"));
    }

    #[test]
    fn keys_never_get_connection_management_tools() {
        let visible = BTreeMap::from([("a".to_string(), TeamAccess::ReadWriteDangerous)]);
        let narrowed = narrow_policy(&McpGlobalPolicy::default(), &visible, &groups(), &tools());
        assert_eq!(
            narrowed.allowed_tool_names,
            Some(vec!["dbx_list_connections".to_string(), "dbx_execute_query".to_string()])
        );

        let global = McpGlobalPolicy {
            allowed_tool_names: Some(vec!["dbx_execute_query".into(), "dbx_add_connection".into()]),
            ..Default::default()
        };
        assert_eq!(
            narrow_policy(&global, &visible, &groups(), &tools()).allowed_tool_names,
            Some(vec!["dbx_execute_query".to_string()])
        );
    }

    #[test]
    fn read_only_team_forces_read_only_without_existing_rule() {
        let global = McpGlobalPolicy { read_only: false, allow_dangerous_sql: true, ..Default::default() };
        let visible = BTreeMap::from([
            ("a".to_string(), TeamAccess::ReadOnly),
            ("b".to_string(), TeamAccess::ReadWrite),
            ("in-group".to_string(), TeamAccess::ReadWriteDangerous),
        ]);
        let narrowed = narrow_policy(&global, &visible, &groups(), &tools());
        assert_eq!(mode(&narrowed, "a", "app"), (true, false));
        assert_eq!(mode(&narrowed, "b", "app"), (false, false));
        assert_eq!(mode(&narrowed, "in-group", "app"), (false, true));
    }

    #[test]
    fn team_access_never_widens_a_read_only_global_policy() {
        let global = McpGlobalPolicy {
            read_only: true,
            group_policies: vec![McpGroupPolicy {
                group_id: "g-root".into(),
                read_only: true,
                allow_dangerous_sql: false,
            }],
            ..Default::default()
        };
        let visible = BTreeMap::from([
            ("a".to_string(), TeamAccess::ReadWrite),
            ("in-group".to_string(), TeamAccess::ReadWriteDangerous),
        ]);
        let narrowed = narrow_policy(&global, &visible, &groups(), &tools());
        assert_eq!(mode(&narrowed, "a", "app"), (true, false));
        assert_eq!(mode(&narrowed, "in-group", "app"), (true, false));
    }

    #[test]
    fn existing_versioned_and_database_rules_are_clamped() {
        let versioned = McpConnectionPolicy {
            database_policies: vec![McpDatabasePolicy {
                database_name: "prod".into(),
                read_only: false,
                allow_dangerous_sql: true,
            }],
            allow_salesforce_dml: true,
            execution_mode_configured: false,
            execution_mode_policy_version: Some(MCP_EXECUTION_POLICY_VERSION),
            ..ceiling_rule("in-group", (false, true))
        };
        let legacy = McpConnectionPolicy { execution_mode_configured: false, ..ceiling_rule("b", (false, false)) };
        let global = McpGlobalPolicy {
            allow_dangerous_sql: true,
            group_policies: vec![McpGroupPolicy {
                group_id: "g-child".into(),
                read_only: false,
                allow_dangerous_sql: true,
            }],
            connection_policies: vec![versioned, legacy, ceiling_rule("hidden", (false, true))],
            ..Default::default()
        };
        assert_eq!(mode(&global, "in-group", "prod"), (false, true));
        assert_eq!(mode(&global, "in-group", "other"), (false, true));

        let visible =
            BTreeMap::from([("in-group".to_string(), TeamAccess::ReadWrite), ("b".to_string(), TeamAccess::ReadOnly)]);
        let narrowed = narrow_policy(&global, &visible, &groups(), &tools());
        assert_eq!(mode(&narrowed, "in-group", "prod"), (false, false));
        assert_eq!(mode(&narrowed, "in-group", "other"), (false, false));
        assert_eq!(mode(&narrowed, "b", "app"), (true, false));
        assert!(narrowed.connection_policies.iter().all(|rule| rule.connection_id != "hidden"));

        let read_only = narrow_policy(
            &global,
            &BTreeMap::from([("in-group".to_string(), TeamAccess::ReadOnly)]),
            &groups(),
            &tools(),
        );
        assert_eq!(mode(&read_only, "in-group", "prod"), (true, false));
        assert!(!dbx_core::mcp_policy::connection_allows_salesforce_dml(&read_only, "in-group"));
    }

    #[test]
    fn keys_without_teams_see_nothing() {
        let visible = visible_connections(&McpGlobalPolicy::default(), &[], &all(), &groups());
        assert!(visible.is_empty());
        let narrowed = narrow_policy(&McpGlobalPolicy::default(), &visible, &groups(), &tools());
        assert_eq!(narrowed.allowed_connection_ids, Some(Vec::new()));
        assert!(!policy_allows_connection(&narrowed, None, "a"));
    }
}
