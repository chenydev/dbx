use std::{
    collections::{HashMap, HashSet},
    net::Ipv6Addr,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use url::Url;

/// Authenticated caller of the HTTP endpoint. The shared bearer token maps to
/// `Master`; hosts that install an [`McpKeyResolver`] may map additional API
/// keys to their own principals and scope the backend per principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpPrincipal {
    /// Stable identifier used for session binding and backend scoping.
    pub id: String,
    /// Human-readable label for audit logs. Never contains secret material.
    pub label: String,
    pub kind: McpPrincipalKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpPrincipalKind {
    Master,
    ApiKey,
}

impl McpPrincipal {
    pub fn master() -> Self {
        Self { id: "master".to_string(), label: "master-token".to_string(), kind: McpPrincipalKind::Master }
    }
}

/// Resolves bearer tokens other than the shared master token. Implementations
/// must be cheap and non-blocking: they run inside the request middleware.
pub trait McpKeyResolver: Send + Sync {
    fn resolve(&self, token: &str) -> Option<McpPrincipal>;
}

tokio::task_local! {
    static CURRENT_PRINCIPAL: McpPrincipal;
}

/// Principal of the HTTP request currently being served. rmcp creates the
/// per-session server synchronously inside the request future, so session
/// factories can use this to pick a principal-scoped backend.
pub fn current_principal() -> Option<McpPrincipal> {
    CURRENT_PRINCIPAL.try_with(Clone::clone).ok()
}

const SESSION_HEADER: &str = "mcp-session-id";
const SESSION_BINDING_IDLE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const SESSION_BINDING_CAPACITY: usize = 10_000;

/// MCP session id -> owning principal id. Only enforced while a key resolver
/// is installed, so one API key can never drive another key's session.
#[derive(Default)]
struct SessionBindings {
    owners: HashMap<String, (String, Instant)>,
}

impl SessionBindings {
    fn owner(&mut self, session_id: &str) -> Option<String> {
        let entry = self.owners.get_mut(session_id)?;
        entry.1 = Instant::now();
        Some(entry.0.clone())
    }

    fn bind(&mut self, session_id: String, principal_id: String) {
        let now = Instant::now();
        self.owners.retain(|_, (_, seen)| now.duration_since(*seen) < SESSION_BINDING_IDLE_TTL);
        if self.owners.len() >= SESSION_BINDING_CAPACITY {
            if let Some(oldest) =
                self.owners.iter().min_by_key(|(_, (_, seen))| *seen).map(|(session_id, _)| session_id.clone())
            {
                self.owners.remove(&oldest);
            }
        }
        self.owners.insert(session_id, (principal_id, now));
    }

    fn unbind(&mut self, session_id: &str) {
        self.owners.remove(session_id);
    }
}

/// Authentication and browser-origin policy for the Streamable HTTP endpoint.
/// The token is intentionally not `Debug` and is never exposed by diagnostics.
#[derive(Clone)]
pub struct HttpAuth {
    config: Arc<RwLock<HttpAuthConfig>>,
    key_resolver: Arc<RwLock<Option<Arc<dyn McpKeyResolver>>>>,
    sessions: Arc<Mutex<SessionBindings>>,
}

#[derive(Clone)]
struct HttpAuthConfig {
    token: Option<Arc<[u8]>>,
    allowed_hosts: Vec<HostRule>,
    allowed_origins: HashSet<String>,
    allow_loopback_origins: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HostRule {
    host: String,
    port: Option<u16>,
}

impl HttpAuth {
    pub fn new(
        token: String,
        allowed_origins: impl IntoIterator<Item = String>,
        allow_loopback_origins: bool,
    ) -> Result<Self, String> {
        Self::new_with_hosts(Some(token), Vec::<String>::new(), allowed_origins, allow_loopback_origins)
    }

    pub fn new_with_hosts(
        token: Option<String>,
        allowed_hosts: impl IntoIterator<Item = String>,
        allowed_origins: impl IntoIterator<Item = String>,
        allow_loopback_origins: bool,
    ) -> Result<Self, String> {
        let config = HttpAuthConfig {
            token: validate_token(token)?.map(|token| Arc::from(token.into_bytes())),
            allowed_hosts: normalize_hosts(allowed_hosts)?,
            allowed_origins: normalize_origins(allowed_origins)?,
            allow_loopback_origins,
        };
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            key_resolver: Arc::new(RwLock::new(None)),
            sessions: Arc::new(Mutex::new(SessionBindings::default())),
        })
    }

    /// Installs (or removes) the resolver for additional API keys. The shared
    /// master token keeps working either way; API keys are only accepted while
    /// the endpoint itself is enabled by a master token.
    pub fn set_key_resolver(&self, resolver: Option<Arc<dyn McpKeyResolver>>) {
        *self.key_resolver.write().unwrap_or_else(|error| error.into_inner()) = resolver;
    }

    fn resolver(&self) -> Option<Arc<dyn McpKeyResolver>> {
        self.key_resolver.read().unwrap_or_else(|error| error.into_inner()).clone()
    }

    /// Replaces the live bearer token and request-origin/host policy. The
    /// shared lock lets embedded Web MCP rotate credentials without rebuilding
    /// the Axum router or dropping existing application state.
    pub fn reconfigure(
        &self,
        token: Option<String>,
        allowed_hosts: impl IntoIterator<Item = String>,
        allowed_origins: impl IntoIterator<Item = String>,
    ) -> Result<(), String> {
        let next = HttpAuthConfig {
            token: validate_token(token)?.map(|token| Arc::from(token.into_bytes())),
            allowed_hosts: normalize_hosts(allowed_hosts)?,
            allowed_origins: normalize_origins(allowed_origins)?,
            allow_loopback_origins: self
                .config
                .read()
                .unwrap_or_else(|error| error.into_inner())
                .allow_loopback_origins,
        };
        *self.config.write().unwrap_or_else(|error| error.into_inner()) = next;
        Ok(())
    }

    pub fn set_allowed_hosts(&self, allowed_hosts: impl IntoIterator<Item = String>) -> Result<(), String> {
        let allowed_hosts = normalize_hosts(allowed_hosts)?;
        self.config.write().unwrap_or_else(|error| error.into_inner()).allowed_hosts = allowed_hosts;
        Ok(())
    }

    pub fn enabled(&self) -> bool {
        self.config.read().unwrap_or_else(|error| error.into_inner()).token.is_some()
    }

    #[cfg(test)]
    fn token_matches(&self, candidate: &str) -> bool {
        let config = self.config.read().unwrap_or_else(|error| error.into_inner());
        token_matches(&config, candidate)
    }

    pub fn origin_is_allowed(&self, origin: &str) -> bool {
        let config = self.config.read().unwrap_or_else(|error| error.into_inner());
        origin_is_allowed(&config, origin)
    }

    #[cfg(test)]
    fn host_is_allowed(&self, uri: &Uri, headers: &axum::http::HeaderMap) -> bool {
        let config = self.config.read().unwrap_or_else(|error| error.into_inner());
        host_is_allowed(&config, uri, headers)
    }
}

fn token_matches(config: &HttpAuthConfig, candidate: &str) -> bool {
    let Some(token) = config.token.as_ref() else {
        return false;
    };
    let candidate = candidate.as_bytes();
    if candidate.len() != token.len() {
        return false;
    }

    // Keep comparison work independent of the first mismatching byte.
    let difference =
        token.iter().zip(candidate).fold(0_u8, |difference, (expected, actual)| difference | (expected ^ actual));
    difference == 0
}

fn origin_is_allowed(config: &HttpAuthConfig, origin: &str) -> bool {
    let Ok(origin) = normalize_origin(origin) else {
        return false;
    };
    config.allowed_origins.contains(&origin) || (config.allow_loopback_origins && origin_is_loopback(&origin))
}

fn host_is_allowed(config: &HttpAuthConfig, uri: &Uri, headers: &axum::http::HeaderMap) -> bool {
    let authority = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| uri.authority().map(|authority| authority.as_str()));
    let Some(authority) = authority.and_then(|value| parse_host_rule(value).ok()) else {
        return false;
    };
    config.allowed_hosts.is_empty()
        || config.allowed_hosts.iter().any(|allowed| {
            allowed.host == authority.host && allowed.port.is_none_or(|port| authority.port == Some(port))
        })
}

pub async fn authorize_request(State(auth): State<HttpAuth>, request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let principal = {
        let config = auth.config.read().unwrap_or_else(|error| error.into_inner());
        if config.token.is_none() {
            log::warn!(target: "dbx_mcp::audit", "MCP HTTP request rejected: method={method} path={path} reason=server-disabled");
            return not_found();
        }

        if let Some(origin) = request.headers().get(header::ORIGIN) {
            let origin = match origin.to_str() {
                Ok(origin) => origin,
                Err(_) => {
                    log::warn!(target: "dbx_mcp::audit", "MCP HTTP request rejected: method={method} path={path} reason=invalid-origin");
                    return forbidden();
                }
            };
            if !origin_is_allowed(&config, origin) {
                log::warn!(target: "dbx_mcp::audit", "MCP HTTP request rejected: method={method} path={path} origin={origin} reason=origin-not-allowed");
                return forbidden();
            }
        }

        if !host_is_allowed(&config, request.uri(), request.headers()) {
            log::warn!(target: "dbx_mcp::audit", "MCP HTTP request rejected: method={method} path={path} reason=host-not-allowed");
            return forbidden();
        }

        let Some(token) = bearer_token(request.headers().get(header::AUTHORIZATION)) else {
            log::warn!(target: "dbx_mcp::audit", "MCP HTTP request rejected: method={method} path={path} reason=missing-bearer-token");
            return unauthorized();
        };
        if token_matches(&config, token) {
            Some(McpPrincipal::master())
        } else {
            None
        }
    };
    let resolver = auth.resolver();
    let principal = match principal {
        Some(principal) => principal,
        None => {
            let resolved = bearer_token(request.headers().get(header::AUTHORIZATION))
                .and_then(|token| resolver.as_ref().and_then(|resolver| resolver.resolve(token)));
            let Some(principal) = resolved else {
                log::warn!(target: "dbx_mcp::audit", "MCP HTTP request rejected: method={method} path={path} reason=invalid-bearer-token");
                return unauthorized();
            };
            principal
        }
    };
    let label = principal.label.clone();

    let session_id =
        request.headers().get(SESSION_HEADER).and_then(|value| value.to_str().ok()).map(ToOwned::to_owned);
    let enforce_sessions = resolver.is_some();
    if enforce_sessions {
        if let Some(session_id) = session_id.as_deref() {
            let owner = auth.sessions.lock().unwrap_or_else(|error| error.into_inner()).owner(session_id);
            if owner.as_deref() != Some(principal.id.as_str()) {
                log::warn!(target: "dbx_mcp::audit", "MCP HTTP request rejected: method={method} path={path} principal={label} reason=session-not-owned");
                return not_found();
            }
        }
    }

    let mut request = request;
    request.extensions_mut().insert(principal.clone());
    let principal_id = principal.id.clone();
    let response = CURRENT_PRINCIPAL.scope(principal, next.run(request)).await;

    if enforce_sessions {
        let mut sessions = auth.sessions.lock().unwrap_or_else(|error| error.into_inner());
        match session_id {
            None => {
                if let Some(created) = response.headers().get(SESSION_HEADER).and_then(|value| value.to_str().ok()) {
                    sessions.bind(created.to_string(), principal_id);
                }
            }
            Some(session_id) if method == axum::http::Method::DELETE && response.status().is_success() => {
                sessions.unbind(&session_id);
            }
            Some(_) => {}
        }
    }
    log::info!(target: "dbx_mcp::audit", "MCP HTTP request authenticated: method={method} path={path} principal={label} status={}", response.status());
    response
}

fn bearer_token(value: Option<&HeaderValue>) -> Option<&str> {
    let value = value?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() && !token.contains(char::is_whitespace))
        .then_some(token)
}

fn normalize_origin(origin: &str) -> Result<String, String> {
    let url = Url::parse(origin).map_err(|_| format!("invalid allowed origin: {origin}"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(format!("allowed origin must be an HTTP(S) origin without a path: {origin}"));
    }
    Ok(url.origin().ascii_serialization())
}

fn origin_is_loopback(origin: &str) -> bool {
    let Ok(url) = Url::parse(origin) else {
        return false;
    };
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()),
        None => false,
    }
}

fn unauthorized() -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "Forbidden").into_response()
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

fn validate_token(token: Option<String>) -> Result<Option<String>, String> {
    token
        .map(|token| {
            let token = token.trim().to_string();
            if token.is_empty() || token.contains(char::is_whitespace) {
                return Err("MCP HTTP bearer token must be non-empty and contain no whitespace".into());
            }
            Ok(token)
        })
        .transpose()
}

fn normalize_origins(origins: impl IntoIterator<Item = String>) -> Result<HashSet<String>, String> {
    origins.into_iter().map(|origin| normalize_origin(&origin)).collect()
}

fn normalize_hosts(hosts: impl IntoIterator<Item = String>) -> Result<Vec<HostRule>, String> {
    hosts.into_iter().map(|host| parse_host_rule(&host)).collect()
}

fn parse_host_rule(value: &str) -> Result<HostRule, String> {
    let value = value.trim();
    // `Authority` requires IPv6 literals to use URI brackets (`[::1]`), while
    // the loopback defaults and settings UI naturally expose the bare form
    // (`::1`). Normalize that form before parsing so loopback HTTP services do
    // not fail immediately during startup.
    let normalized = if value.parse::<Ipv6Addr>().is_ok() { format!("[{value}]") } else { value.to_string() };
    let authority = axum::http::uri::Authority::try_from(normalized.as_str())
        .map_err(|_| format!("invalid allowed host: {value}"))?;
    if value.contains('@') {
        return Err(format!("invalid allowed host: {value}"));
    }
    let host = authority.host().to_ascii_lowercase();
    if host.is_empty() {
        return Err(format!("invalid allowed host: {value}"));
    }
    Ok(HostRule { host, port: authority.port_u16() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_rotation_rejects_old_token_and_updates_hosts_and_origins() {
        let auth = HttpAuth::new_with_hosts(
            Some("old-token".to_string()),
            ["dbx.example.test:4224".to_string()],
            ["https://client.example.test".to_string()],
            false,
        )
        .unwrap();
        let route_auth = auth.clone();
        let uri: Uri = "/mcp".parse().unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("dbx.example.test:4224"));
        assert!(route_auth.token_matches("old-token"));
        assert!(route_auth.host_is_allowed(&uri, &headers));
        assert!(route_auth.origin_is_allowed("https://client.example.test"));

        auth.reconfigure(
            Some("new-token".to_string()),
            ["new.example.test:443".to_string()],
            ["https://new-client.example.test".to_string()],
        )
        .unwrap();
        assert!(!route_auth.token_matches("old-token"));
        assert!(route_auth.token_matches("new-token"));
        assert!(!route_auth.host_is_allowed(&uri, &headers));
        assert!(!route_auth.origin_is_allowed("https://client.example.test"));

        auth.reconfigure(None, Vec::<String>::new(), Vec::<String>::new()).unwrap();
        assert!(!route_auth.enabled());
        assert!(!route_auth.token_matches("new-token"));
    }

    #[test]
    fn host_validation_requires_exact_port_when_configured() {
        let auth = HttpAuth::new_with_hosts(
            Some("token".to_string()),
            ["192.168.0.77:4224".to_string()],
            Vec::<String>::new(),
            false,
        )
        .unwrap();
        let uri: Uri = "/mcp".parse().unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("192.168.0.77:4224"));
        assert!(auth.host_is_allowed(&uri, &headers));
        headers.insert(header::HOST, HeaderValue::from_static("192.168.0.77:5225"));
        assert!(!auth.host_is_allowed(&uri, &headers));
        assert!(parse_host_rule("https://dbx.example.test").is_err());
        assert!(parse_host_rule("user@dbx.example.test:4224").is_err());
        assert!(parse_host_rule("[::1]").is_ok());
    }

    #[test]
    fn bare_ipv6_loopback_host_is_normalized_for_uri_authority_parsing() {
        let auth = HttpAuth::new_with_hosts(Some("token".to_string()), ["::1".to_string()], Vec::<String>::new(), true)
            .unwrap();
        let uri: Uri = "/mcp".parse().unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("[::1]"));
        assert!(auth.host_is_allowed(&uri, &headers));
    }
}
