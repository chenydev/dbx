# DBX Web：MCP 多 API Key + Team 访问隔离 设计与实施计划

> 分支：`feat/web-mcp-api-keys`　基线：`t8y2/dbx@4bcab0148`
> 范围：**只改 Web 端**（`crates/dbx-web` + 前端 Web 模式）。桌面端 / Tauri / 独立 `dbx-mcp` 二进制行为保持不变。

## 1. 背景与现状

| 项 | 现状 | 位置 |
| --- | --- | --- |
| Web MCP 端点 | `/mcp`（Streamable HTTP），挂在 dbx-web 同一进程里 | `crates/dbx-web/src/main.rs` `web_mcp_router` |
| 认证 | **单一** Bearer token（环境变量 / 文件 / Web 设置里生成），常量时间比较 | `crates/dbx-mcp/src/http_auth.rs`、`crates/dbx-web/src/web_mcp.rs` |
| 授权 | 全局 `McpGlobalPolicy`：连接白名单、侧边栏分组白名单、工具白名单、只读/危险 SQL、库级规则 | `crates/dbx-core/src/persistence/storage.rs`、`crates/dbx-core/src/ai/mcp_policy.rs` |
| Policy 读取入口 | MCP server 所有授权判断都经过 `backend.load_mcp_global_policy()` 和 `backend.load_connections()` | `crates/dbx-mcp/src/server.rs` `load_scoped_connections` / `load_policy` |
| MCP 会话 | rmcp `StreamableHttpService`，每个 MCP 会话由工厂闭包 `DbxMcpServer::with_runtime_options(backend, …)` 创建；工厂在 initialize 请求的 future 内**同步**调用 | rmcp 2.2 `tower.rs::handle_post` |

问题：所有 MCP 客户端共用一个 token，看到同一批连接，无法按团队隔离，也不能单独吊销。

## 2. 目标 / 非目标

**目标**
1. 管理员可创建任意多个 **API Key**（类似 OpenAI / GitHub PAT）：只在创建时显示一次明文，服务端只存 SHA-256 哈希。
2. 引入 **Team（团队/分组）**：每个 Team 拥有一组数据库连接（直接选连接 + 选侧边栏分组，分组内连接动态生效）以及执行上限（只读 / 读写 / 读写+危险 SQL）。
3. 一个 Key 可绑定**多个 Team**；Key 通过 MCP 只能看到、操作这些 Team 的连接的并集。
4. Key 支持：名称、启用/停用、过期时间、轮换、删除、最后使用时间。
5. 新增 Web 端 **「MCP 访问密钥」管理页面**（Team 管理 + Key 管理）。
6. 修改 Team/Key 后**实时生效**（包括已建立的 MCP 会话），吊销后立即拒绝。

**非目标（本期不做）**
- Web UI 本身的多用户/多租户登录（Web 仍是单管理员密码）。Team 仅作用于 MCP 访问面。
- 桌面端（Tauri）和独立 `dbx-mcp` 二进制的多 Key。
- 按 Key 的配额/限流、用量计费。

## 3. 核心概念与授权模型

```
API Key ──(n:m)── Team ──┬── connection_ids[]        (直接授权的连接)
                         ├── group_ids[]             (侧边栏分组，含子分组内的连接，动态)
                         └── access: readOnly | readWrite | readWriteDangerous
```

**有效权限 = 全局 MCP Policy ∩ Key 的 Team 授权**（只收窄，永不放宽）：

1. **可见连接**：连接 c 可见 ⇔ 全局 policy 允许 c **且** 存在 Key 绑定的 Team t，使 `c ∈ t.connection_ids` 或 c 的分组路径含 `t.group_ids` 之一。
2. **执行上限**：c 同时属于多个 Team 时取**最宽**的 access（并集语义）；再与全局/分组/连接/库级规则取**更严**者。
3. **工具**：Team Key 永远禁用连接管理工具 `dbx_add_connection` / `dbx_duplicate_connection` / `dbx_remove_connection`（防止越权创建/复制凭据）；其余与全局工具白名单取交集。
4. **旧版全局 Token**（现有 Web MCP token / `DBX_WEB_MCP_TOKEN`）保持原语义 = 管理员 Key（全局 policy，全部连接），保证向后兼容。
5. Key 停用 / 过期 / 删除 / 未绑定任何 Team → 认证失败或看不到任何连接（fail-closed）。

### Policy 收窄的具体实现（不改 core 语义）
在 `load_mcp_global_policy()` 返回前对全局 policy 做变换：
- `allowed_connection_ids = Some(可见连接集合的具体 id)`，`allowed_group_ids = []`（把分组展开成具体连接，避免与全局分组规则产生并集放宽）。
- 对 access 为 `readOnly` 的连接：已有连接规则 → 强制 `read_only=true, allow_dangerous_sql=false, allow_salesforce_dml=false`，其库级规则同样强制只读；无规则 → 追加一条 **legacy ceiling** 规则 `(read_only=true)`（legacy 规则语义是"上限"，只会收窄）。
- 对 access 为 `readWrite` 的连接：已有规则 → `allow_dangerous_sql=false`（含库级）；无规则 → 追加 legacy ceiling `(read_only=false, allow_dangerous_sql=false)`，按 `apply_ceiling` 只会关掉危险 SQL，不会放开只读。
- `allowed_tool_names`：`None` → 全部工具去掉连接管理类；`Some(list)` → 去掉连接管理类。
- `load_connections()` 同样只返回可见连接（纵深防御）。

## 4. 架构改动

### 4.1 `crates/dbx-mcp`（最小、向后兼容的钩子，桌面端不启用）
- `http_auth.rs`
  - 新增 `McpPrincipal { id: String, kind: Master | ApiKey { key_id } , label }`。
  - 新增 trait `McpKeyResolver: Send + Sync { fn resolve(&self, token: &str) -> Option<McpPrincipal>; }`，`HttpAuth::set_key_resolver(Option<Arc<dyn McpKeyResolver>>)`。
  - `authorize_request`：先比对旧 token（→ Master），否则交给 resolver（→ ApiKey）；都失败 401。`enabled()` = 有旧 token **或** 有 resolver 且 resolver 声明有可用 key。
  - 认证通过后：把 principal 放进 request extensions，并用 `tokio::task_local!` `CURRENT_MCP_PRINCIPAL` 包住 `next.run()`（rmcp 在同一 future 内同步调用会话工厂，因此工厂可读取）。
  - **会话绑定**（仅 resolver 启用时）：initialize 响应里的 `Mcp-Session-Id` 记录为 `session → principal.id`；之后带该会话头的请求 principal 不一致 → 404，防止 Key A 劫持 Key B 的会话（事务、会话状态）。DELETE 会话时移除；容量上限 + 过期清理。
  - 审计日志追加 `principal=<label>`。
- `http.rs`：新增 `streamable_http_router_with_backend_factory(factory: Arc<dyn Fn(Option<&McpPrincipal>) -> Result<Arc<dyn DbxBackend>, String>>, …)`；原 `streamable_http_router` 改为调用它（factory 恒返回同一 backend），行为不变。

### 4.2 `crates/dbx-web`
- 新模块 `mcp_access/`
  - `model.rs`：`McpTeam`、`McpApiKeyRecord`、`McpAccessDocument { version, teams, keys }`、`TeamAccess` 枚举。
  - `store.rs`：`McpAccessStore`——持久化到 `state_store` 表（key `web_mcp_access.v1`，JSON），无需改 core 表结构；内存索引 `sha256(token) → key_id`；CRUD；`last_used_at` 内存记录、60 秒批量落盘。
  - `resolver.rs`：实现 `McpKeyResolver`（查哈希、校验启用/过期、记录使用）。
  - `scoped_backend.rs`：`KeyScopedBackend { inner: Arc<dyn DbxBackend>, store, key_id }`，实现 `DbxBackend` 全部方法：policy/连接做第 3 节的收窄，其余透传。每次调用都从 store 读当前 Team 配置 → 修改实时生效。
  - 单元测试：收窄规则、只读上限、多 Team 并集、分组展开、吊销/过期、工具过滤。
- `routes/mcp_access.rs`（需要 Web 登录会话 + `X-DBX-MCP-Settings: 1` 防 CSRF + 已设置密码，与现有 Web MCP 设置相同的门槛）：

| Method | Path | 说明 |
| --- | --- | --- |
| GET | `/api/mcp-access/overview` | teams + keys（不含明文/哈希）+ 端点信息 + 可选连接/分组列表 |
| POST | `/api/mcp-access/teams` | 新建 Team |
| PUT | `/api/mcp-access/teams/{id}` | 修改 Team |
| DELETE | `/api/mcp-access/teams/{id}` | 删除 Team（同时从各 Key 解绑） |
| POST | `/api/mcp-access/keys` | 新建 Key → **返回一次性明文** |
| PUT | `/api/mcp-access/keys/{id}` | 改名/绑定 Team/启用停用/过期时间 |
| POST | `/api/mcp-access/keys/{id}/rotate` | 轮换 → 返回新明文，旧的立即失效 |
| DELETE | `/api/mcp-access/keys/{id}` | 删除（立即失效） |

- `main.rs`：启动时加载 store；`web_mcp_router` 改用 backend factory：`Master → LocalBackend`，`ApiKey → KeyScopedBackend`，无 principal → 报错（fail-closed）。
- demo 模式：`/api/mcp-access/*` 写操作禁止（沿用 demo gate）。

### 4.3 Key 格式与安全
- 明文：`dbxk_` + 64 位十六进制（256 bit 随机）；展示前缀 `dbxk_xxxxxxxx`（前 13 字符）。
- 存储：`sha256(明文)` 十六进制；高熵随机 token 不需要 argon2。明文不落盘、不写日志、列表接口不返回。
- 仍受现有 Web MCP 的 Host / Origin 白名单约束；Web MCP 总开关关闭时所有 Key 都不可用。

### 4.4 前端（仅 Web 模式）
- `lib/backend/http.ts` + `lib/backend/api.ts`：新增 `mcpAccess*` API（Tauri 实现抛 "unsupported"，桌面端不显示入口）。
- 新组件 `components/settings/WebMcpAccessKeysSettings.vue`，在设置对话框中新增 Web 专属分类 **「MCP 访问密钥」**：
  - **Team 列表**：名称、描述、连接数/分组数、权限级别；新建/编辑对话框（连接多选 + 侧边栏分组多选 + 权限级别）。
  - **Key 列表**：名称、前缀、绑定 Team（徽标）、状态（启用/停用/已过期）、过期时间、最后使用、创建时间；操作：编辑、停用/启用、轮换、删除（确认）。
  - **创建成功弹窗**：明文 Key 仅显示一次 + 复制按钮 + MCP 客户端配置片段（`{"url": ".../mcp", "headers": {"Authorization": "Bearer dbxk_…"}}`）。
  - Web MCP 未启用 / 未设置密码时显示提示并引导到 MCP 设置页。
- i18n：`zh-CN`、`en`（其余语言回退英文）。

## 5. 实施计划（按顺序执行）

| # | 任务 | 产出 / 验证 |
| --- | --- | --- |
| 0 | 开发环境：`nix develop`（仓库自带 flake devShell）+ `pnpm install` + `cargo build -p dbx-web` | 能编译、`pnpm dev:web` + `pnpm dev:backend` 可跑 |
| 1 | dbx-mcp 钩子：principal、resolver、task-local、会话绑定、backend factory 路由 | `cargo test -p dbx-mcp http_auth` 旧测试全过 + 新测试 |
| 2 | dbx-web `mcp_access` 模型 + store（state_store 持久化、哈希索引、last_used 批量落盘） | 单元测试：CRUD、重启恢复、明文不落盘 |
| 3 | `KeyScopedBackend` policy 收窄 | 单元测试：可见性、只读/危险上限、多 Team 并集、分组展开、工具过滤、吊销 |
| 4 | 路由 + main.rs 装配 | 集成测试：真实 `/mcp` 用不同 Key `tools/call dbx_list_connections` 只看到各自连接；吊销后 401；跨 Key 复用会话 404 |
| 5 | 前端 API + 管理页面 + i18n | `pnpm typecheck`、vitest |
| 6 | 端到端手测：`pnpm dev:web` + `pnpm dev:backend`，建 2 个 Team / 2 个 Key，用 curl 走 MCP 协议验证 | 截图/日志 |
| 7 | 文档：本文件 + `docs` 使用说明 | — |

## 6. 开发与验证（NixOS）

```sh
cd dbx
nix develop                      # 仓库自带 flake devShell：Rust 1.97 / Node 22 / pnpm 10 / webkitgtk 等
pnpm install --frozen-lockfile
pnpm dev:backend                 # cargo watch 运行 dbx-web（默认 :4224）
pnpm dev:web                     # Vite 前端 :5173，代理到后端
```

Web 模式下入口：设置 →「MCP 访问密钥」（需要先设置登录密码，并在「MCP → HTTP 服务」启用 Web MCP 并配置允许的 Host）。

自动化验证：

```sh
cargo test -p dbx-web mcp_access         # 收窄规则 / 存储 / 吊销（10 个）
cargo test -p dbx-mcp --lib http         # 认证钩子 + 会话绑定（含原有测试）
pnpm typecheck
npx vitest run apps/desktop/src/lib/settings apps/desktop/src/i18n

# 端到端：用 3 个 SQLite 连接走真实 /mcp 协议（20 项检查）
DBX_DATA_DIR=/tmp/dbx-e2e DBX_PORT=4299 DBX_PASSWORD=pass \
DBX_WEB_MCP_TOKEN=master-secret-token DBX_WEB_MCP_ALLOWED_HOSTS=127.0.0.1:4299 \
  target/debug/dbx-web &
python3 scripts/e2e-web-mcp-keys.py
```

MCP 客户端配置示例：

```json
{ "mcpServers": { "dbx": { "type": "http", "url": "https://dbx.example.com/mcp",
  "headers": { "Authorization": "Bearer dbxk_…" } } } }
```

## 7. 发布（fork：chenydev/dbx）

上游 workflow 在 fork 中全部停用，只启用 `.github/workflows/ghcr-release.yml`：

```sh
git push origin main
gh release create v0.6.25-keys.2 --target main --generate-notes   # 触发镜像构建
gh run watch                                                       # 查看构建
docker pull ghcr.io/chenydev/dbx:v0.6.25-keys.2
```

- 预发布（`--prerelease`）不更新 `latest`；重建已有 tag：`gh workflow run ghcr-release.yml -f tag=<tag>`。
- 合并上游：`git fetch upstream && git merge upstream/main`。

## 8. 风险与处理
- **rmcp 工厂读取 task-local 的前提**（工厂在请求 future 内同步调用）：已核对 rmcp 2.2 源码；另加集成测试锁定该行为，升级 rmcp 时若失效测试会红。工厂拿不到 principal 时直接报错，不会退化成全权限。
- **全局 policy 语义复杂**（legacy / versioned 规则）：收窄只使用"强制只读 / 关闭危险"和 legacy ceiling 两种单调变换，并对每种组合写测试。
- **与上游合并冲突**：新代码集中在新文件；对现有文件只做小改动（`http_auth.rs`、`http.rs`、`main.rs`、`state.rs`、设置对话框加一个 tab）。
