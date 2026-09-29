#!/usr/bin/env python3
"""End-to-end check for Web MCP API keys against a running dbx-web.

Start dbx-web first, for example:

    DBX_DATA_DIR=/tmp/dbx-e2e DBX_PORT=4299 DBX_PASSWORD=pass \
    DBX_WEB_MCP_TOKEN=master-secret-token DBX_WEB_MCP_ALLOWED_HOSTS=127.0.0.1:4299 \
    target/debug/dbx-web

then run: python3 scripts/e2e-web-mcp-keys.py
"""

import json
import os
import sqlite3
import sys
import tempfile
import urllib.error
import urllib.request
from http.cookiejar import CookieJar

BASE = os.environ.get("DBX_E2E_BASE", "http://127.0.0.1:4299")
PASSWORD = os.environ.get("DBX_E2E_PASSWORD", "pass")
MASTER = os.environ.get("DBX_E2E_MASTER_TOKEN", "master-secret-token")

jar = CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def api(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(BASE + path, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    request.add_header("X-DBX-MCP-Settings", "1")
    with opener.open(request) as response:
        raw = response.read()
        return json.loads(raw) if raw else None


class Mcp:
    def __init__(self, token):
        self.token = token
        self.session = None
        self.next_id = 1

    def post(self, message, session=None):
        request = urllib.request.Request(BASE + "/mcp", data=json.dumps(message).encode(), method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json, text/event-stream")
        request.add_header("Authorization", f"Bearer {self.token}")
        request.add_header("Mcp-Protocol-Version", "2025-06-18")
        if session or self.session:
            request.add_header("Mcp-Session-Id", session or self.session)
        try:
            with urllib.request.urlopen(request) as response:
                body = response.read().decode()
                return response.status, response.headers.get("mcp-session-id"), body
        except urllib.error.HTTPError as error:
            return error.code, None, error.read().decode()

    def rpc(self, method, params=None):
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}}
        self.next_id += 1
        status, _, body = self.post(message)
        if status >= 400:
            return status, None
        for line in body.splitlines():
            if line.startswith("data:") and line[5:].strip():
                payload = json.loads(line[5:])
                if payload.get("id") == message["id"]:
                    return status, payload
        return status, json.loads(body) if body.strip().startswith("{") else None

    def initialize(self):
        status, session, _ = self.post(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}},
            }
        )
        assert status == 200, f"initialize failed: {status}"
        self.session = session
        self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return self

    def tool(self, name, arguments=None):
        status, payload = self.rpc("tools/call", {"name": name, "arguments": arguments or {}})
        assert status == 200 and payload, f"{name} failed: {status} {payload}"
        result = payload["result"]
        text = "\n".join(item.get("text", "") for item in result.get("content", []))
        return result.get("isError", False), text

    def tool_names(self):
        _, payload = self.rpc("tools/list")
        return {tool["name"] for tool in payload["result"]["tools"]}


def check(condition, label):
    print(("PASS " if condition else "FAIL ") + label)
    if not condition:
        sys.exit(1)


def main():
    workdir = tempfile.mkdtemp(prefix="dbx-e2e-")
    for name in ("sales", "hr", "ops"):
        with sqlite3.connect(os.path.join(workdir, f"{name}.db")) as db:
            db.execute(f"CREATE TABLE {name}_items (id INTEGER PRIMARY KEY, label TEXT)")
            db.execute(f"INSERT INTO {name}_items (label) VALUES ('{name}-1')")

    api("POST", "/api/auth/login", {"password": PASSWORD})
    connections = [
        {"id": f"e2e-{name}", "name": f"E2E {name}", "db_type": "sqlite", "host": os.path.join(workdir, f"{name}.db"), "port": 0, "username": "", "password": ""}
        for name in ("sales", "hr", "ops")
    ]
    api("POST", "/api/connection/save", {"configs": connections})
    api(
        "POST",
        "/api/layout/sidebar",
        {
            "layout": {
                "groups": [{"id": "grp-ops", "name": "Ops"}],
                "order": [
                    {"type": "connection", "id": "e2e-sales"},
                    {"type": "connection", "id": "e2e-hr"},
                    {"type": "group", "id": "grp-ops", "children": [{"type": "connection", "id": "e2e-ops"}]},
                ],
            }
        },
    )

    # Allow dangerous SQL globally so the team ceiling is what blocks it below.
    api("PUT", "/api/app-settings/mcp-policy", {"readOnly": False, "allowDangerousSql": True, "allowedConnectionIds": None})

    overview = api("GET", "/api/mcp-access/overview")
    check(overview["endpointEnabled"], "Web MCP endpoint enabled")
    check({"e2e-sales", "e2e-hr", "e2e-ops"} <= {c["id"] for c in overview["connections"]}, "overview lists connections")

    sales = api("POST", "/api/mcp-access/teams", {"name": f"Sales {workdir[-6:]}", "connectionIds": ["e2e-sales"], "access": "readOnly"})
    ops = api("POST", "/api/mcp-access/teams", {"name": f"Ops {workdir[-6:]}", "groupIds": ["grp-ops"], "access": "readWrite"})
    key_a = api("POST", "/api/mcp-access/keys", {"name": "sales-only", "teamIds": [sales["id"]]})
    key_b = api("POST", "/api/mcp-access/keys", {"name": "sales+ops", "teamIds": [sales["id"], ops["id"]]})
    check(key_a["secret"].startswith("dbxk_"), "key secret issued once")
    listed = api("GET", "/api/mcp-access/overview")["keys"]
    check(all("secret" not in key and "keyHash" not in key for key in listed), "listing never exposes secrets or hashes")

    master = Mcp(MASTER).initialize()
    _, text = master.tool("dbx_list_connections")
    check(all(name in text for name in ("e2e-sales", "e2e-hr", "e2e-ops")), "master token sees every connection")
    check("dbx_add_connection" in master.tool_names(), "master token keeps connection management tools")

    a = Mcp(key_a["secret"]).initialize()
    _, text = a.tool("dbx_list_connections")
    check("e2e-sales" in text and "e2e-hr" not in text and "e2e-ops" not in text, "key A sees only the sales team connection")
    check("dbx_add_connection" not in a.tool_names(), "key A has no connection management tools")
    error, text = a.tool("dbx_execute_query", {"connection_id": "e2e-hr", "sql": "SELECT * FROM hr_items"})
    check(error, "key A cannot query a connection outside its teams")
    error, text = a.tool("dbx_execute_query", {"connection_id": "e2e-sales", "sql": "SELECT * FROM sales_items"})
    check(not error and "sales-1" in text, "key A can read its connection")
    error, text = a.tool("dbx_execute_query", {"connection_id": "e2e-sales", "sql": "INSERT INTO sales_items (label) VALUES ('x')"})
    check(error, "read-only team blocks writes for key A")

    b = Mcp(key_b["secret"]).initialize()
    _, text = b.tool("dbx_list_connections")
    check("e2e-sales" in text and "e2e-ops" in text and "e2e-hr" not in text, "key B sees union of teams incl. group members")
    error, text = b.tool("dbx_execute_query", {"connection_id": "e2e-ops", "sql": "INSERT INTO ops_items (label) VALUES ('from-key-b')"})
    check(not error, f"read-write team allows writes for key B ({text[:120]})")
    error, text = b.tool("dbx_execute_query", {"connection_id": "e2e-ops", "sql": "DROP TABLE ops_items"})
    check(error, "read-write team still blocks dangerous SQL")

    status, _, _ = Mcp(key_b["secret"]).post({"jsonrpc": "2.0", "id": 9, "method": "tools/list"}, session=a.session)
    check(status == 404, "key B cannot reuse key A's MCP session")

    api("PUT", f"/api/mcp-access/teams/{sales['id']}", {"name": sales["name"], "connectionIds": ["e2e-sales", "e2e-hr"], "access": "readOnly"})
    _, text = a.tool("dbx_list_connections")
    check("e2e-hr" in text, "team edits apply to open sessions")

    api("PUT", f"/api/mcp-access/keys/{key_a['key']['id']}", {"name": "sales-only", "teamIds": [sales["id"]], "enabled": False})
    status, _ = a.rpc("tools/list")
    check(status == 401, "disabled key is rejected immediately")

    rotated = api("POST", f"/api/mcp-access/keys/{key_b['key']['id']}/rotate")
    status, _ = b.rpc("tools/list")
    check(status == 401, "rotated key's old secret is rejected")
    fresh = Mcp(rotated["secret"]).initialize()
    _, text = fresh.tool("dbx_list_connections")
    check("e2e-ops" in text, "rotated secret works")

    api("DELETE", f"/api/mcp-access/keys/{key_b['key']['id']}")
    status, _ = fresh.rpc("tools/list")
    check(status == 401, "deleted key is rejected")

    # Batch creation with a team prefix, then copying stored secrets again.
    api("PUT", f"/api/mcp-access/teams/{ops['id']}", {"name": ops["name"], "connectionIds": ["e2e-ops"], "access": "readWrite", "keyPrefix": "ops"})
    batch = api("POST", "/api/mcp-access/keys/batch", {"names": ["ops-alice", "ops-bob"], "teamIds": [ops["id"]]})
    check(len(batch) == 2 and all(item["secret"].startswith("ops_") for item in batch), "batch keys use the team prefix")
    custom = api("POST", "/api/mcp-access/keys/batch", {"names": ["ops-carol"], "teamIds": [ops["id"]], "prefix": "acme"})
    check(custom[0]["secret"].startswith("acme_"), "explicit prefix overrides the team prefix")
    _, text = Mcp(batch[1]["secret"]).initialize().tool("dbx_list_connections")
    check("e2e-ops" in text and "e2e-sales" not in text, "prefixed batch key is scoped to its team")
    ids = [item["key"]["id"] for item in batch + custom]
    revealed = api("POST", "/api/mcp-access/keys/reveal", {"ids": ids})
    check([item["secret"] for item in revealed] == [item["secret"] for item in batch + custom], "stored secrets can be copied again")
    try:
        api("POST", "/api/mcp-access/keys/batch", {"names": ["ops-alice"]})
        check(False, "duplicate key names are rejected")
    except urllib.error.HTTPError as error:
        check(error.code == 400, "duplicate key names are rejected")

    for key in [key_a, *batch, *custom]:
        api("DELETE", f"/api/mcp-access/keys/{key['key']['id']}")
    for team in (sales, ops):
        api("DELETE", f"/api/mcp-access/teams/{team['id']}")
    api("POST", "/api/connection/save", {"configs": [], "removed_ids": [c["id"] for c in connections]})
    api("PUT", "/api/app-settings/mcp-policy", {"readOnly": False, "allowDangerousSql": False, "allowedConnectionIds": None})
    print("ALL PASSED")


if __name__ == "__main__":
    main()
