// create_session/close_session must treat the profiles.json maps as plain
// data: a project id like "constructor" (or "__proto__") resolves to an
// Object.prototype member under plain indexing, so approval lookups have to
// be own-property checks and the directory itself a string.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { AuditLog } from "../src/audit.js";
import { HerdrCoreClient } from "../src/core/client.js";
import { HerdrCoreLink } from "../src/core/link.js";
import { registerCloseSessionTool, registerCreateSessionTool } from "../src/mcp/sessions.js";
import { startFakeCore } from "./fake-core.js";

function terminalFixture(labels: Record<string, string>) {
  return {
    address: "t7",
    name: null,
    labels,
    argv: ["bash"],
    cwd: "/tmp/demo",
    state: "live",
    pid: 100,
    exit_code: null,
    signal: null,
    reason: null,
    created_ms: 1,
    finished_ms: null,
    title: "demo",
    parent: null,
  };
}

test("session tools reject prototype-name profiles and projects", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "herdr-mcp-sessions-"));
  writeFileSync(
    join(stateDir, "profiles.json"),
    JSON.stringify({ main: { executable: "bash", projects: { "herdr-app": "/tmp/herdr-app" } } }),
    { mode: 0o600 },
  );
  const mutations: string[] = [];
  const core = await startFakeCore({
    "terminal.get": () => ({ result: terminalFixture({ oauth_mcp_profile: "main", oauth_mcp_project: "constructor" }) }),
    "terminal.list": () => ({ result: { terminals: [], hidden_finished: 0, machines: [] } }),
    "terminal.run": () => {
      mutations.push("terminal.run");
      return { result: terminalFixture({ oauth_mcp_profile: "main", oauth_mcp_project: "constructor" }) };
    },
    "terminal.kill": () => {
      mutations.push("terminal.kill");
      return { result: terminalFixture({}) };
    },
    "terminal.rm": () => {
      mutations.push("terminal.rm");
      return { result: { removed: "t7" } };
    },
  });

  const link = new HerdrCoreLink({ path: core.path, source: "env" }, "default");
  const client = new HerdrCoreClient(link);
  const audit = new AuditLog(join(stateDir, "audit.log"));
  const server = new McpServer({ name: "test", version: "0" });
  registerCreateSessionTool(server, { client, audit, stateDir });
  registerCloseSessionTool(server, { client, audit, stateDir });

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const mcp = new Client({ name: "test", version: "0" });
  await Promise.all([mcp.connect(clientTransport), server.connect(serverTransport)]);

  try {
    const created = (await mcp.callTool({
      name: "create_session",
      arguments: { profile: "main", project: "constructor", request_id: "constructor-1" },
    })) as { isError?: boolean; content: { text: string }[] };
    assert.equal(created.isError, true);
    assert.match(created.content[0]!.text, /Unknown project 'constructor' for profile 'main'/);

    const proto = (await mcp.callTool({
      name: "create_session",
      arguments: { profile: "__proto__", project: "herdr-app", request_id: "constructor-2" },
    })) as { isError?: boolean; content: { text: string }[] };
    assert.equal(proto.isError, true);
    assert.match(proto.content[0]!.text, /Unknown profile '__proto__'/);

    const closed = (await mcp.callTool({
      name: "close_session",
      arguments: { terminal: "t7" },
    })) as { isError?: boolean; content: { text: string }[] };
    assert.equal(closed.isError, true);
    assert.match(closed.content[0]!.text, /Refused: t7 was not started by create_session/);

    assert.deepEqual(mutations, []);
  } finally {
    await mcp.close();
    await server.close();
    link.close();
    await core.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});
