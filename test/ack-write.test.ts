// writeAckMarker is read_terminal's handshake with the done-blink mod: one
// flat JSON file per canonical address, written atomically, whose failure must
// never be observable in the tool's own result.

import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { AuditLog } from "../src/audit.js";
import { HerdrCoreClient, type Terminal } from "../src/core/client.js";
import { HerdrCoreLink } from "../src/core/link.js";
import { registerTools, writeAckMarker } from "../src/mcp/tools.js";
import { startFakeCore } from "./fake-core.js";

const ACK_DIR_PERMISSIONS = 0o700;
const ACK_FILE_PERMISSIONS = 0o600;

function terminalFixture(address: string): Terminal {
  return {
    address,
    name: null,
    labels: {},
    argv: ["bash"],
    cwd: "/tmp/demo",
    state: "live",
    pid: 100,
    exit_code: null,
    signal: null,
    reason: null,
    created_ms: 1,
    finished_ms: null,
    screen: "exact",
    cols: 80,
    rows: 24,
    status: null,
    status_ms: null,
    turn: 3,
    reported: false,
    title: "demo",
    parent: null,
    foreground: null,
  };
}

test("writeAckMarker writes one flat 0600 marker in a 0700 dir", () => {
  const root = mkdtempSync(join(tmpdir(), "herdr-mcp-ack-"));
  try {
    writeAckMarker("t3f", root, 1_700_000_000_000);
    const path = join(root, "ack", "t3f.json");
    assert.ok(existsSync(path), "marker file exists");
    assert.equal(readFileSync(path, "utf8"), `${JSON.stringify({ v: 1, address: "t3f", ts: 1_700_000_000_000, by: "bori", tool: "read_terminal" })}\n`);
    assert.equal(statSync(path).mode & 0o777, ACK_FILE_PERMISSIONS);
    assert.equal(statSync(join(root, "ack")).mode & 0o777, ACK_DIR_PERMISSIONS);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("writeAckMarker keeps remote and unicode addresses flat", () => {
  const root = mkdtempSync(join(tmpdir(), "herdr-mcp-ack-"));
  try {
    writeAckMarker("machine/t7", root, 1);
    writeAckMarker("터미널9", root, 1);
    const names = readdirSync(join(root, "ack"));
    assert.deepEqual(names.slice().sort(), ["%ED%84%B0%EB%AF%B8%EB%84%909.json", "machine%2Ft7.json"]);
    assert.ok(!existsSync(join(root, "ack", "machine")), "no directory is created for a remote address");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("writeAckMarker atomically replaces an older marker", () => {
  const root = mkdtempSync(join(tmpdir(), "herdr-mcp-ack-"));
  try {
    writeAckMarker("t3f", root, 1_111);
    writeAckMarker("t3f", root, 2_222);
    const marker = JSON.parse(readFileSync(join(root, "ack", "t3f.json"), "utf8")) as { ts: number };
    assert.equal(marker.ts, 2_222, "the newer marker wins");
    assert.equal(readdirSync(join(root, "ack")).length, 1, "no temp file is left behind");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("writeAckMarker swallows an unwritable ack dir", () => {
  const root = mkdtempSync(join(tmpdir(), "herdr-mcp-ack-"));
  const ack = join(root, "ack");
  try {
    writeAckMarker("t3f", root, 1);
    chmodSync(ack, 0o000);
    assert.doesNotThrow(() => writeAckMarker("t9", root, 2));
    assert.ok(!existsSync(join(ack, "t9.json")), "nothing was written");
  } finally {
    chmodSync(ack, ACK_DIR_PERMISSIONS);
    rmSync(root, { recursive: true, force: true });
  }
});

test("read_terminal acks the canonical address and is unchanged when the ack write fails", async () => {
  const home = mkdtempSync(join(tmpdir(), "herdr-mcp-ack-home-"));
  const stateDir = mkdtempSync(join(tmpdir(), "herdr-mcp-ack-state-"));
  const realHome = process.env.HOME;
  process.env.HOME = home;
  try {
    const core = await startFakeCore({
      // The tool is called with the name "demo" but the terminal record's
      // canonical address is t3f: the marker must use the record.
      "terminal.get": () => ({ result: terminalFixture("t3f") }),
      "terminal.read": () => ({ result: { text: "hello screen", complete: true, how: "screen", why: null } }),
    });
    const link = new HerdrCoreLink({ path: core.path, source: "env" }, "default");
    const client = new HerdrCoreClient(link);
    const server = new McpServer({ name: "test", version: "0" });
    registerTools(server, { client, audit: new AuditLog(join(stateDir, "audit.log")), readOnly: true, allowedMachines: null, stateDir });

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const mcp = new Client({ name: "test", version: "0" });
    await Promise.all([mcp.connect(clientTransport), server.connect(serverTransport)]);

    try {
      const call = () =>
        mcp.callTool({ name: "read_terminal", arguments: { terminal: "demo" } }) as Promise<
          { isError?: boolean; content: { type: string; text: string }[] }
        >;
      const writable = await call();
      assert.ok(!writable.isError);
      assert.ok(existsSync(join(home, ".config/herdr-app/data/ack/t3f.json")), "marker uses the canonical address");
      assert.ok(!existsSync(join(home, ".config/herdr-app/data/ack/demo.json")), "not the raw argument");

      const ackDir = join(home, ".config/herdr-app/data/ack");
      chmodSync(ackDir, 0o000);
      const unwritable = await call();
      assert.ok(!unwritable.isError);
      assert.deepEqual(unwritable.content, writable.content, "the tool result is byte-identical when the ack write fails");
      assert.ok(!existsSync(join(ackDir, "t9.json")));
      chmodSync(ackDir, ACK_DIR_PERMISSIONS);
    } finally {
      await mcp.close();
      await server.close();
      link.close();
      await core.close();
    }
  } finally {
    process.env.HOME = realHome;
    rmSync(home, { recursive: true, force: true });
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("list_history numbers resolve from done-blink first and fall back to terminal-numbers", async () => {
  const home = mkdtempSync(join(tmpdir(), "herdr-mcp-numbers-home-"));
  const stateDir = mkdtempSync(join(tmpdir(), "herdr-mcp-numbers-state-"));
  const realHome = process.env.HOME;
  process.env.HOME = home;
  try {
    const core = await startFakeCore({});
    const link = new HerdrCoreLink({ path: core.path, source: "env" }, "default");
    const server = new McpServer({ name: "test", version: "0" });
    registerTools(server, { client: new HerdrCoreClient(link), audit: new AuditLog(join(stateDir, "audit.log")), readOnly: true, allowedMachines: null, stateDir });

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const mcp = new Client({ name: "test", version: "0" });
    await Promise.all([mcp.connect(clientTransport), server.connect(serverTransport)]);

    try {
      const call = () =>
        mcp.callTool({ name: "list_history", arguments: { terminal_number: 4 } }) as Promise<
          { isError?: boolean; content: { text: string }[] }
        >;
      // Only the old folder exists: the fallback still resolves the number.
      mkdirSync(join(home, ".config/herdr-app/mods/terminal-numbers"), { recursive: true });
      writeFileSync(join(home, ".config/herdr-app/mods/terminal-numbers/numbers.json"), JSON.stringify({ numbers: { "4": "t9" } }), { mode: 0o600 });
      const fallback = await call();
      assert.ok(!fallback.isError);
      assert.match(fallback.content[0]!.text, /t9/);

      // Once the done-blink folder exists it wins.
      mkdirSync(join(home, ".config/herdr-app/mods/done-blink"), { recursive: true });
      writeFileSync(join(home, ".config/herdr-app/mods/done-blink/numbers.json"), JSON.stringify({ numbers: { "4": "t3f" } }), { mode: 0o600 });
      const primary = await call();
      assert.ok(!primary.isError);
      assert.match(primary.content[0]!.text, /t3f/);
    } finally {
      await mcp.close();
      await server.close();
      link.close();
      await core.close();
    }
  } finally {
    process.env.HOME = realHome;
    rmSync(home, { recursive: true, force: true });
    rmSync(stateDir, { recursive: true, force: true });
  }
});
