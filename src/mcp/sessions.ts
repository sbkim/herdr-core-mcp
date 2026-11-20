// create_session: start a new terminal from an operator-approved profile in an
// approved project directory. Ported from the rp-herdr-core-mcp adapter's
// createSession: the caller never supplies argv or a working directory, only
// names what the operator configured, and request_id reconciles retries
// instead of creating duplicates.

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { AuditLog } from "../audit.js";
import type { HerdrCoreClient } from "../core/client.js";

const TERMINAL_ADDRESS = /^t[1-9][0-9bcdfghjkmnpqrstvwxyz]*$/;
const REQUEST_ID = /^[A-Za-z0-9_-]{8,64}$/;
const SESSION_NAME = /^[a-z0-9][a-z0-9_.-]{0,31}$/;

export interface SessionProfile {
  executable: string;
  args?: string[];
  variants?: Record<string, string[]>;
  projects: Record<string, string>;
  desktopSpaces?: Record<string, string>;
}

type ProfilesFile = Record<string, SessionProfile>;

function loadProfiles(stateDir: string): ProfilesFile {
  const path = join(stateDir, "profiles.json");
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error(`No operator profiles: create ${path} (mode 0600) with profile definitions first.`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${path} must be an object of profiles.`);
  }
  return parsed as ProfilesFile;
}

function failure(error: unknown): { content: { type: "text"; text: string }[]; isError: true } {
  const message = error instanceof Error ? error.message : String(error);
  return { content: [{ type: "text", text: message }], isError: true };
}

function text(value: string): { content: { type: "text"; text: string }[] } {
  return { content: [{ type: "text", text: value }] };
}

function collectDocTerminals(node: unknown, found: string[] = []): string[] {
  if (typeof node !== "object" || node === null) return found;
  const record = node as { content?: { terminal?: string }; children?: unknown[] };
  if (typeof record.content?.terminal === "string") found.push(record.content.terminal);
  for (const child of record.children ?? []) collectDocTerminals(child, found);
  return found;
}

async function appDocTerminals(client: HerdrCoreClient): Promise<string[] | null> {
  try {
    const doc = await client.getDocument("herdr-app");
    const spaces = (doc.value as { spaces?: { tabs?: { root?: unknown }[] }[] }).spaces ?? [];
    return spaces.flatMap((space) => space.tabs ?? []).flatMap((tab) => collectDocTerminals(tab.root));
  } catch {
    return null;
  }
}

export function registerCloseSessionTool(
  server: McpServer,
  context: { client: HerdrCoreClient; audit: AuditLog; stateDir: string },
): void {
  const { client, audit, stateDir } = context;
  server.registerTool(
    "close_session",
    {
      title: "Close an agent session",
      description:
        "End and remove a session that create_session started. The address is only honored when the terminal " +
        "carries this server's oauth_mcp labels AND its profile and project are still operator-configured; " +
        "anything else (sessions you opened yourself in Herdr, shells, other agents) is refused. " +
        "Returns a receipt verifying the terminal is gone from the core list and from the Herdr app's spaces.",
      inputSchema: {
        terminal: z.string().regex(TERMINAL_ADDRESS, "Terminal address like t2x (this core's own terminals only).").describe("Address of the create_session terminal to close."),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    },
    async ({ terminal: address }) => {
      try {
        const profiles = loadProfiles(stateDir);
        const record = await client.getTerminal(address);
        const profile = record.labels?.oauth_mcp_profile;
        const project = record.labels?.oauth_mcp_project;
        const allowed =
          profile !== undefined &&
          project !== undefined &&
          profiles[profile] !== undefined &&
          profiles[profile].projects[project] !== undefined;
        if (!allowed) {
          throw new Error(
            `Refused: ${record.address} was not started by create_session with a currently configured profile/project.`,
          );
        }

        const wasLive = record.state === "live";
        if (wasLive) await client.killTerminal(record.address);
        await client.rmTerminal(record.address);

        let coreGone = false;
        let appCleared = false;
        let appCheckable = false;
        for (let attempt = 0; attempt < 6; attempt += 1) {
          if (!coreGone) {
            const list = await client.listTerminals({ all: true });
            coreGone = !list.terminals.some((terminal) => terminal.address === record.address);
          }
          if (!appCleared) {
            const placed = await appDocTerminals(client);
            if (placed !== null) {
              appCheckable = true;
              appCleared = !placed.includes(record.address);
            }
          }
          if (coreGone && (appCleared || !appCheckable)) break;
          await new Promise((resolve) => setTimeout(resolve, 2000));
        }

        const output = [
          `closed: ${record.address}`,
          `profile: ${profile}  project: ${project}`,
          `killed: ${wasLive ? "yes" : "already finished"}  removed: yes`,
          `core_list: ${coreGone ? "gone" : "still listed"}`,
          `app_space: ${appCheckable ? (appCleared ? "cleared" : "still placed") : "unavailable (no herdr-app document)"}`,
        ].join("\n");
        audit.write({
          tool: "close_session",
          terminal: record.address,
          summary: `${profile}/${project} name=${record.name ?? ""}`,
          outcome: "ok",
          detail: coreGone && appCleared ? undefined : `core_list=${coreGone} app_space=${appCheckable ? appCleared : "unavailable"}`,
        });
        return text(output);
      } catch (error) {
        audit.write({
          tool: "close_session",
          terminal: String(address),
          summary: "refused-or-failed",
          outcome: "error",
          detail: error instanceof Error ? error.message : String(error),
        });
        return failure(error);
      }
    },
  );
}

export function registerCreateSessionTool(
  server: McpServer,
  context: { client: HerdrCoreClient; audit: AuditLog; stateDir: string },
): void {
  const { client, audit, stateDir } = context;
  server.registerTool(
    "create_session",
    {
      title: "Start an agent session",
      description:
        "Start a new terminal from an operator-approved profile in an approved project directory. " +
        "The caller cannot pass argv, a working directory, or a command: only profile, project, optional variant and name. " +
        "request_id makes retries safe: a retry with the same id reconciles the earlier attempt instead of creating another terminal; never invent a new id after an uncertain outcome. " +
        "Verify readiness with get_terminal or wait_terminal before sending work.",
      inputSchema: {
        profile: z.string().min(1).describe("Operator-configured profile id (from profiles.json)."),
        project: z.string().min(1).describe("Operator-configured project id; its exact directory becomes the cwd."),
        variant: z.string().min(1).optional().describe("Optional operator-configured extra-args variant."),
        name: z
          .string()
          .regex(SESSION_NAME, "Name must be short lowercase letters, digits, dots, dashes, underscores.")
          .refine((value) => !TERMINAL_ADDRESS.test(value), "Name must not look like a terminal id.")
          .optional()
          .describe("Optional terminal name shown in lists."),
        request_id: z
          .string()
          .regex(REQUEST_ID, "8-64 chars of letters, digits, underscore, dash.")
          .describe("Caller-chosen unique id: reuse it to reconcile an uncertain earlier attempt."),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
    },
    async ({ profile, project, variant, name, request_id }) => {
      try {
        const profiles = loadProfiles(stateDir);
        const config = profiles[profile];
        if (config === undefined) throw new Error(`Unknown profile '${profile}': operator-configured profiles only.`);
        const cwd = config.projects[project];
        if (cwd === undefined) throw new Error(`Unknown project '${project}' for profile '${profile}'.`);
        const variantArgs = variant === undefined ? [] : config.variants?.[variant];
        if (variant !== undefined && variantArgs === undefined) throw new Error(`Unknown variant '${variant}'.`);
        const argv = [config.executable, ...(config.args ?? []), ...(variantArgs ?? [])];
        const sessionName =
          name ?? `mcp-${createHash("sha256").update(request_id).digest("hex").slice(0, 20)}`;
        const fingerprint = createHash("sha256").update(JSON.stringify({ argv, cwd, name: sessionName })).digest("hex");

        const labels: Record<string, string> = {
          oauth_mcp_request: request_id,
          oauth_mcp_fingerprint: fingerprint,
          oauth_mcp_profile: profile,
          oauth_mcp_project: project,
        };
        const desktopSpace = config.desktopSpaces?.[project];
        if (desktopSpace !== undefined) labels["herdr.space"] = desktopSpace;

        const list = await client.listTerminals({ all: true, labels: { oauth_mcp_request: request_id } });
        const prior = list.terminals.filter(
          (terminal) => TERMINAL_ADDRESS.test(terminal.address) && terminal.labels?.oauth_mcp_fingerprint === fingerprint,
        );
        if (prior.length > 1) {
          throw new Error("Reconciliation conflict: several terminals carry this request_id; inspect them before any new attempt.");
        }
        const record = prior[0] ?? (await client.runTerminal({
          argv,
          cwd,
          name: sessionName,
          labels,
          wait: false,
          keep: false,
          rm: false,
          no_parent: true,
          no_notify: true,
        }));

        let current: Awaited<ReturnType<HerdrCoreClient["getTerminal"]>> | null = null;
        try {
          current = await client.getTerminal(record.address);
        } catch {
          current = null;
        }
        const same =
          current !== null &&
          current.address === record.address &&
          current.created_ms === record.created_ms &&
          current.labels?.oauth_mcp_fingerprint === fingerprint;
        const live = current !== null && same && current.state === "live" && typeof current.pid === "number" && current.pid > 0 && current.reason === null;
        const statusWord = current?.status?.state ?? (current?.state === "finished" ? "finished" : "no-status");

        const output = [
          `session: ${record.address}`,
          `created: ${prior.length > 0 ? "reconciled" : "now"}  verified: ${same ? "yes" : "no"}`,
          `profile: ${profile}  project: ${project}${variant === undefined ? "" : `  variant: ${variant}`}`,
          `name: ${sessionName}  cwd: ${cwd}`,
          `desktop_space: ${desktopSpace ?? "none"}`,
          `status: ${statusWord}${live === false ? "  (not yet ready or unverified)" : ""}`,
          `request_id: ${request_id}`,
          "Reuse this request_id to reconcile; never retry with a new one.",
        ].join("\n");
        audit.write({
          tool: "create_session",
          terminal: record.address,
          summary: `${profile}/${project}${variant === undefined ? "" : ":" + variant} name=${sessionName}`,
          outcome: "ok",
          detail: live ? undefined : "created but not verified live",
        });
        return text(output);
      } catch (error) {
        audit.write({
          tool: "create_session",
          terminal: "",
          summary: `${String(profile)}/${String(project)}`,
          outcome: "error",
          detail: error instanceof Error ? error.message : String(error),
        });
        return failure(error);
      }
    },
  );
}
