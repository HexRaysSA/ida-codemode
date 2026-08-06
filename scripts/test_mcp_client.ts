#!/usr/bin/env node
/**
 * Standalone probe for @modelcontextprotocol/sdk timeout and cancellation behavior.
 *
 * It spawns scripts/test_mcp.py over stdio, traces MCP messages, and runs either
 * a short scenario matrix or one configurable call. No ida-codemode code is used.
 *
 * Examples:
 *   node scripts/test_mcp_client.ts
 *   node scripts/test_mcp_client.ts --scenario single --timeout-ms 500 --seconds 5
 *   node scripts/test_mcp_client.ts --scenario single --abort-after-ms 500 --seconds 5
 *   node scripts/test_mcp_client.ts --scenario single --seconds 65
 *   node scripts/test_mcp_client.ts --stdio-mode sync
 */

import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const PROJECT_PYTHON =
  process.platform === "win32"
    ? join(SCRIPT_DIR, "..", ".venv", "Scripts", "python.exe")
    : join(SCRIPT_DIR, "..", ".venv", "bin", "python");
const STARTED = performance.now();

type StdioMode = "async" | "sync";
type ScenarioName = "matrix" | "single";

type Options = {
  scenario: ScenarioName;
  python: string;
  stdioMode: StdioMode;
  seconds: number;
  pollInterval: number;
  timeoutMs?: number;
  abortAfterMs?: number;
  ignoreCancellation: boolean;
  postWaitMs: number;
  traceWire: boolean;
};

type Scenario = {
  name: string;
  seconds: number;
  pollInterval?: number;
  timeoutMs?: number;
  abortAfterMs?: number;
  ignoreCancellation?: boolean;
  postWaitMs?: number;
};

function log(event: string, fields: Record<string, unknown> = {}): void {
  process.stdout.write(
    `${JSON.stringify({
      source: "typescript-client",
      elapsed_ms: Math.round((performance.now() - STARTED) * 1000) / 1000,
      event,
      ...fields,
    })}\n`,
  );
}

function numberArgument(name: string, raw: string | undefined): number {
  if (raw === undefined) throw new Error(`${name} requires a value`);
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${name} must be a finite non-negative number`);
  }
  return value;
}

function parseArgs(argv: string[]): Options {
  const options: Options = {
    scenario: "matrix",
    python:
      process.env.PYTHON ?? (existsSync(PROJECT_PYTHON) ? PROJECT_PYTHON : "python3"),
    stdioMode: "async",
    seconds: 5,
    pollInterval: 0.05,
    ignoreCancellation: false,
    postWaitMs: 1000,
    traceWire: true,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = argv[index + 1];
    switch (argument) {
      case "--scenario":
        if (value !== "matrix" && value !== "single") {
          throw new Error("--scenario must be matrix or single");
        }
        options.scenario = value;
        index += 1;
        break;
      case "--python":
        if (!value) throw new Error("--python requires a value");
        options.python = value;
        index += 1;
        break;
      case "--stdio-mode":
        if (value !== "async" && value !== "sync") {
          throw new Error("--stdio-mode must be async or sync");
        }
        options.stdioMode = value;
        index += 1;
        break;
      case "--seconds":
        options.seconds = numberArgument(argument, value);
        index += 1;
        break;
      case "--poll-interval":
        options.pollInterval = numberArgument(argument, value);
        index += 1;
        break;
      case "--timeout-ms":
        options.timeoutMs = numberArgument(argument, value);
        index += 1;
        break;
      case "--abort-after-ms":
        options.abortAfterMs = numberArgument(argument, value);
        index += 1;
        break;
      case "--post-wait-ms":
        options.postWaitMs = numberArgument(argument, value);
        index += 1;
        break;
      case "--ignore-cancellation":
        options.ignoreCancellation = true;
        break;
      case "--no-wire-trace":
        options.traceWire = false;
        break;
      case "--help":
      case "-h":
        process.stdout.write(`Usage: node scripts/test_mcp_client.ts [options]\n\n`);
        process.stdout.write(`  --scenario matrix|single     Run quick matrix (default) or one call\n`);
        process.stdout.write(`  --python PATH                Python containing zeromcp\n`);
        process.stdout.write(`  --stdio-mode async|sync      ZeroMCP stdio dispatcher mode\n`);
        process.stdout.write(`  --seconds N                  Server-side sleep duration\n`);
        process.stdout.write(`  --poll-interval N            Cancellation polling interval in seconds\n`);
        process.stdout.write(`  --timeout-ms N               SDK request timeout; omit for SDK default\n`);
        process.stdout.write(`  --abort-after-ms N           AbortSignal delay; omit for no abort\n`);
        process.stdout.write(`  --ignore-cancellation        Server deliberately finishes after cancellation\n`);
        process.stdout.write(`  --post-wait-ms N             Observe late server activity after rejection\n`);
        process.stdout.write(`  --no-wire-trace              Hide raw MCP messages\n`);
        process.exit(0);
      default:
        throw new Error(`unknown argument: ${argument}`);
    }
  }

  if (options.pollInterval <= 0) {
    throw new Error("--poll-interval must be positive");
  }
  return options;
}

function errorFields(error: unknown): Record<string, unknown> {
  if (!(error instanceof Error)) return { thrown: String(error) };
  const candidate = error as Error & {
    code?: unknown;
    data?: unknown;
    cause?: unknown;
  };
  return {
    error_name: error.name,
    error_message: error.message,
    error_code: candidate.code,
    error_data: candidate.data,
    error_cause: candidate.cause ? String(candidate.cause) : undefined,
  };
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function runScenario(client: Client, scenario: Scenario): Promise<void> {
  const started = performance.now();
  const controller =
    scenario.abortAfterMs === undefined ? undefined : new AbortController();
  const abortTimer =
    controller && scenario.abortAfterMs !== undefined
      ? setTimeout(() => {
          log("abort_fired", {
            scenario: scenario.name,
            abort_after_ms: scenario.abortAfterMs,
          });
          controller.abort(`abort requested after ${scenario.abortAfterMs}ms`);
        }, scenario.abortAfterMs)
      : undefined;

  const requestOptions: {
    timeout?: number;
    signal?: AbortSignal;
  } = {};
  if (scenario.timeoutMs !== undefined) requestOptions.timeout = scenario.timeoutMs;
  if (controller !== undefined) requestOptions.signal = controller.signal;

  log("scenario_started", {
    scenario: scenario.name,
    server_seconds: scenario.seconds,
    timeout_ms: scenario.timeoutMs ?? "SDK default (60000ms)",
    abort_after_ms: scenario.abortAfterMs,
    ignore_cancellation: scenario.ignoreCancellation ?? false,
  });

  try {
    const result = await client.callTool(
      {
        name: "sleep",
        arguments: {
          seconds: scenario.seconds,
          poll_interval: scenario.pollInterval ?? 0.02,
          ignore_cancellation: scenario.ignoreCancellation ?? false,
        },
      },
      undefined,
      requestOptions,
    );
    log("scenario_resolved", {
      scenario: scenario.name,
      client_elapsed_ms: Math.round((performance.now() - started) * 1000) / 1000,
      result,
    });
  } catch (error) {
    log("scenario_rejected", {
      scenario: scenario.name,
      client_elapsed_ms: Math.round((performance.now() - started) * 1000) / 1000,
      ...errorFields(error),
    });
  } finally {
    if (abortTimer !== undefined) clearTimeout(abortTimer);
  }

  const postWaitMs = scenario.postWaitMs ?? 900;
  if (postWaitMs > 0) {
    log("post_wait_started", { scenario: scenario.name, post_wait_ms: postWaitMs });
    await delay(postWaitMs);
  }
  log("scenario_finished", { scenario: scenario.name });
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const serverPath = join(SCRIPT_DIR, "test_mcp.py");
  const transport = new StdioClientTransport({
    command: options.python,
    args: [serverPath, "--stdio-mode", options.stdioMode],
    stderr: "pipe",
  });

  const stderr = transport.stderr;
  if (stderr) {
    const lines = createInterface({ input: stderr as Readable });
    lines.on("line", (line) => process.stdout.write(`${line}\n`));
  }

  if (options.traceWire) {
    const originalSend = transport.send.bind(transport);
    transport.send = async (message) => {
      log("mcp_outbound", { message });
      await originalSend(message);
    };
  }

  const client = new Client({ name: "timeout-test-client", version: "1.0.0" });
  client.onerror = (error) => log("client_error", errorFields(error));
  client.onclose = () => log("client_closed");

  log("client_connecting", {
    python: options.python,
    server_path: serverPath,
    stdio_mode: options.stdioMode,
    sdk_package: "@modelcontextprotocol/sdk",
  });

  try {
    await client.connect(transport);
    if (options.traceWire) {
      const originalOnMessage = transport.onmessage;
      transport.onmessage = (message) => {
        log("mcp_inbound", { message });
        originalOnMessage?.(message);
      };
    }
    log("client_connected", {
      server_version: client.getServerVersion(),
      server_capabilities: client.getServerCapabilities(),
    });

    if (options.scenario === "matrix") {
      const scenarios: Scenario[] = [
        {
          name: "success",
          seconds: 0.1,
          timeoutMs: 1000,
          postWaitMs: 100,
        },
        {
          name: "sdk-timeout-cooperative",
          seconds: 0.8,
          timeoutMs: 200,
          postWaitMs: 900,
        },
        {
          name: "abort-signal-cooperative",
          seconds: 0.8,
          timeoutMs: 5000,
          abortAfterMs: 200,
          postWaitMs: 900,
        },
        {
          name: "sdk-timeout-ignored-by-tool",
          seconds: 0.6,
          timeoutMs: 200,
          ignoreCancellation: true,
          postWaitMs: 700,
        },
      ];
      for (const scenario of scenarios) await runScenario(client, scenario);
    } else {
      await runScenario(client, {
        name: "single",
        seconds: options.seconds,
        pollInterval: options.pollInterval,
        timeoutMs: options.timeoutMs,
        abortAfterMs: options.abortAfterMs,
        ignoreCancellation: options.ignoreCancellation,
        postWaitMs: options.postWaitMs,
      });
    }
  } finally {
    log("client_closing");
    await client.close();
  }
}

main().catch((error) => {
  log("fatal_error", errorFields(error));
  process.exitCode = 1;
});
