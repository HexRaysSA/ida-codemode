import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_LINES,
  formatSize,
  highlightCode,
  keyHint,
  truncateHead,
  type ExtensionAPI,
  type Theme,
} from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";

const PACKAGE_ROOT = dirname(fileURLToPath(import.meta.url));
const CALL_TIMEOUT_MS = 360_000;

type PiContent =
  | { type: "text"; text: string }
  | { type: "image"; data: string; mimeType: string };

function renderToolCall(
  toolName: string,
  args: Record<string, unknown> | undefined,
  theme: Theme,
  expanded: boolean,
): Text {
  let text = theme.fg("toolTitle", theme.bold(toolName));
  const mcpToolName = toolName.startsWith("ida_") ? toolName.slice(4) : toolName;

  if (mcpToolName === "execute_python" && typeof args?.code === "string") {
    if (typeof args.instance_id === "string") {
      text += ` ${theme.fg("muted", args.instance_id)}`;
    }

    const lines = highlightCode(args.code.replaceAll("\t", "    "), "python");
    const maxLines = expanded ? lines.length : 10;
    const displayed = lines.slice(0, maxLines);
    text += `\n\n${displayed.join("\n")}`;

    const remaining = lines.length - displayed.length;
    if (remaining > 0) {
      text +=
        theme.fg("muted", `\n... (${remaining} more lines,`) +
        ` ${keyHint("app.tools.expand", "to expand")}${theme.fg("muted", ")")}`;
    }
    return new Text(text, 0, 0);
  }

  const serialized = args ? JSON.stringify(args, null, 2) : undefined;
  if (serialized && serialized !== "{}") {
    text += `\n\n${theme.fg("toolOutput", serialized)}`;
  }
  return new Text(text, 0, 0);
}

export default function idaCodemode(pi: ExtensionAPI) {
  let client: Client | undefined;

  pi.on("session_start", async (_event, ctx) => {
    if (client) return;

    const next = new Client({ name: "ida-codemode-pi", version: "0.2.0" });
    const transport = new StdioClientTransport({
      command: "uv",
      args: ["run", "--project", PACKAGE_ROOT, "ida-codemode-mcp", "--agent", "pi"],
      cwd: PACKAGE_ROOT,
      env: {
        ...(process.env.IDA_CODEMODE_ID
          ? { IDA_CODEMODE_ID: process.env.IDA_CODEMODE_ID }
          : {}),
        ...(process.env.IDAUSR ? { IDAUSR: process.env.IDAUSR } : {}),
        ...(process.env.IDA_CODEMODE_STATE_DIR
          ? { IDA_CODEMODE_STATE_DIR: process.env.IDA_CODEMODE_STATE_DIR }
          : {}),
      },
    });

    try {
      await next.connect(transport);
      client = next;

      const { tools } = await next.listTools();
      for (const tool of tools) {
        const piToolName = tool.name.startsWith("ida_") ? tool.name : `ida_${tool.name}`;
        pi.registerTool({
          name: piToolName,
          label: tool.annotations?.title ?? `IDA ${tool.name}`,
          description: tool.description ?? `Call the IDA MCP ${tool.name} tool`,
          // MCP and Pi both use JSON Schema for tool inputs. The SDK's type is
          // structurally compatible, but it is not branded as a TypeBox schema.
          parameters: tool.inputSchema as any,
          renderCall(args, theme, context) {
            return renderToolCall(
              piToolName,
              args as Record<string, unknown> | undefined,
              theme,
              context.expanded,
            );
          },
          async execute(_id, params, signal, onUpdate, ctx) {
            if (!client) throw new Error("The IDA MCP server is not connected");

            const sessionPath = ctx.sessionManager.getSessionFile();
            const result = await client.callTool(
              {
                name: tool.name,
                arguments: params as Record<string, unknown>,
                ...(sessionPath
                  ? { _meta: { pi_session_path: sessionPath } }
                  : {}),
              },
              undefined,
              {
                signal,
                timeout: CALL_TIMEOUT_MS,
                onprogress(progress) {
                  const total = progress.total ? `/${progress.total}` : "";
                  onUpdate?.({
                    content: [
                      { type: "text", text: `IDA MCP progress: ${progress.progress}${total}` },
                    ],
                    details: {},
                  });
                },
              },
            );

            if (!Array.isArray(result.content)) {
              return {
                content: [{ type: "text", text: JSON.stringify(result.toolResult ?? result, null, 2) }],
                details: {},
              };
            }

            const images: PiContent[] = [];
            const textParts: string[] = [];
            for (const item of result.content as Array<any>) {
              if (item.type === "text") textParts.push(item.text);
              else if (item.type === "image") {
                images.push({ type: "image", data: item.data, mimeType: item.mimeType });
              } else textParts.push(JSON.stringify(item, null, 2));
            }
            if (textParts.length === 0 && result.structuredContent) {
              textParts.push(JSON.stringify(result.structuredContent, null, 2));
            }

            const fullText = textParts.join("\n");
            const truncated = truncateHead(fullText, {
              maxBytes: DEFAULT_MAX_BYTES,
              maxLines: DEFAULT_MAX_LINES,
            });
            let text = truncated.content;
            let fullOutputPath: string | undefined;
            if (truncated.truncated) {
              const dir = await mkdtemp(join(tmpdir(), "pi-ida-mcp-"));
              fullOutputPath = join(dir, `${tool.name}.txt`);
              await writeFile(fullOutputPath, fullText, "utf8");
              text += `\n\n[Output truncated to ${DEFAULT_MAX_LINES} lines or ${formatSize(DEFAULT_MAX_BYTES)}. Full output: ${fullOutputPath}]`;
            }

            if (result.isError) throw new Error(text || `${tool.name} failed`);
            return {
              content: [...(text ? [{ type: "text" as const, text }] : []), ...images],
              details: fullOutputPath ? { fullOutputPath } : {},
            };
          },
        });
      }

      ctx.ui.notify(`IDA MCP connected (${tools.length} tools)`, "info");
    } catch (error) {
      client = undefined;
      await next.close().catch(() => undefined);
      const message = error instanceof Error ? error.message : String(error);
      ctx.ui.notify(`IDA MCP failed to start: ${message}`, "error");
    }
  });

  pi.on("session_shutdown", async () => {
    const active = client;
    client = undefined;
    await active?.close();
  });
}
