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
  truncateHead,
  type ExtensionAPI,
} from "@earendil-works/pi-coding-agent";

const PACKAGE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const CALL_TIMEOUT_MS = 360_000;

type PiContent =
  | { type: "text"; text: string }
  | { type: "image"; data: string; mimeType: string };

export default function idaCodemode(pi: ExtensionAPI) {
  let client: Client | undefined;

  pi.on("session_start", async (_event, ctx) => {
    if (client) return;

    const next = new Client({ name: "ida-codemode-pi", version: "0.1.0" });
    const transport = new StdioClientTransport({
      command: "uv",
      args: ["run", "--project", PACKAGE_ROOT, "ida-codemode-mcp", "mcp"],
      cwd: PACKAGE_ROOT,
    });

    try {
      await next.connect(transport);
      client = next;

      const { tools } = await next.listTools();
      for (const tool of tools) {
        pi.registerTool({
          name: tool.name,
          label: tool.annotations?.title ?? `IDA ${tool.name}`,
          description: tool.description ?? `Call the IDA MCP ${tool.name} tool`,
          // MCP and Pi both use JSON Schema for tool inputs. The SDK's type is
          // structurally compatible, but it is not branded as a TypeBox schema.
          parameters: tool.inputSchema as any,
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
