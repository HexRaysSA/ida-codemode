---
title: "Code Mode: give agents an entire API in 1,000 tokens"
site: "The Cloudflare Blog"
published: 2026-02-20T14:00+00:00
source: "https://blog.cloudflare.com/code-mode-mcp/"
domain: "blog.cloudflare.com"
description: "The Cloudflare API has over 2,500 endpoints. Exposing each one as an MCP tool would consume over 2 million tokens. With Code Mode, we collapsed all of it into two tools and roughly 1,000 tokens of context."
word_count: 1894
---

This post is also available in [简体中文](https://blog.cloudflare.com/zh-cn/code-mode-mcp), [Italiano](https://blog.cloudflare.com/it-it/code-mode-mcp), [日本語](https://blog.cloudflare.com/ja-jp/code-mode-mcp), [한국어](https://blog.cloudflare.com/ko-kr/code-mode-mcp), [Tiếng Việt](https://blog.cloudflare.com/vi-vn/code-mode-mcp) and [繁體中文](https://blog.cloudflare.com/zh-tw/code-mode-mcp).

![](https://cf-assets.www.cloudflare.com/zkvhlag99gkb/6YAHY3FwNCFMGMYtIDuri7/139b77ff4e1b71ca706af22064222f67/images_BLOG-3184_1.png)

[Model Context Protocol (MCP)](https://www.cloudflare.com/learning/ai/what-is-model-context-protocol-mcp/) has become the standard way for AI agents to use external tools. But there is a tension at its core: agents need many tools to do useful work, yet every tool added fills the model's context window, leaving less room for the actual task.

[Code Mode](https://blog.cloudflare.com/code-mode/) is a technique we first introduced for reducing context window usage during agent tool use. Instead of describing every operation as a separate tool, let the model write code against a typed SDK and execute the code safely in a [Dynamic Worker Loader](https://developers.cloudflare.com/workers/runtime-apis/bindings/worker-loader/). The code acts as a compact plan. The model can explore tool operations, compose multiple calls, and return just the data it needs. Anthropic independently explored the same pattern in their [Code Execution with MCP](https://www.anthropic.com/engineering/code-execution-with-mcp) post.

Today we are introducing [a new MCP server](https://github.com/cloudflare/mcp) for the [entire Cloudflare API](https://developers.cloudflare.com/api/) — from [DNS](https://developers.cloudflare.com/dns/) and [Zero Trust](https://developers.cloudflare.com/cloudflare-one/) to [Workers](https://workers.cloudflare.com/product/workers/) and [R2](https://workers.cloudflare.com/product/r2/) — that uses Code Mode. With just two tools, search() and execute(), the server is able to provide access to the entire Cloudflare API over MCP, while consuming only around 1,000 tokens. The footprint stays fixed, no matter how many API endpoints exist.

For a large API like the Cloudflare API, Code Mode reduces the number of input tokens used by 99.9%. An equivalent MCP server without Code Mode would consume 1.17 million tokens — more than the entire context window of the most advanced foundation models.

<sup><i>Code mode savings vs native MCP, measured with</i> </sup> [<sup><i><u>tiktoken</u></i></sup>](https://github.com/openai/tiktoken)

You can start using this new Cloudflare MCP server today. And we are also open-sourcing a new [Code Mode SDK](https://github.com/cloudflare/agents/tree/main/packages/codemode) in the [Cloudflare Agents SDK](https://github.com/cloudflare/agents), so you can use the same approach in your own MCP servers and AI Agents.

### Server‑side Code Mode

This new MCP server applies Code Mode server-side. Instead of thousands of tools, the server exports just two: `search()` and `execute()`. Both are powered by Code Mode. Here is the full tool surface area that gets loaded into the model context:

```javascript
[
  {
    "name": "search",
    "description": "Search the Cloudflare OpenAPI spec. All $refs are pre-resolved inline.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "code": {
          "type": "string",
          "description": "JavaScript async arrow function to search the OpenAPI spec"
        }
      },
      "required": ["code"]
    }
  },
  {
    "name": "execute",
    "description": "Execute JavaScript code against the Cloudflare API.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "code": {
          "type": "string",
          "description": "JavaScript async arrow function to execute"
        }
      },
      "required": ["code"]
    }
  }
]
```

To discover what it can do, the agent calls `search()`. It writes JavaScript against a typed representation of the OpenAPI spec. The agent can filter endpoints by product, path, tags, or any other metadata and narrow thousands of endpoints to the handful it needs. The full OpenAPI spec never enters the model context. The agent only interacts with it through code.

When the agent is ready to act, it calls `execute()`. The agent writes code that can make Cloudflare API requests, handle pagination, check responses, and chain operations together in a single execution.

Both tools run the generated code inside a [Dynamic Worker](https://developers.cloudflare.com/workers/runtime-apis/bindings/worker-loader/) isolate — a lightweight V8 sandbox with no file system, no environment variables to leak through prompt injection and external fetches disabled by default. Outbound requests can be explicitly controlled with outbound fetch handlers when needed.

#### Example: Protecting an origin from DDoS attacks

Suppose a user tells their agent: "protect my origin from DDoS attacks." The agent's first step is to consult documentation. It might call the [Cloudflare Docs MCP Server](https://developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/), use a [Cloudflare Skill](https://github.com/cloudflare/skills), or search the web directly. From the docs it learns: put [Cloudflare WAF](https://www.cloudflare.com/application-services/products/waf/) and [DDoS protection](https://www.cloudflare.com/ddos/) rules in front of the origin.

**Step 1: Search for the right endpoints** The `search` tool gives the model a `spec` object: the full Cloudflare OpenAPI spec with all `$refs` pre-resolved. The model writes JavaScript against it. Here the agent looks for WAF and ruleset endpoints on a zone:

```javascript
async () => {
  const results = [];
  for (const [path, methods] of Object.entries(spec.paths)) {
    if (path.includes('/zones/') &&
        (path.includes('firewall/waf') || path.includes('rulesets'))) {
      for (const [method, op] of Object.entries(methods)) {
        results.push({ method: method.toUpperCase(), path, summary: op.summary });
      }
    }
  }
  return results;
}
```

The server runs this code in a Workers isolate and returns:

```javascript
[
  { "method": "GET",    "path": "/zones/{zone_id}/firewall/waf/packages",              "summary": "List WAF packages" },
  { "method": "PATCH",  "path": "/zones/{zone_id}/firewall/waf/packages/{package_id}", "summary": "Update a WAF package" },
  { "method": "GET",    "path": "/zones/{zone_id}/firewall/waf/packages/{package_id}/rules", "summary": "List WAF rules" },
  { "method": "PATCH",  "path": "/zones/{zone_id}/firewall/waf/packages/{package_id}/rules/{rule_id}", "summary": "Update a WAF rule" },
  { "method": "GET",    "path": "/zones/{zone_id}/rulesets",                           "summary": "List zone rulesets" },
  { "method": "POST",   "path": "/zones/{zone_id}/rulesets",                           "summary": "Create a zone ruleset" },
  { "method": "GET",    "path": "/zones/{zone_id}/rulesets/phases/{ruleset_phase}/entrypoint", "summary": "Get a zone entry point ruleset" },
  { "method": "PUT",    "path": "/zones/{zone_id}/rulesets/phases/{ruleset_phase}/entrypoint", "summary": "Update a zone entry point ruleset" },
  { "method": "POST",   "path": "/zones/{zone_id}/rulesets/{ruleset_id}/rules",        "summary": "Create a zone ruleset rule" },
  { "method": "PATCH",  "path": "/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}", "summary": "Update a zone ruleset rule" }
]
```

The full Cloudflare API spec has over 2,500 endpoints. The model narrowed that to the WAF and ruleset endpoints it needs, without any of the spec entering the context window.

The model can also drill into a specific endpoint's schema before calling it. Here it inspects what phases are available on zone rulesets:

```javascript
async () => {
  const op = spec.paths['/zones/{zone_id}/rulesets']?.get;
  const items = op?.responses?.['200']?.content?.['application/json']?.schema;
  // Walk the schema to find the phase enum
  const props = items?.allOf?.[1]?.properties?.result?.items?.allOf?.[1]?.properties;
  return { phases: props?.phase?.enum };
}

{
  "phases": [
    "ddos_l4", "ddos_l7",
    "http_request_firewall_custom", "http_request_firewall_managed",
    "http_response_firewall_managed", "http_ratelimit",
    "http_request_redirect", "http_request_transform",
    "magic_transit", "magic_transit_managed"
  ]
}
```

The agent now knows the exact phases it needs: `ddos_l7 ` for DDoS protection and `http_request_firewall_managed` for WAF.

**Step 2: Act on the API** The agent switches to using `execute`. The sandbox gets a `cloudflare.request()` client that can make authenticated calls to the Cloudflare API. First the agent checks what rulesets already exist on the zone:

```javascript
async () => {
  const response = await cloudflare.request({
    method: "GET",
    path: \`/zones/${zoneId}/rulesets\`
  });
  return response.result.map(rs => ({
    name: rs.name, phase: rs.phase, kind: rs.kind
  }));
}

[
  { "name": "DDoS L7",          "phase": "ddos_l7",                        "kind": "managed" },
  { "name": "Cloudflare Managed","phase": "http_request_firewall_managed", "kind": "managed" },
  { "name": "Custom rules",     "phase": "http_request_firewall_custom",   "kind": "zone" }
]
```

The agent sees that managed DDoS and WAF rulesets already exist. It can now chain calls to inspect their rules and update sensitivity levels in a single execution:

```javascript
async () => {
  // Get the current DDoS L7 entrypoint ruleset
  const ddos = await cloudflare.request({
    method: "GET",
    path: \`/zones/${zoneId}/rulesets/phases/ddos_l7/entrypoint\`
  });

  // Get the WAF managed ruleset
  const waf = await cloudflare.request({
    method: "GET",
    path: \`/zones/${zoneId}/rulesets/phases/http_request_firewall_managed/entrypoint\`
  });
}
```

This entire operation, from searching the spec and inspecting a schema to listing rulesets and fetching DDoS and WAF configurations, took four tool calls.

### The Cloudflare MCP server

We started with MCP servers for individual products. Want an agent that manages DNS? Add the [DNS MCP server](https://github.com/cloudflare/mcp-server-cloudflare/tree/main/apps/dns-analytics). Want Workers logs? Add the [Workers Observability MCP server](https://developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/). Each server exported a fixed set of tools that mapped to API operations. This worked when the tool set was small, but the Cloudflare API has over 2,500 endpoints. No collection of hand-maintained servers could keep up.

The Cloudflare MCP server simplifies this. Two tools, roughly 1,000 tokens, and coverage of every endpoint in the API. When we add new products, the same `search()` and `execute()` code paths discover and call them — no new tool definitions, no new MCP servers. It even has support for the [GraphQL Analytics API](https://developers.cloudflare.com/analytics/graphql-api/).

Our MCP server is built on the latest MCP specifications. It is OAuth 2.1 compliant, using [Workers OAuth Provider](https://github.com/cloudflare/workers-oauth-provider) to downscope the token to selected permissions approved by the user when connecting. The agent only gets the capabilities the user explicitly granted.

For developers, this means you can use a simple agent loop and still give your agent access to the full Cloudflare API with built-in progressive capability discovery.

### Comparing approaches to context reduction

Several approaches have emerged to reduce how many tokens MCP tools consume:

**Client-side Code Mode** was our first experiment. The model writes TypeScript against typed SDKs and runs it in a Dynamic Worker Loader on the client. The tradeoff is that it requires the agent to ship with secure sandbox access. Code Mode is implemented in [Goose](https://block.github.io/goose/blog/2025/12/15/code-mode-mcp/) and Anthropics Claude SDK as [Programmatic Tool Calling](https://platform.claude.com/docs/en/agents-and-tools/tool-use/programmatic-tool-calling).

**Command-line interfaces** are another path. CLIs are self-documenting and reveal capabilities as the agent explores. Tools like [OpenClaw](https://openclaw.ai/) and [Moltworker](https://blog.cloudflare.com/moltworker-self-hosted-ai-agent/) convert MCP servers into CLIs using [MCPorter](https://github.com/steipete/mcporter) to give agents progressive disclosure. The limitation is obvious: the agent needs a shell, which not every environment provides and which introduces a much broader attack surface than a sandboxed isolate.

**Dynamic tool search**, as used by [Anthropic in Claude Code](https://x.com/trq212/status/2011523109871108570), surfaces a smaller set of tools hopefully relevant to the current task. It shrinks context use but now requires a search function that must be maintained and evaluated, and each matched tool still uses tokens.

Each approach solves a real problem. But for MCP servers specifically, server-side Code Mode combines their strengths: fixed token cost regardless of API size, no modifications needed on the agent side, progressive discovery built in, and safe execution inside a sandboxed isolate. The agent just calls two tools with code. Everything else happens on the server.

### Get started today

The Cloudflare MCP server is available now. Point your MCP client at the server URL and you'll be redirected to Cloudflare to authorize and select the permissions to grant to your agent. Add this config to your MCP client:

```javascript
{
  "mcpServers": {
    "cloudflare-api": {
      "url": "https://mcp.cloudflare.com/mcp"
    }
  }
}
```

For CI/CD, automation, or if you prefer managing tokens yourself, create a Cloudflare API token with the permissions you need. Both user tokens and account tokens are supported and can be passed as bearer tokens in the `Authorization` header.

More information on different MCP setup configurations can be found at the [Cloudflare MCP repository](https://github.com/cloudflare/mcp).

### Looking forward

Code Mode solves context costs for a single API. But agents rarely talk to one service. A developer's agent might need the Cloudflare API alongside GitHub, a database, and an internal docs server. Each additional MCP server brings the same context window pressure we started with.

[Cloudflare MCP Server Portals](https://blog.cloudflare.com/zero-trust-mcp-server-portals/) let you compose multiple MCP servers behind a single gateway with unified auth and access control. We are building a first-class Code Mode integration for all your MCP servers, and exposing them to agents with built-in progressive discovery and the same fixed-token footprint, regardless of how many services sit behind the gateway.

Cloudflare's connectivity cloud protects [entire corporate networks](https://www.cloudflare.com/network-services/), helps customers build [Internet-scale applications efficiently](https://workers.cloudflare.com/), accelerates any [website or Internet application](https://www.cloudflare.com/performance/accelerate-internet-applications/), [wards off DDoS attacks](https://www.cloudflare.com/ddos/), keeps [hackers at bay](https://www.cloudflare.com/application-security/), and can help you on [your journey to Zero Trust](https://www.cloudflare.com/products/zero-trust/).  
  
Visit [1.1.1.1](https://one.one.one.one/) from any device to get started with our free app that makes your Internet faster and safer.  
  
To learn more about our mission to help build a better Internet, [start here](https://www.cloudflare.com/learning/what-is-cloudflare/). If you're looking for a new career direction, check out [our open positions](https://www.cloudflare.com/careers).

<iframe title="cloudflare-tv-live-link" src="https://cloudflare.tv/embed/live.html"></iframe>[Developers](https://blog.cloudflare.com/tag/developers/) [Developer Platform](https://blog.cloudflare.com/tag/developer-platform/) [AI](https://blog.cloudflare.com/tag/ai/) [Workers AI](https://blog.cloudflare.com/tag/workers-ai/) [Cloudflare Workers](https://blog.cloudflare.com/tag/workers/) [Optimization](https://blog.cloudflare.com/tag/optimization/) [Open Source](https://blog.cloudflare.com/tag/open-source/)