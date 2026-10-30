// Connects to the server with the official TypeScript MCP SDK client and
// uses it the way MCP clients do. The SDK validates every response against
// its schemas, compiles each tool's outputSchema with Ajv, and checks
// structuredContent against it on tools/call, so anything it rejects here
// would break clients built on it.
//
// Usage: node client.mjs <mcp-url>. Prints a JSON report; exits 1 on failures.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const failures = [];
// Tools that return isError, e.g. because the fake FortiGate lacks an
// endpoint, skip output validation; the Go test reports them.
const toolErrors = {};
const counts = { tools: 0, toolCalls: 0, toolErrors: 0, prompts: 0, resources: 0, resourceTemplates: 0 };

async function check(what, fn) {
  try {
    return await fn();
  } catch (err) {
    failures.push(`${what}: ${err.message}`);
    return undefined;
  }
}

const client = new Client({ name: 'fortigate-mcp-conformance', version: '0' });
await client.connect(new StreamableHTTPClientTransport(new URL(process.argv[2])));

const tools = (await check('tools/list', () => client.listTools()))?.tools ?? [];
counts.tools = tools.length;

// Read-only tools that need no arguments can run against the fake FortiGate.
// The SDK fails the call if structuredContent doesn't match outputSchema.
for (const tool of tools) {
  if (!tool.annotations?.readOnlyHint || tool.inputSchema.required?.length) continue;
  const res = await check(`tools/call ${tool.name}`, () => client.callTool({ name: tool.name, arguments: {} }));
  if (res?.isError) {
    counts.toolErrors++;
    toolErrors[tool.name] = res.content?.[0]?.text?.slice(0, 200);
  }  else if (res) counts.toolCalls++;
}

const prompts = (await check('prompts/list', () => client.listPrompts()))?.prompts ?? [];
for (const prompt of prompts) {
  const args = Object.fromEntries((prompt.arguments ?? []).filter((a) => a.required).map((a) => [a.name, 'x']));
  if (await check(`prompts/get ${prompt.name}`, () => client.getPrompt({ name: prompt.name, arguments: args }))) counts.prompts++;
}

const resources = (await check('resources/list', () => client.listResources()))?.resources ?? [];
for (const resource of resources) {
  if (await check(`resources/read ${resource.uri}`, () => client.readResource({ uri: resource.uri }))) counts.resources++;
}
counts.resourceTemplates =
  (await check('resources/templates/list', () => client.listResourceTemplates()))?.resourceTemplates?.length ?? 0;

await client.close();
console.log(JSON.stringify({ counts, failures, toolErrors }, null, 2));
process.exit(failures.length ? 1 : 0);
