import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { PROJECT_ROOT, loadConfig } from "../src/config.mjs";
import { createBridgeServer } from "../src/server.mjs";

const execFileAsync = promisify(execFile);

const EXPECTED_TOOLS = [
  "list_tasks",
  "get_task",
  "claim_task",
  "submit_task_result",
  "propose_task",
  "list_files",
  "read_file",
  "write_file",
  "search_notes",
  "read_note",
  "list_repo_tree",
  "read_repo_file",
  "search_repo_code",
  "get_workspace_status",
  "checkpoint_task",
  "list_notes",
  "search_files",
  "edit_file",
  "list_file_snapshots",
  "restore_file_snapshot",
];

function sha256Base64Url(str) {
  return crypto.createHash("sha256").update(str, "utf8").digest("base64url");
}

function extractHiddenInput(html, name) {
  const match = html.match(new RegExp(`name="${name}"\\s+value="([^"]+)"`));
  assert.ok(match, `Expected hidden input '${name}' in OAuth consent HTML`);
  return match[1];
}

async function mcpCall(baseUrl, accessToken, sessionId, payload) {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
    "MCP-Protocol-Version": "2025-11-25",
  };
  if (sessionId) {
    headers["Mcp-Session-Id"] = sessionId;
  }
  const res = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });
  const text = await res.text();
  return {
    status: res.status,
    headers: res.headers,
    json: text ? JSON.parse(text) : null,
  };
}

async function runAuthorizeRoundtrip({
  baseUrl,
  clientId,
  redirectUri,
  state,
  codeChallenge,
  passphrase,
  wrongPassphrase,
}) {
  const authUrl = new URL(`${baseUrl}/oauth/authorize`);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("scope", "mcp:tools");

  const getRes = await fetch(authUrl);
  assert.equal(getRes.status, 200);
  let html = await getRes.text();
  assert.ok(html.includes(`<strong>Redirect URI:</strong> ${redirectUri}`));
  let csrfToken = extractHiddenInput(html, "csrf_token");

  if (wrongPassphrase) {
    const badForm = new URLSearchParams({
      csrf_token: csrfToken,
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      scope: "mcp:tools",
      resource: "",
      passphrase: wrongPassphrase,
    });
    const badRes = await fetch(`${baseUrl}/oauth/authorize`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: badForm.toString(),
      redirect: "manual",
    });
    assert.equal(badRes.status, 403);
    html = await badRes.text();
    csrfToken = extractHiddenInput(html, "csrf_token");
  }

  const okForm = new URLSearchParams({
    csrf_token: csrfToken,
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    scope: "mcp:tools",
    resource: "",
    passphrase,
  });

  const okRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: okForm.toString(),
    redirect: "manual",
  });
  assert.equal(okRes.status, 302);
  const location = okRes.headers.get("location");
  await okRes.text();
  assert.ok(location, "Expected Location redirect header");
  const redirected = new URL(location);
  assert.equal(redirected.searchParams.get("state"), state);
  const code = redirected.searchParams.get("code");
  assert.ok(code, "Expected authorization code in redirect query");
  return code;
}

test("gemini-bridge-mcp end-to-end OAuth, MCP tools, security sandbox, and CLI", async (t) => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "gemini-bridge-test-"));
  const dataDir = path.join(tmpDir, "data");
  const outsideFile = path.join(tmpDir, "outside-secret.txt");
  await fs.writeFile(outsideFile, "TOP_SECRET_OUTSIDE_SANDBOX", "utf8");

  const ownerPassphrase = "test-owner-passphrase-!@#";
  const ownerPassphrases = "personal:pass-personal,work:pass-work";
  const mcpAccountKeys =
    "acc1:gbk_test_key_acc1_abcdef,acc2:gbk_test_key_acc2_ghijkl,acc3:gbk_test_key_acc3_mnopqr";
  const adminToken = "test-admin-token-xyz";

  const { server, config } = createBridgeServer({
    skipDotEnv: true,
    host: "127.0.0.1",
    port: 0,
    dataDir,
    ownerPassphrase,
    ownerPassphrases,
    mcpAccountKeys,
    adminToken,
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;

  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  // 1. Health check & static logo endpoints
  const healthRes = await fetch(`${baseUrl}/api/health`);
  assert.equal(healthRes.status, 200);
  const healthJson = await healthRes.json();
  assert.equal(healthJson.ok, true);
  assert.equal(healthJson.service, "gemini-handoff-mcp");

  for (const iconPath of ["/assets/logo.svg", "/logo.svg", "/favicon.ico"]) {
    const iconRes = await fetch(`${baseUrl}${iconPath}`);
    assert.equal(iconRes.status, 200, `${iconPath} must return 200`);
    assert.match(iconRes.headers.get("content-type") || "", /image\/svg\+xml/);
    assert.match(await iconRes.text(), /<svg[\s>]/);
  }

  // 2. Unauthenticated POST /mcp returns 401 + WWW-Authenticate protected resource metadata
  const unauthMcp = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
  });
  assert.equal(unauthMcp.status, 401);
  const wwwAuth = unauthMcp.headers.get("www-authenticate") || "";
  assert.match(wwwAuth, /resource_metadata="http:\/\/127\.0\.0\.1:\d+\/\.well-known\/oauth-protected-resource\/mcp"/);
  await unauthMcp.text();

  // Malformed X-Forwarded-Host must not inject quotes into WWW-Authenticate; malformed Host -> 400
  const badFwdMcp = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Forwarded-Host": 'evil.com" scope="admin',
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
  });
  assert.equal(badFwdMcp.status, 401);
  const badFwdAuth = badFwdMcp.headers.get("www-authenticate") || "";
  assert.doesNotMatch(badFwdAuth, /evil\.com/);
  assert.match(badFwdAuth, /resource_metadata="http:\/\/127\.0\.0\.1:\d+\/\.well-known\/oauth-protected-resource\/mcp"/);
  await badFwdMcp.text();

  const badHostRes = await new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port: address.port,
        path: "/api/health",
        method: "GET",
        headers: { Host: "127.0.0.1:notaport" },
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          body += chunk;
        });
        res.on("end", () => resolve({ status: res.statusCode, json: JSON.parse(body) }));
      }
    );
    req.on("error", reject);
    req.end();
  });
  assert.equal(badHostRes.status, 400);
  assert.equal(badHostRes.json.error, "http_error");
  assert.equal(badHostRes.json.message, "Invalid request URL or Host header");

  // 3. OAuth discovery metadata endpoints
  for (const wellKnownPath of [
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
  ]) {
    const res = await fetch(`${baseUrl}${wellKnownPath}`);
    assert.equal(res.status, 200);
    const meta = await res.json();
    assert.equal(meta.resource, `${baseUrl}/mcp`);
    assert.deepEqual(meta.authorization_servers, [baseUrl]);
  }

  const authMetaRes = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);
  assert.equal(authMetaRes.status, 200);
  const authMeta = await authMetaRes.json();
  assert.equal(authMeta.registration_endpoint, `${baseUrl}/oauth/register`);
  assert.ok(authMeta.code_challenge_methods_supported.includes("S256"));

  // 4. RFC 7591 Dynamic Client Registration
  const redirectUri = "https://oauth-redirect.googleusercontent.com/r/gemini-bridge-test";
  const regRes = await fetch(`${baseUrl}/oauth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Gemini Test Client",
      redirect_uris: [redirectUri],
    }),
  });
  assert.equal(regRes.status, 201);
  const client = await regRes.json();
  assert.ok(client.client_id.startsWith("gb_c_"));
  assert.ok(client.client_secret.startsWith("gb_s_"));

  // 5. OAuth 2.1 Authorization Code + PKCE (S256) with 2048-char state
  const longState = "s".repeat(2048);
  const verifier1 = "verifier_alpha_0123456789_abcdefghijklmnopqrstuvwxyz_ABC";
  const challenge1 = sha256Base64Url(verifier1);

  const code1 = await runAuthorizeRoundtrip({
    baseUrl,
    clientId: client.client_id,
    redirectUri,
    state: longState,
    codeChallenge: challenge1,
    passphrase: ownerPassphrase,
    wrongPassphrase: "totally-wrong-passphrase",
  });

  // Wrong code_verifier -> 400
  const wrongTokenRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code1,
      redirect_uri: redirectUri,
      client_id: client.client_id,
      client_secret: client.client_secret,
      code_verifier: "wrong-verifier-value-that-does-not-match",
    }).toString(),
  });
  assert.equal(wrongTokenRes.status, 400);
  await wrongTokenRes.text();

  // Replaying consumed code1 -> 400
  const replayCode1 = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code1,
      redirect_uri: redirectUri,
      client_id: client.client_id,
      client_secret: client.client_secret,
      code_verifier: verifier1,
    }).toString(),
  });
  assert.equal(replayCode1.status, 400);
  await replayCode1.text();

  // Fresh code + valid code_verifier -> 200
  const verifier2 = "verifier_beta_0123456789_abcdefghijklmnopqrstuvwxyz_XYZ";
  const challenge2 = sha256Base64Url(verifier2);
  const code2 = await runAuthorizeRoundtrip({
    baseUrl,
    clientId: client.client_id,
    redirectUri,
    state: longState,
    codeChallenge: challenge2,
    passphrase: ownerPassphrase,
  });

  const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code2,
      redirect_uri: redirectUri,
      client_id: client.client_id,
      client_secret: client.client_secret,
      code_verifier: verifier2,
    }).toString(),
  });
  assert.equal(tokenRes.status, 200);
  const tokenData = await tokenRes.json();
  assert.ok(tokenData.access_token);
  assert.ok(tokenData.refresh_token);

  // Replay code2 -> 400
  const replayCode2 = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code2,
      redirect_uri: redirectUri,
      client_id: client.client_id,
      client_secret: client.client_secret,
      code_verifier: verifier2,
    }).toString(),
  });
  assert.equal(replayCode2.status, 400);
  await replayCode2.text();

  // Refresh token rotation -> 200
  const refreshRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: tokenData.refresh_token,
      client_id: client.client_id,
      client_secret: client.client_secret,
    }).toString(),
  });
  assert.equal(refreshRes.status, 200);
  const rotatedTokens = await refreshRes.json();
  assert.ok(rotatedTokens.access_token);
  assert.notEqual(rotatedTokens.refresh_token, tokenData.refresh_token);
  const accessToken = rotatedTokens.access_token;

  // Malformed % sequence in Authorization: Basic -> 401 invalid_client (not 500)
  const badBasicRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${Buffer.from(`${client.client_id}:%ZZ`).toString("base64")}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: "unused",
      client_id: client.client_id,
    }).toString(),
  });
  assert.equal(badBasicRes.status, 401);
  assert.equal((await badBasicRes.json()).error, "invalid_client");

  // 6. MCP Streamable HTTP lifecycle & tools/list
  const initRes = await mcpCall(baseUrl, accessToken, null, {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "test-gemini-app", version: "1.0.0" },
    },
  });
  assert.equal(initRes.status, 200);
  const sessionId = initRes.headers.get("mcp-session-id");
  assert.ok(sessionId, "Expected Mcp-Session-Id header");
  assert.equal(initRes.headers.get("mcp-protocol-version"), "2025-11-25");
  assert.equal(initRes.json.result.serverInfo.name, "gemini-handoff-mcp");
  assert.ok(Array.isArray(initRes.json.result.serverInfo.icons));
  assert.match(initRes.json.result.serverInfo.icons[0].src, /\/assets\/logo\.svg$/);
  assert.equal(initRes.json.result.serverInfo.icons[0].mimeType, "image/svg+xml");

  const notifRes = await mcpCall(baseUrl, accessToken, sessionId, {
    jsonrpc: "2.0",
    method: "notifications/initialized",
  });
  assert.equal(notifRes.status, 202);

  const getMcpRes = await fetch(`${baseUrl}/mcp`, {
    method: "GET",
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  assert.equal(getMcpRes.status, 405);
  assert.ok(getMcpRes.headers.get("allow"));
  await getMcpRes.text();

  const listToolsRes = await mcpCall(baseUrl, accessToken, sessionId, {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list",
  });
  assert.equal(listToolsRes.status, 200);
  const toolNames = listToolsRes.json.result.tools.map((tool) => tool.name);
  assert.deepEqual(toolNames, EXPECTED_TOOLS);
  assert.equal(toolNames.length, 20);
  for (const tool of listToolsRes.json.result.tools) {
    assert.equal(tool.inputSchema?.type, "object");
  }

  // JSON-RPC numeric id: 0 on error must preserve id: 0 and return HTTP 200
  const zeroIdErr = await mcpCall(baseUrl, accessToken, sessionId, {
    jsonrpc: "2.0",
    id: 0,
    method: "nonexistent/method",
  });
  assert.equal(zeroIdErr.status, 200);
  assert.equal(zeroIdErr.json.id, 0);
  assert.equal(zeroIdErr.json.error?.code, -32601);

  // 7. Push test data via Admin API & exercise all 12 MCP tools end-to-end
  const adminHeaders = {
    Authorization: `Bearer ${adminToken}`,
  };

  assert.equal(
    (
      await fetch(`${baseUrl}/api/sync/files/docs/spec.md`, {
        method: "PUT",
        headers: adminHeaders,
        body: "# Product Spec\nLine 2\nTargetRequirement: OAuth 2.1\n",
      })
    ).status,
    200
  );

  assert.equal(
    (
      await fetch(`${baseUrl}/api/sync/notes/research/oauth-note.md`, {
        method: "PUT",
        headers: adminHeaders,
        body: "Intro line\nContext before\nGemini uses PKCE S256\nContext after\nFinal line\n",
      })
    ).status,
    200
  );

  assert.equal(
    (
      await fetch(`${baseUrl}/api/sync/repos/demo-app/src/auth.mjs`, {
        method: "PUT",
        headers: adminHeaders,
        body: "export function verifySession(token) {\n  return token.startsWith('gb_');\n}\n",
      })
    ).status,
    200
  );

  const createTaskRes = await fetch(`${baseUrl}/api/tasks`, {
    method: "POST",
    headers: { ...adminHeaders, "Content-Type": "application/json" },
    body: JSON.stringify({
      title: "Review auth architecture",
      objective: "Verify spec, notes, and repo auth helper",
      instructions: "Read spec.md and demo-app/src/auth.mjs, then write a summary.",
      attached_files: ["docs/spec.md"],
      priority: "high",
      tags: ["auth", "mcp"],
    }),
  });
  assert.equal(createTaskRes.status, 201);
  const { task } = await createTaskRes.json();

  const callTool = async (id, name, args) => {
    const r = await mcpCall(baseUrl, accessToken, sessionId, {
      jsonrpc: "2.0",
      id,
      method: "tools/call",
      params: { name, arguments: args },
    });
    assert.equal(r.status, 200);
    return r.json.result;
  };

  const listed = JSON.parse((await callTool(10, "list_tasks", { status: "pending" })).content[0].text);
  assert.equal(listed.count, 1);
  assert.equal(listed.tasks[0].id, task.id);

  const fetched = JSON.parse((await callTool(11, "get_task", { task_id: task.id })).content[0].text);
  assert.equal(fetched.title, "Review auth architecture");

  const claimed = JSON.parse(
    (await callTool(12, "claim_task", { task_id: task.id, note: "Working on it" })).content[0].text
  );
  assert.equal(claimed.status, "in_progress");

  const filesTree = JSON.parse(
    (await callTool(13, "list_files", { recursive: true })).content[0].text
  );
  assert.ok(filesTree.entries.some((e) => e.path === "docs/spec.md"));

  const fileContent = (await callTool(14, "read_file", { path: "docs/spec.md", start_line: 2, end_line: 3 }))
    .content[0].text;
  assert.match(fileContent, /TargetRequirement: OAuth 2\.1/);

  const writeOut = JSON.parse(
    (
      await callTool(15, "write_file", {
        path: "reports/review.md",
        content: "# Review Report\nAll checks passed.\n",
        mode: "overwrite",
      })
    ).content[0].text
  );
  assert.equal(writeOut.ok, true);

  const noteHits = (await callTool(16, "search_notes", { query: "PKCE S256" })).content[0].text;
  assert.match(noteHits, /research\/oauth-note\.md:3/);
  assert.match(noteHits, /Context before/);
  assert.match(noteHits, /Context after/);

  const noteBody = (await callTool(17, "read_note", { path: "research/oauth-note.md" })).content[0].text;
  assert.match(noteBody, /Gemini uses PKCE S256/);

  const repoTree = JSON.parse(
    (await callTool(18, "list_repo_tree", { repo_path: "demo-app" })).content[0].text
  );
  assert.ok(repoTree.entries.some((e) => e.path === "demo-app/src/auth.mjs"));

  const repoCode = (await callTool(19, "read_repo_file", { path: "demo-app/src/auth.mjs" })).content[0]
    .text;
  assert.match(repoCode, /1 \| export function verifySession/);

  const codeHits = (
    await callTool(20, "search_repo_code", { query: "verifySession", file_glob: ".mjs" })
  ).content[0].text;
  assert.match(codeHits, /demo-app\/src\/auth\.mjs:1:/);

  const submitted = JSON.parse(
    (
      await callTool(21, "submit_task_result", {
        task_id: task.id,
        summary: "Auth matches OAuth 2.1 and PKCE S256 requirements.",
        content: "# Full Report\n\nVerified `docs/spec.md` and `demo-app/src/auth.mjs`.",
        artifacts: ["reports/review.md"],
      })
    ).content[0].text
  );
  assert.equal(submitted.status, "completed");

  // Verify via Admin API
  const verifyTaskRes = await fetch(`${baseUrl}/api/tasks/${task.id}`, { headers: adminHeaders });
  assert.equal(verifyTaskRes.status, 200);
  const verifiedTask = (await verifyTaskRes.json()).task;
  assert.equal(verifiedTask.status, "completed");
  assert.match(verifiedTask.result_markdown, /Full Report/);

  const verifyFileRes = await fetch(`${baseUrl}/api/sync/files/reports/review.md`, {
    headers: adminHeaders,
  });
  assert.equal(verifyFileRes.status, 200);
  assert.match(await verifyFileRes.text(), /All checks passed/);

  // Test propose_task (reverse proposal from Gemini APP to Antigravity)
  const proposedRes = JSON.parse(
    (
      await callTool(22, "propose_task", {
        title: "Gemini Reverse Proposal",
        summary: "Architecture proposal initiated from mobile Gemini APP",
        plan_markdown: "# Mobile Proposal\nDesigned in Gemini APP.\n",
        suggested_actions: "Review and scaffold microservices.",
        tags: ["mobile", "proposal"],
      })
    ).content[0].text
  );
  assert.equal(proposedRes.status, "proposed");
  assert.ok(proposedRes.id);

  const verifyProposedRes = await fetch(`${baseUrl}/api/tasks/${proposedRes.id}`, {
    headers: adminHeaders,
  });
  assert.equal(verifyProposedRes.status, 200);
  const verifiedProposed = (await verifyProposedRes.json()).task;
  assert.equal(verifiedProposed.status, "proposed");
  assert.match(verifiedProposed.result_markdown, /Mobile Proposal/);

  // 8. Security boundaries: traversal, sensitive files, symlinks, read-only repos
  for (const badPath of ["../outside-secret.txt", "../../etc/passwd", "C:\\Windows\\win.ini"]) {
    const rFile = await callTool(30, "read_file", { path: badPath });
    assert.equal(rFile.isError, true, `read_file must reject ${badPath}`);

    const wFile = await callTool(31, "write_file", { path: badPath, content: "x" });
    assert.equal(wFile.isError, true, `write_file must reject ${badPath}`);

    const rNote = await callTool(32, "read_note", { path: badPath });
    assert.equal(rNote.isError, true, `read_note must reject ${badPath}`);

    const rRepo = await callTool(33, "read_repo_file", { path: badPath });
    assert.equal(rRepo.isError, true, `read_repo_file must reject ${badPath}`);

    const syncAttempt = await fetch(`${baseUrl}/api/sync/files/${badPath}`, {
      method: "PUT",
      headers: adminHeaders,
      body: "evil",
    });
    assert.equal(syncAttempt.ok, false, `Admin sync must reject ${badPath}`);
  }

  for (const sensitivePath of [".env", "nested/.env.local", "server.key", "credentials.json"]) {
    const wSens = await callTool(34, "write_file", { path: sensitivePath, content: "SECRET=1" });
    assert.equal(wSens.isError, true, `write_file must block ${sensitivePath}`);
  }

  // Place sensitive files directly on disk and confirm tools refuse to expose them
  await fs.writeFile(path.join(config.reposRoot, "demo-app", ".env"), "DB_PASS=123", "utf8");
  await fs.writeFile(path.join(config.filesRoot, "server.key"), "PRIVATE KEY", "utf8");
  await fs.writeFile(path.join(config.notesRoot, "credentials.json"), '{"token":"x"}', "utf8");

  assert.equal((await callTool(35, "read_repo_file", { path: "demo-app/.env" })).isError, true);
  assert.equal((await callTool(36, "read_file", { path: "server.key" })).isError, true);
  assert.equal((await callTool(37, "read_note", { path: "credentials.json" })).isError, true);
  const sensSearch = await callTool(38, "search_repo_code", { query: "DB_PASS" });
  assert.doesNotMatch(sensSearch.content[0].text, /DB_PASS/);

  // Symlink escape test (skip gracefully on Windows if privilege EPERM occurs)
  const symlinkTargetPath = path.join(config.filesRoot, "escape-link.txt");
  let symlinkCreated = false;
  try {
    await fs.symlink(outsideFile, symlinkTargetPath);
    symlinkCreated = true;
  } catch (err) {
    if (err?.code !== "EPERM" && err?.code !== "EACCES") {
      throw err;
    }
  }
  if (symlinkCreated) {
    const symRead = await callTool(39, "read_file", { path: "escape-link.txt" });
    assert.equal(symRead.isError, true);
    const symWrite = await callTool(40, "write_file", { path: "escape-link.txt", content: "pwn" });
    assert.equal(symWrite.isError, true);

    const intraSymlinkPath = path.join(config.filesRoot, "alias-to-key.txt");
    await fs.symlink(path.join(config.filesRoot, "server.key"), intraSymlinkPath);
    const intraRead = await callTool(41, "read_file", { path: "alias-to-key.txt" });
    assert.equal(intraRead.isError, true);
    const intraWrite = await callTool(42, "write_file", { path: "alias-to-key.txt", content: "pwn" });
    assert.equal(intraWrite.isError, true);
  }

  // Intra-sandbox directory link/junction to sensitive directory (.git) must be blocked
  const gitHiddenDir = path.join(config.filesRoot, ".git");
  const intraDirLinkPath = path.join(config.filesRoot, "alias-to-git");
  await fs.mkdir(gitHiddenDir, { recursive: true });
  let dirLinkCreated = false;
  try {
    await fs.symlink(gitHiddenDir, intraDirLinkPath, process.platform === "win32" ? "junction" : "dir");
    dirLinkCreated = true;
  } catch (err) {
    if (err?.code !== "EPERM" && err?.code !== "EACCES") {
      throw err;
    }
  }
  if (dirLinkCreated) {
    const intraDirWrite = await callTool(43, "write_file", {
      path: "alias-to-git/config",
      content: "pwn",
    });
    assert.equal(intraDirWrite.isError, true);
  }

  // Confirm no write tool exists for repos bucket
  assert.equal(toolNames.some((n) => n.includes("write_repo")), false);

  // 9. CLI subprocess test against running server
  const cliPath = path.join(PROJECT_ROOT, "cli", "bridge-cli.mjs");
  const cliEnv = {
    ...process.env,
    BRIDGE_URL: baseUrl,
    ADMIN_TOKEN: adminToken,
    DATA_DIR: dataDir,
  };

  const healthCli = await execFileAsync(process.execPath, [cliPath, "health"], { env: cliEnv });
  assert.match(healthCli.stdout, /"ok":\s*true/);

  const localUploadSrc = path.join(tmpDir, "cli-upload.md");
  await fs.writeFile(localUploadSrc, "# CLI Upload\nHello Bridge\n", "utf8");
  const pushCli = await execFileAsync(
    process.execPath,
    [cliPath, "push-file", localUploadSrc, "cli/uploaded.md"],
    { env: cliEnv }
  );
  assert.match(pushCli.stdout, /Uploaded cli\/uploaded\.md/);

  // Push small repo directory via CLI
  const sampleRepoDir = path.join(tmpDir, "sample-repo");
  await fs.mkdir(path.join(sampleRepoDir, "src"), { recursive: true });
  await fs.mkdir(path.join(sampleRepoDir, "node_modules", "pkg"), { recursive: true });
  await fs.writeFile(path.join(sampleRepoDir, "src", "index.js"), "console.log('hi');\n", "utf8");
  await fs.writeFile(path.join(sampleRepoDir, ".env"), "SECRET=ignored\n", "utf8");
  await fs.writeFile(path.join(sampleRepoDir, "node_modules", "pkg", "ignored.js"), "x", "utf8");
  const pushRepoCli = await execFileAsync(
    process.execPath,
    [cliPath, "push-repo", sampleRepoDir, "sample-repo"],
    { env: cliEnv }
  );
  assert.match(pushRepoCli.stdout, /uploaded=1/);

  const dispatchCli = await execFileAsync(
    process.execPath,
    [
      cliPath,
      "dispatch",
      "--title",
      "CLI Dispatched Task",
      "--objective",
      "Verify CLI end-to-end",
      "--attach",
      "cli/uploaded.md",
    ],
    { env: cliEnv }
  );
  const taskIdMatch = dispatchCli.stdout.match(/Task dispatched:\s+(task_[a-zA-Z0-9_-]+)/);
  assert.ok(taskIdMatch, "Expected CLI dispatch to print created task ID");
  const cliTaskId = taskIdMatch[1];

  const listCli = await execFileAsync(process.execPath, [cliPath, "list"], { env: cliEnv });
  assert.match(listCli.stdout, new RegExp(cliTaskId));

  // Complete the CLI task via MCP and pull via CLI
  await callTool(50, "submit_task_result", {
    task_id: cliTaskId,
    summary: "CLI task verified.",
    content: "# CLI Task Output\nDone.\n",
  });

  const pulledOutPath = path.join(tmpDir, "pulled-result.md");
  const pullCli = await execFileAsync(
    process.execPath,
    [cliPath, "pull", cliTaskId, "--out", pulledOutPath],
    { env: cliEnv }
  );
  assert.match(pullCli.stdout, /CLI task verified\./);
  const beginMatch = pullCli.stdout.match(/<<<UNTRUSTED_REMOTE_ARTIFACT_BEGIN nonce=([0-9a-f]{12})>>>/);
  assert.ok(beginMatch, "Expected randomized untrusted boundary start marker in CLI pull stdout");
  assert.ok(
    pullCli.stdout.includes(`<<<UNTRUSTED_REMOTE_ARTIFACT_END nonce=${beginMatch[1]}>>>`),
    "Expected matching randomized untrusted boundary end marker in CLI pull stdout"
  );
  const pulledDisk = await fs.readFile(pulledOutPath, "utf8");
  assert.match(pulledDisk, /# CLI Task Output/);

  // Test CLI listing and pulling reverse proposals
  const proposalsCli = await execFileAsync(process.execPath, [cliPath, "proposals"], { env: cliEnv });
  assert.match(proposalsCli.stdout, new RegExp(proposedRes.id));
  assert.match(proposalsCli.stdout, /Gemini Reverse Proposal/);

  const pullProposalCli = await execFileAsync(process.execPath, [cliPath, "pull", proposedRes.id], {
    env: cliEnv,
  });
  assert.match(pullProposalCli.stdout, /Source: Initiated by Gemini APP \(Proposal\)/);
  assert.match(pullProposalCli.stdout, /Mobile Proposal/);

  // Multi-Account Verification: Register, authorize personal and work clients
  const regPersonalRes = await fetch(`${baseUrl}/oauth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Gemini Personal Client",
      redirect_uris: ["https://example.com/oauth/personal/callback"],
      token_endpoint_auth_method: "client_secret_post",
    }),
  });
  assert.equal(regPersonalRes.status, 201);
  const clientPersonal = await regPersonalRes.json();

  const regWorkRes = await fetch(`${baseUrl}/oauth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Gemini Work Client",
      redirect_uris: ["https://example.com/oauth/work/callback"],
      token_endpoint_auth_method: "client_secret_post",
    }),
  });
  assert.equal(regWorkRes.status, 201);
  const clientWork = await regWorkRes.json();

  const verifierPersonal = "verifier_personal_123456789012345678901234567890";
  const challengePersonal = sha256Base64Url(verifierPersonal);
  const codePersonal = await runAuthorizeRoundtrip({
    baseUrl,
    clientId: clientPersonal.client_id,
    redirectUri: "https://example.com/oauth/personal/callback",
    state: "state_personal_xyz",
    codeChallenge: challengePersonal,
    passphrase: "pass-personal",
  });

  const tokenPersonalRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "authorization_code",
      code: codePersonal,
      client_id: clientPersonal.client_id,
      client_secret: clientPersonal.client_secret,
      redirect_uri: "https://example.com/oauth/personal/callback",
      code_verifier: verifierPersonal,
    }),
  });
  assert.equal(tokenPersonalRes.status, 200);
  const tokensPersonal = await tokenPersonalRes.json();
  assert.equal(tokensPersonal.account_id, "personal");

  const verifierWork = "verifier_work_123456789012345678901234567890";
  const challengeWork = sha256Base64Url(verifierWork);
  const codeWork = await runAuthorizeRoundtrip({
    baseUrl,
    clientId: clientWork.client_id,
    redirectUri: "https://example.com/oauth/work/callback",
    state: "state_work_xyz",
    codeChallenge: challengeWork,
    passphrase: "pass-work",
  });

  const tokenWorkRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "authorization_code",
      code: codeWork,
      client_id: clientWork.client_id,
      client_secret: clientWork.client_secret,
      redirect_uri: "https://example.com/oauth/work/callback",
      code_verifier: verifierWork,
    }),
  });
  assert.equal(tokenWorkRes.status, 200);
  const tokensWork = await tokenWorkRes.json();
  assert.equal(tokensWork.account_id, "work");

  // Call get_workspace_status with both tokens and assert current_account
  const statusPersonalCall = await mcpCall(baseUrl, tokensPersonal.access_token, null, {
    jsonrpc: "2.0",
    id: 101,
    method: "tools/call",
    params: { name: "get_workspace_status", arguments: {} },
  });
  const statusPersonal = JSON.parse(statusPersonalCall.json.result.content[0].text);
  assert.equal(statusPersonal.current_account, "personal");
  assert.equal(statusPersonal.configured_accounts, undefined);
  assert.equal(statusPersonal.sessions?.sessions, undefined);

  const statusWorkCall = await mcpCall(baseUrl, tokensWork.access_token, null, {
    jsonrpc: "2.0",
    id: 102,
    method: "tools/call",
    params: { name: "get_workspace_status", arguments: {} },
  });
  const statusWork = JSON.parse(statusWorkCall.json.result.content[0].text);
  assert.equal(statusWork.current_account, "work");

  // Submit proposal from personal account
  const propPersonalCall = await mcpCall(baseUrl, tokensPersonal.access_token, null, {
    jsonrpc: "2.0",
    id: 103,
    method: "tools/call",
    params: {
      name: "propose_task",
      arguments: {
        title: "Personal Proposal",
        summary: "Proposal submitted by Personal Gemini APP.",
        plan_markdown: "# Personal Plan\nStep 1.\n",
      },
    },
  });
  const propPersonal = JSON.parse(propPersonalCall.json.result.content[0].text);
  assert.equal(propPersonal.account, "personal");

  // Submit proposal from work account
  const propWorkCall = await mcpCall(baseUrl, tokensWork.access_token, null, {
    jsonrpc: "2.0",
    id: 104,
    method: "tools/call",
    params: {
      name: "propose_task",
      arguments: {
        title: "Work Proposal",
        summary: "Proposal submitted by Work Gemini APP.",
        plan_markdown: "# Work Plan\nStep 1.\n",
      },
    },
  });
  const propWork = JSON.parse(propWorkCall.json.result.content[0].text);
  assert.equal(propWork.account, "work");

  // Filter list_tasks by account
  const listPersonalCall = await mcpCall(baseUrl, tokensPersonal.access_token, null, {
    jsonrpc: "2.0",
    id: 105,
    method: "tools/call",
    params: {
      name: "list_tasks",
      arguments: { status: "proposed", account: "personal" },
    },
  });
  const listPersonal = JSON.parse(listPersonalCall.json.result.content[0].text);
  assert.ok(listPersonal.tasks.some((t) => t.id === propPersonal.id));
  assert.ok(!listPersonal.tasks.some((t) => t.id === propWork.id));

  const listWorkCall = await mcpCall(baseUrl, tokensWork.access_token, null, {
    jsonrpc: "2.0",
    id: 106,
    method: "tools/call",
    params: {
      name: "list_tasks",
      arguments: { status: "proposed", account: "work" },
    },
  });
  const listWork = JSON.parse(listWorkCall.json.result.content[0].text);
  assert.ok(listWork.tasks.some((t) => t.id === propWork.id));
  assert.ok(!listWork.tasks.some((t) => t.id === propPersonal.id));

  // CLI dispatch and list with --account
  const dispatchAcctCli = await execFileAsync(
    process.execPath,
    [
      cliPath,
      "dispatch",
      "--title",
      "Account Specific Task",
      "--objective",
      "Verify CLI account filtering",
      "--account",
      "work",
    ],
    { env: cliEnv }
  );
  assert.match(dispatchAcctCli.stdout, /Target Account:\s+work/);
  const acctTaskId = dispatchAcctCli.stdout.match(/Task dispatched:\s+(task_[a-zA-Z0-9_-]+)/)[1];

  const listWorkCli = await execFileAsync(
    process.execPath,
    [cliPath, "list", "--account", "work"],
    { env: cliEnv }
  );
  assert.match(listWorkCli.stdout, new RegExp(acctTaskId));
  assert.match(listWorkCli.stdout, /\{@work\}/);

  const listPersonalCli = await execFileAsync(
    process.execPath,
    [cliPath, "list", "--account", "personal"],
    { env: cliEnv }
  );
  assert.doesNotMatch(listPersonalCli.stdout, new RegExp(acctTaskId));

  // Per-Account Secret Path URL (/mcp/u/<key>) — No OAuth / No Passwords
  const mcpPathCall = async (urlPath, sessionId, payload, method = "POST") => {
    const headers = {
      Accept: "application/json, text/event-stream",
      "MCP-Protocol-Version": "2025-11-25",
    };
    if (method === "POST") {
      headers["Content-Type"] = "application/json";
    }
    if (sessionId) {
      headers["Mcp-Session-Id"] = sessionId;
    }
    const res = await fetch(`${baseUrl}${urlPath}`, {
      method,
      headers,
      body: method === "POST" ? JSON.stringify(payload) : undefined,
    });
    const text = await res.text();
    return {
      status: res.status,
      headers: res.headers,
      json: text ? JSON.parse(text) : null,
    };
  };

  // 1. Wrong path key -> 403 and MUST NOT include WWW-Authenticate
  const invalidKeyRes = await mcpPathCall("/mcp/u/gbk_invalid_key_000000", null, {
    jsonrpc: "2.0",
    id: 200,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "bad-key-client", version: "1.0" },
    },
  });
  assert.equal(invalidKeyRes.status, 403);
  assert.equal(invalidKeyRes.headers.get("www-authenticate"), null);

  // 2. Per-Key OAuth Discovery + Zero-Prompt 302 Auto-Approval Handshake
  // Invalid key on well-known / scoped oauth must be rejected
  const badWellKnownRes = await fetch(
    `${baseUrl}/.well-known/oauth-protected-resource/mcp/u/gbk_invalid_key_000000`
  );
  assert.equal(badWellKnownRes.status, 404);
  await badWellKnownRes.text();

  const badScopedAuthRes = await fetch(
    `${baseUrl}/u/gbk_invalid_key_000000/oauth/authorize?response_type=code&client_id=none`
  );
  assert.equal(badScopedAuthRes.status, 403);
  await badScopedAuthRes.text();

  // Valid key RFC 9728 Protected Resource Metadata -> 200 pointing to /u/<key>
  const prmKeyRes = await fetch(
    `${baseUrl}/.well-known/oauth-protected-resource/mcp/u/gbk_test_key_acc1_abcdef`
  );
  assert.equal(prmKeyRes.status, 200);
  const prmKeyJson = await prmKeyRes.json();
  assert.equal(prmKeyJson.resource, `${baseUrl}/mcp/u/gbk_test_key_acc1_abcdef`);
  assert.deepEqual(prmKeyJson.authorization_servers, [`${baseUrl}/u/gbk_test_key_acc1_abcdef`]);

  // Valid key RFC 8414 & path-appended Authorization Server Metadata -> 200
  for (const metaPath of [
    "/.well-known/oauth-authorization-server/u/gbk_test_key_acc1_abcdef",
    "/u/gbk_test_key_acc1_abcdef/.well-known/oauth-authorization-server",
    "/u/gbk_test_key_acc1_abcdef/.well-known/openid-configuration",
  ]) {
    const asRes = await fetch(`${baseUrl}${metaPath}`);
    assert.equal(asRes.status, 200);
    const asJson = await asRes.json();
    assert.equal(asJson.issuer, `${baseUrl}/u/gbk_test_key_acc1_abcdef`);
    assert.equal(asJson.authorization_endpoint, `${baseUrl}/u/gbk_test_key_acc1_abcdef/oauth/authorize`);
    assert.equal(asJson.token_endpoint, `${baseUrl}/u/gbk_test_key_acc1_abcdef/oauth/token`);
    assert.equal(asJson.registration_endpoint, `${baseUrl}/u/gbk_test_key_acc1_abcdef/oauth/register`);
  }

  // Simulate Google Gemini Connected Apps DCR (6 googleusercontent redirect URIs)
  const googleRedirectUris = [
    "https://oauth-redirect-sandbox.googleusercontent.com/r/user_bound_custom-mcp-test",
    "https://oauth-redirect-test.googleusercontent.com/r/user_bound_custom-mcp-test",
    "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-test",
    "https://oauth-redirect-sandbox.googleusercontent.com/a/user_bound_custom-mcp-test",
    "https://oauth-redirect-test.googleusercontent.com/a/user_bound_custom-mcp-test",
    "https://oauth-redirect.googleusercontent.com/a/user_bound_custom-mcp-test",
  ];
  const regKeyClientRes = await fetch(`${baseUrl}/u/gbk_test_key_acc1_abcdef/oauth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Google",
      redirect_uris: googleRedirectUris,
      token_endpoint_auth_method: "client_secret_post",
    }),
  });
  assert.equal(regKeyClientRes.status, 201);
  const googleStyleClient = await regKeyClientRes.json();

  // Scoped authorize MUST directly 302 redirect without rendering any passphrase HTML form
  const keyVerifier = "verifier_key_acc1_123456789012345678901234567890";
  const keyChallenge = sha256Base64Url(keyVerifier);
  const longKeyState = "k".repeat(2048);
  const keyAuthUrl = new URL(`${baseUrl}/u/gbk_test_key_acc1_abcdef/oauth/authorize`);
  keyAuthUrl.searchParams.set("response_type", "code");
  keyAuthUrl.searchParams.set("client_id", googleStyleClient.client_id);
  keyAuthUrl.searchParams.set("redirect_uri", googleRedirectUris[2]);
  keyAuthUrl.searchParams.set("state", longKeyState);
  keyAuthUrl.searchParams.set("code_challenge", keyChallenge);
  keyAuthUrl.searchParams.set("code_challenge_method", "S256");
  keyAuthUrl.searchParams.set("scope", "mcp:tools");

  const keyAuthRes = await fetch(keyAuthUrl, { redirect: "manual" });
  assert.equal(keyAuthRes.status, 302);
  await keyAuthRes.text();
  const keyAuthLoc = new URL(keyAuthRes.headers.get("location"));
  assert.equal(keyAuthLoc.searchParams.get("state"), longKeyState);
  const keyAuthCode = keyAuthLoc.searchParams.get("code");
  assert.ok(keyAuthCode, "Expected auto-approved authorization code in 302 Location");

  const keyTokenRes = await fetch(`${baseUrl}/u/gbk_test_key_acc1_abcdef/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "authorization_code",
      code: keyAuthCode,
      client_id: googleStyleClient.client_id,
      client_secret: googleStyleClient.client_secret,
      redirect_uri: googleRedirectUris[2],
      code_verifier: keyVerifier,
    }),
  });
  assert.equal(keyTokenRes.status, 200);
  const keyTokenJson = await keyTokenRes.json();
  assert.equal(keyTokenJson.account_id, "acc1");

  // Use Bearer token from auto-key OAuth on /mcp/u/<key1>
  const bearerKeyMcpRes = await fetch(`${baseUrl}/mcp/u/gbk_test_key_acc1_abcdef`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${keyTokenJson.access_token}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      "MCP-Protocol-Version": "2025-11-25",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 210,
      method: "tools/call",
      params: { name: "get_workspace_status", arguments: {} },
    }),
  });
  assert.equal(bearerKeyMcpRes.status, 200);
  const bearerKeyMcpJson = await bearerKeyMcpRes.json();
  const bearerStatus = JSON.parse(bearerKeyMcpJson.result.content[0].text);
  assert.equal(bearerStatus.current_account, "acc1");

  // Root /oauth/authorize with `resource` pointing to /mcp/u/<acc2_key> also auto-approves as acc2
  const acc2Verifier = "verifier_key_acc2_123456789012345678901234567890";
  const rootResourceAuthUrl = new URL(`${baseUrl}/oauth/authorize`);
  rootResourceAuthUrl.searchParams.set("response_type", "code");
  rootResourceAuthUrl.searchParams.set("client_id", googleStyleClient.client_id);
  rootResourceAuthUrl.searchParams.set("redirect_uri", googleRedirectUris[2]);
  rootResourceAuthUrl.searchParams.set("state", "acc2_resource_state");
  rootResourceAuthUrl.searchParams.set("code_challenge", sha256Base64Url(acc2Verifier));
  rootResourceAuthUrl.searchParams.set("code_challenge_method", "S256");
  rootResourceAuthUrl.searchParams.set("scope", "mcp:tools");
  rootResourceAuthUrl.searchParams.set("resource", `${baseUrl}/mcp/u/gbk_test_key_acc2_ghijkl`);

  const rootResAuthRes = await fetch(rootResourceAuthUrl, { redirect: "manual" });
  assert.equal(rootResAuthRes.status, 302);
  await rootResAuthRes.text();
  const acc2Code = new URL(rootResAuthRes.headers.get("location")).searchParams.get("code");
  const acc2TokenRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "authorization_code",
      code: acc2Code,
      client_id: googleStyleClient.client_id,
      client_secret: googleStyleClient.client_secret,
      redirect_uri: googleRedirectUris[2],
      code_verifier: acc2Verifier,
    }),
  });
  assert.equal(acc2TokenRes.status, 200);
  const acc2TokenJson = await acc2TokenRes.json();
  assert.equal(acc2TokenJson.account_id, "acc2");

  // 3. Account 1 initialize + get_workspace_status without Authorization header
  const initAcc1 = await mcpPathCall("/mcp/u/gbk_test_key_acc1_abcdef", null, {
    jsonrpc: "2.0",
    id: 201,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "Gemini Account 1", version: "1.0" },
    },
  });
  assert.equal(initAcc1.status, 200);
  const acc1SessionId = initAcc1.headers.get("mcp-session-id");
  assert.ok(acc1SessionId, "Expected Mcp-Session-Id for path-key initialize");

  const statusAcc1Res = await mcpPathCall("/mcp/u/gbk_test_key_acc1_abcdef", acc1SessionId, {
    jsonrpc: "2.0",
    id: 202,
    method: "tools/call",
    params: { name: "get_workspace_status", arguments: {} },
  });
  assert.equal(statusAcc1Res.status, 200);
  const statusAcc1 = JSON.parse(statusAcc1Res.json.result.content[0].text);
  assert.equal(statusAcc1.current_account, "acc1");
  assert.equal(statusAcc1.configured_accounts, undefined);
  assert.equal(statusAcc1.sessions?.sessions, undefined);

  // 4. Account 2 (with trailing slash) + Account 3
  const statusAcc2Res = await mcpPathCall("/mcp/u/gbk_test_key_acc2_ghijkl/", null, {
    jsonrpc: "2.0",
    id: 203,
    method: "tools/call",
    params: { name: "get_workspace_status", arguments: {} },
  });
  assert.equal(statusAcc2Res.status, 200);
  const statusAcc2 = JSON.parse(statusAcc2Res.json.result.content[0].text);
  assert.equal(statusAcc2.current_account, "acc2");

  const statusAcc3Res = await mcpPathCall("/mcp/u/gbk_test_key_acc3_mnopqr", null, {
    jsonrpc: "2.0",
    id: 204,
    method: "tools/call",
    params: { name: "get_workspace_status", arguments: {} },
  });
  assert.equal(statusAcc3Res.status, 200);
  const statusAcc3 = JSON.parse(statusAcc3Res.json.result.content[0].text);
  assert.equal(statusAcc3.current_account, "acc3");

  // 5. Propose task from acc1 and acc2 via secret path URLs and verify account tagging + filtering
  const propAcc1Res = await mcpPathCall("/mcp/u/gbk_test_key_acc1_abcdef", acc1SessionId, {
    jsonrpc: "2.0",
    id: 205,
    method: "tools/call",
    params: {
      name: "propose_task",
      arguments: {
        title: "Path Key Proposal Acc1",
        summary: "Proposed from secret path URL acc1.",
        plan_markdown: "# Acc1 Plan\nStep 1.\n",
      },
    },
  });
  const propAcc1 = JSON.parse(propAcc1Res.json.result.content[0].text);
  assert.equal(propAcc1.account, "acc1");
  assert.ok(propAcc1.tags.includes("account:acc1"));

  const propAcc2Res = await mcpPathCall("/mcp/u/gbk_test_key_acc2_ghijkl", null, {
    jsonrpc: "2.0",
    id: 206,
    method: "tools/call",
    params: {
      name: "propose_task",
      arguments: {
        title: "Path Key Proposal Acc2",
        summary: "Proposed from secret path URL acc2.",
        plan_markdown: "# Acc2 Plan\nStep 1.\n",
      },
    },
  });
  const propAcc2 = JSON.parse(propAcc2Res.json.result.content[0].text);
  assert.equal(propAcc2.account, "acc2");

  const listAcc1Res = await mcpPathCall("/mcp/u/gbk_test_key_acc1_abcdef", acc1SessionId, {
    jsonrpc: "2.0",
    id: 207,
    method: "tools/call",
    params: {
      name: "list_tasks",
      arguments: { status: "proposed", account: "acc1" },
    },
  });
  const listAcc1 = JSON.parse(listAcc1Res.json.result.content[0].text);
  assert.ok(listAcc1.tasks.some((t) => t.id === propAcc1.id));
  assert.ok(!listAcc1.tasks.some((t) => t.id === propAcc2.id));

  // 6. DELETE session on secret path URL with owning sessionId returns 204
  const delAcc1Res = await mcpPathCall(
    "/mcp/u/gbk_test_key_acc1_abcdef",
    acc1SessionId,
    null,
    "DELETE"
  );
  assert.equal(delAcc1Res.status, 204);
});

test("P0/P1 security hardening: tenant isolation, annotations, state machine, Origin 403, ADMIN_PORT, and snapshots", async (t) => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "gemini-bridge-p0-"));
  const dataDir = path.join(tmpDir, "data");
  const adminToken = "p0-admin-token-secret";
  const mcpAccountKeys = "acc1:gbk_p0_acc1_11111111,acc2:gbk_p0_acc2_22222222";

  const { server, adminServer, audit, snapshots } = createBridgeServer({
    skipDotEnv: true,
    host: "127.0.0.1",
    port: 0,
    adminHost: "127.0.0.1",
    adminPort: 0,
    dataDir,
    ownerPassphrase: "p0-owner-passphrase",
    mcpAccountKeys,
    adminToken,
    tenantIsolation: true,
    allowedOrigins: ["https://gemini.google.com"],
    sessionTtlMs: 60_000,
    zeroCallSessionTtlMs: 30_000,
    maxSessions: 16,
  });

  assert.ok(audit, "Expected AuditLogger to be wired into createBridgeServer");
  assert.ok(snapshots, "Expected SnapshotStore to be wired into createBridgeServer");

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  await new Promise((resolve) => adminServer.listen(0, "127.0.0.1", resolve));
  const mcpBase = `http://127.0.0.1:${server.address().port}`;
  const adminBase = `http://127.0.0.1:${adminServer.address().port}`;

  t.after(async () => {
    await new Promise((resolve) => adminServer.close(resolve));
    await new Promise((resolve) => server.close(resolve));
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  const callPath = async (key, sessionId, payload, extraHeaders = {}) => {
    const res = await fetch(`${mcpBase}/mcp/u/${key}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "MCP-Protocol-Version": "2025-11-25",
        ...(sessionId ? { "Mcp-Session-Id": sessionId } : {}),
        ...extraHeaders,
      },
      body: JSON.stringify(payload),
    });
    const text = await res.text();
    return { status: res.status, headers: res.headers, json: text ? JSON.parse(text) : null };
  };

  // 1. P1 Origin 403 check (DNS rebinding defense)
  const evilOriginRes = await callPath(
    "gbk_p0_acc1_11111111",
    null,
    { jsonrpc: "2.0", id: 1, method: "ping" },
    { Origin: "https://evil-attacker.example" }
  );
  assert.equal(evilOriginRes.status, 403);
  assert.equal(evilOriginRes.headers.get("access-control-allow-origin"), null);

  const okOriginRes = await callPath(
    "gbk_p0_acc1_11111111",
    null,
    { jsonrpc: "2.0", id: 2, method: "ping" },
    { Origin: "https://gemini.google.com" }
  );
  assert.equal(okOriginRes.status, 200);
  assert.equal(okOriginRes.headers.get("access-control-allow-origin"), "https://gemini.google.com");

  const optsOkRes = await fetch(`${mcpBase}/mcp`, {
    method: "OPTIONS",
    headers: { Origin: "https://gemini.google.com" },
  });
  assert.equal(optsOkRes.status, 204);
  assert.equal(optsOkRes.headers.get("access-control-allow-origin"), "https://gemini.google.com");
  await optsOkRes.text();

  const optsEvilRes = await fetch(`${mcpBase}/mcp`, {
    method: "OPTIONS",
    headers: { Origin: "https://evil-attacker.example" },
  });
  assert.equal(optsEvilRes.status, 403);
  await optsEvilRes.text();

  // 2. P1 ADMIN_PORT split-port isolation
  const pubAdminAttempt = await fetch(`${mcpBase}/api/tasks`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert.equal(pubAdminAttempt.status, 403);
  await pubAdminAttempt.text();

  const pubHealthRes = await fetch(`${mcpBase}/api/health`);
  assert.equal(pubHealthRes.status, 200);
  const pubHealth = await pubHealthRes.json();

  const privAdminTasks = await fetch(`${adminBase}/api/tasks`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert.equal(privAdminTasks.status, 200);
  await privAdminTasks.text();

  // Bad account query param returns HTTP 400 (never 500)
  const badSyncAccountRes = await fetch(`${adminBase}/api/sync/files/test.md?account=../evil`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${adminToken}` },
    body: "test",
  });
  assert.equal(badSyncAccountRes.status, 400);
  await badSyncAccountRes.text();

  // 3. P0-2 Tool annotations audit & strict version equality across package.json and all endpoints
  const pkgJson = JSON.parse(await fs.readFile(path.join(PROJECT_ROOT, "package.json"), "utf8"));
  const rootInfo = await (await fetch(`${mcpBase}/`)).json();
  assert.equal(rootInfo.name, "gemini-handoff-mcp");
  assert.equal(rootInfo.icon, "/assets/logo.svg");
  assert.equal(rootInfo.version, pkgJson.version);
  assert.equal(pubHealth.version, pkgJson.version);

  const initVersionRes = await callPath("gbk_p0_acc1_11111111", null, {
    jsonrpc: "2.0",
    id: 300,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "Version Audit Client", version: "1.0" },
    },
  });
  assert.equal(initVersionRes.json.result.serverInfo.version, pkgJson.version);
  assert.match(initVersionRes.json.result.instructions, new RegExp(`v${pkgJson.version}`));

  const toolsRes = await callPath("gbk_p0_acc1_11111111", null, {
    jsonrpc: "2.0",
    id: 3,
    method: "tools/list",
  });
  const byName = new Map(toolsRes.json.result.tools.map((tool) => [tool.name, tool]));
  const readOnlyTools = [
    "list_tasks",
    "get_task",
    "list_files",
    "read_file",
    "search_notes",
    "read_note",
    "list_repo_tree",
    "read_repo_file",
    "search_repo_code",
    "get_workspace_status",
    "list_notes",
    "search_files",
    "list_file_snapshots",
  ];
  for (const name of readOnlyTools) {
    const ann = byName.get(name).annotations;
    assert.equal(ann.readOnlyHint, true, `${name} readOnlyHint`);
    assert.equal(ann.destructiveHint, false, `${name} destructiveHint`);
    assert.equal(ann.idempotentHint, true, `${name} idempotentHint`);
    assert.equal(ann.openWorldHint, false, `${name} openWorldHint`);
  }
  assert.equal(byName.get("edit_file").annotations.destructiveHint, true);
  assert.equal(byName.get("restore_file_snapshot").annotations.destructiveHint, true);
  assert.equal(byName.get("propose_task").annotations.destructiveHint, false);
  assert.ok(byName.get("list_tasks").inputSchema.properties.status.enum.includes("proposed"));

  // 4. P0-1 Hard tenant isolation (tasks + files + snapshots) & P0-3 state machine
  const propAcc1 = JSON.parse(
    (
      await callPath("gbk_p0_acc1_11111111", null, {
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: {
          name: "propose_task",
          arguments: { title: "Acc1 Secret Plan", summary: "Private", plan_markdown: "# Secret\n" },
        },
      })
    ).json.result.content[0].text
  );

  // Verify P0-3: proposed task has progress_percent=0, completed_at=null, non-null sha256
  const adminTaskView = await (
    await fetch(`${adminBase}/api/tasks/${propAcc1.id}`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    })
  ).json();
  assert.equal(adminTaskView.task.progress_percent, 0);
  assert.equal(adminTaskView.task.completed_at, null);
  assert.ok(adminTaskView.task.result_sha256);

  // Verify P0-3 & P0-2c: acc1 status counts proposed=1, version=1.0.0, redacts accounts/sessions
  const acc1Status = JSON.parse(
    (
      await callPath("gbk_p0_acc1_11111111", null, {
        jsonrpc: "2.0",
        id: 5,
        method: "tools/call",
        params: { name: "get_workspace_status", arguments: {} },
      })
    ).json.result.content[0].text
  );
  assert.equal(acc1Status.harness_version, "1.0.0");
  assert.equal(acc1Status.queue.counts.proposed, 1);
  assert.equal(acc1Status.queue.counts.total, 1);
  assert.equal(acc1Status.configured_accounts, undefined);
  assert.equal(acc1Status.sessions?.sessions, undefined);

  // acc2 cannot list, get, claim, checkpoint, or submit acc1's task
  const acc2CrossList = (
    await callPath("gbk_p0_acc2_22222222", null, {
      jsonrpc: "2.0",
      id: 6,
      method: "tools/call",
      params: { name: "list_tasks", arguments: { status: "all", account: "acc1" } },
    })
  ).json.result;
  assert.equal(acc2CrossList.isError, true);

  const acc2DefaultList = JSON.parse(
    (
      await callPath("gbk_p0_acc2_22222222", null, {
        jsonrpc: "2.0",
        id: 7,
        method: "tools/call",
        params: { name: "list_tasks", arguments: { status: "all" } },
      })
    ).json.result.content[0].text
  );
  assert.equal(acc2DefaultList.count, 0);

  for (const [reqId, toolName, toolArgs] of [
    [8, "get_task", { task_id: propAcc1.id }],
    [9, "claim_task", { task_id: propAcc1.id }],
    [10, "checkpoint_task", { task_id: propAcc1.id, progress_note: "hijack" }],
    [11, "submit_task_result", { task_id: propAcc1.id, summary: "x", content: "y" }],
  ]) {
    const crossRes = (
      await callPath("gbk_p0_acc2_22222222", null, {
        jsonrpc: "2.0",
        id: reqId,
        method: "tools/call",
        params: { name: toolName, arguments: toolArgs },
      })
    ).json.result;
    assert.equal(crossRes.isError, true, `acc2 must not ${toolName} acc1 task`);
  }

  // acc1 writes & edits private.md -> creates snapshot -> acc2 cannot read file, list snapshots, or restore
  await callPath("gbk_p0_acc1_11111111", null, {
    jsonrpc: "2.0",
    id: 12,
    method: "tools/call",
    params: { name: "write_file", arguments: { path: "private.md", content: "ACC1_V1\n" } },
  });
  const acc1Edit = JSON.parse(
    (
      await callPath("gbk_p0_acc1_11111111", null, {
        jsonrpc: "2.0",
        id: 13,
        method: "tools/call",
        params: {
          name: "edit_file",
          arguments: { path: "private.md", old_text: "ACC1_V1", new_text: "ACC1_V2" },
        },
      })
    ).json.result.content[0].text
  );
  assert.ok(acc1Edit.backup_id, "Expected SnapshotStore to capture backup_id when wired via server.mjs");

  const acc2ReadAcc1File = (
    await callPath("gbk_p0_acc2_22222222", null, {
      jsonrpc: "2.0",
      id: 14,
      method: "tools/call",
      params: { name: "read_file", arguments: { path: "private.md" } },
    })
  ).json.result;
  assert.equal(acc2ReadAcc1File.isError, true);

  const acc2ListSnaps = JSON.parse(
    (
      await callPath("gbk_p0_acc2_22222222", null, {
        jsonrpc: "2.0",
        id: 15,
        method: "tools/call",
        params: { name: "list_file_snapshots", arguments: {} },
      })
    ).json.result.content[0].text
  );
  assert.equal(acc2ListSnaps.count, 0);

  const acc2RestoreSnap = (
    await callPath("gbk_p0_acc2_22222222", null, {
      jsonrpc: "2.0",
      id: 16,
      method: "tools/call",
      params: { name: "restore_file_snapshot", arguments: { snapshot_id: acc1Edit.backup_id } },
    })
  ).json.result;
  assert.equal(acc2RestoreSnap.isError, true);

  // CLI push-file & pull-file with --account acc2 targeting adminBase (via primary handoff-cli.mjs entrypoint)
  const cliPath = path.join(PROJECT_ROOT, "cli", "handoff-cli.mjs");
  const cliP0Env = { ...process.env, BRIDGE_URL: adminBase, ADMIN_TOKEN: adminToken, DATA_DIR: dataDir };
  const acc2UploadSrc = path.join(tmpDir, "acc2-brief.md");
  await fs.writeFile(acc2UploadSrc, "# Acc2 Only Brief\n", "utf8");
  await execFileAsync(
    process.execPath,
    [cliPath, "push-file", acc2UploadSrc, "brief.md", "--account", "acc2"],
    { env: cliP0Env }
  );
  const acc2ReadOwnFile = (
    await callPath("gbk_p0_acc2_22222222", null, {
      jsonrpc: "2.0",
      id: 17,
      method: "tools/call",
      params: { name: "read_file", arguments: { path: "brief.md" } },
    })
  ).json.result;
  assert.notEqual(acc2ReadOwnFile.isError, true);
  assert.match(acc2ReadOwnFile.content[0].text, /Acc2 Only Brief/);

  const acc1ReadAcc2File = (
    await callPath("gbk_p0_acc1_11111111", null, {
      jsonrpc: "2.0",
      id: 18,
      method: "tools/call",
      params: { name: "read_file", arguments: { path: "brief.md" } },
    })
  ).json.result;
  assert.equal(acc1ReadAcc2File.isError, true);

  // CLI pull-file --account acc2
  const pulledAcc2Path = path.join(tmpDir, "pulled-acc2-brief.md");
  await execFileAsync(
    process.execPath,
    [cliPath, "pull-file", "brief.md", pulledAcc2Path, "--account", "acc2"],
    { env: cliP0Env }
  );
  assert.match(await fs.readFile(pulledAcc2Path, "utf8"), /Acc2 Only Brief/);

  // 5. MCP resources/read tenant isolation & redaction
  const resStatusAcc2 = JSON.parse(
    (
      await callPath("gbk_p0_acc2_22222222", null, {
        jsonrpc: "2.0",
        id: 19,
        method: "resources/read",
        params: { uri: "bridge://harness/status" },
      })
    ).json.result.contents[0].text
  );
  assert.equal(resStatusAcc2.configured_accounts, undefined);
  assert.equal(resStatusAcc2.sessions?.sessions, undefined);
  assert.equal(resStatusAcc2.queue.counts.total, 0);

  const resQueueAcc2 = JSON.parse(
    (
      await callPath("gbk_p0_acc2_22222222", null, {
        jsonrpc: "2.0",
        id: 20,
        method: "resources/read",
        params: { uri: "bridge://tasks/queue" },
      })
    ).json.result.contents[0].text
  );
  assert.equal(resQueueAcc2.counts.total, 0);

  // 6. loadTaskContract cross-account denial on write_file & edit_file
  await callPath("gbk_p0_acc2_22222222", null, {
    jsonrpc: "2.0",
    id: 21,
    method: "tools/call",
    params: { name: "write_file", arguments: { path: "own.md", content: "v1\n" } },
  });
  const acc2ContractWrite = (
    await callPath("gbk_p0_acc2_22222222", null, {
      jsonrpc: "2.0",
      id: 22,
      method: "tools/call",
      params: { name: "write_file", arguments: { path: "own2.md", content: "x", task_id: propAcc1.id } },
    })
  ).json.result;
  assert.equal(acc2ContractWrite.isError, true);

  const acc2ContractEdit = (
    await callPath("gbk_p0_acc2_22222222", null, {
      jsonrpc: "2.0",
      id: 23,
      method: "tools/call",
      params: {
        name: "edit_file",
        arguments: { path: "own.md", old_text: "v1", new_text: "v2", task_id: propAcc1.id },
      },
    })
  ).json.result;
  assert.equal(acc2ContractEdit.isError, true);
});

test("OAuth tunnel same-origin without PUBLIC_BASE_URL, SnapshotStore per-account pruning, and Session TTL/LRU", async (t) => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "gemini-bridge-lru-"));
  const dataDir = path.join(tmpDir, "data");
  const adminToken = "lru-admin-token-secret";
  const mcpAccountKeys = "acc1:gbk_lru_acc1_11111111,acc2:gbk_lru_acc2_22222222";

  const baseCfg = loadConfig({
    skipDotEnv: true,
    host: "127.0.0.1",
    port: 0,
    dataDir,
    ownerPassphrase: "lru-owner-passphrase",
    mcpAccountKeys,
    adminToken,
    snapshotRetention: 2,
  });
  const { server } = createBridgeServer({
    ...baseCfg,
    zeroCallSessionTtlMs: 40,
    sessionTtlMs: 2000,
    maxSessions: 2,
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  const callMcp = async (headers, payload) => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "MCP-Protocol-Version": "2025-11-25",
        ...headers,
      },
      body: JSON.stringify(payload),
    });
    const text = await res.text();
    return { status: res.status, headers: res.headers, json: text ? JSON.parse(text) : null };
  };

  // 1. OAuth same-origin POST /oauth/authorize via forwarded tunnel host without PUBLIC_BASE_URL
  const regRes = await fetch(`${baseUrl}/oauth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Tunnel Client",
      redirect_uris: ["https://example.com/cb"],
      token_endpoint_auth_method: "client_secret_post",
    }),
  });
  const regClient = await regRes.json();
  const authUrl = new URL(`${baseUrl}/oauth/authorize`);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", regClient.client_id);
  authUrl.searchParams.set("redirect_uri", "https://example.com/cb");
  authUrl.searchParams.set("state", "st123");
  authUrl.searchParams.set("code_challenge", sha256Base64Url("v".repeat(45)));
  authUrl.searchParams.set("code_challenge_method", "S256");

  const fwdHeaders = {
    "X-Forwarded-Proto": "https",
    "X-Forwarded-Host": "my-tunnel.example.com",
  };
  const consentHtml = await (await fetch(authUrl, { headers: fwdHeaders })).text();
  assert.match(consentHtml, /<link rel="icon"[^>]*href="\/assets\/logo\.svg"/);
  assert.match(consentHtml, /<img src="\/assets\/logo\.svg"/);
  const csrfToken = extractHiddenInput(consentHtml, "csrf_token");

  const sameOriginAuthPost = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    headers: {
      ...fwdHeaders,
      Origin: "https://my-tunnel.example.com",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      csrf_token: csrfToken,
      response_type: "code",
      client_id: regClient.client_id,
      redirect_uri: "https://example.com/cb",
      state: "st123",
      code_challenge: sha256Base64Url("v".repeat(45)),
      code_challenge_method: "S256",
      scope: "mcp:tools",
      resource: "",
      passphrase: "lru-owner-passphrase",
    }).toString(),
    redirect: "manual",
  });
  assert.equal(sameOriginAuthPost.status, 302);
  await sameOriginAuthPost.text();

  // Unknown Origin on /mcp must STILL return 403 (DNS rebinding defense unchanged)
  const tunnelMcpAttempt = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: { ...fwdHeaders, Origin: "https://my-tunnel.example.com", "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
  });
  assert.equal(tunnelMcpAttempt.status, 403);
  await tunnelMcpAttempt.text();

  // 2. SnapshotStore independent pruning per account (retention=2)
  const pathCall = async (key, payload) =>
    fetch(`${baseUrl}/mcp/u/${key}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json", "MCP-Protocol-Version": "2025-11-25" },
      body: JSON.stringify(payload),
    }).then((r) => r.json());

  await pathCall("gbk_lru_acc2_22222222", {
    jsonrpc: "2.0", id: 1, method: "tools/call",
    params: { name: "write_file", arguments: { path: "same.md", content: "acc2-v1" } },
  });
  await pathCall("gbk_lru_acc2_22222222", {
    jsonrpc: "2.0", id: 2, method: "tools/call",
    params: { name: "write_file", arguments: { path: "same.md", content: "acc2-v2" } },
  });
  for (let i = 1; i <= 4; i += 1) {
    await pathCall("gbk_lru_acc1_11111111", {
      jsonrpc: "2.0", id: 10 + i, method: "tools/call",
      params: { name: "write_file", arguments: { path: "same.md", content: `acc1-v${i}` } },
    });
  }
  const acc2SnapsAfterAcc1Prune = JSON.parse(
    (
      await pathCall("gbk_lru_acc2_22222222", {
        jsonrpc: "2.0", id: 20, method: "tools/call",
        params: { name: "list_file_snapshots", arguments: { path: "same.md" } },
      })
    ).result.content[0].text
  );
  assert.equal(acc2SnapsAfterAcc1Prune.count, 1, "acc1 pruning must not delete acc2 snapshot");

  // 3. Zero-call short TTL (40ms) and true O(1) LRU eviction (maxSessions=2)
  const adminHdr = { Authorization: `Bearer ${adminToken}` };
  const sZero = await callMcp(adminHdr, {
    jsonrpc: "2.0", id: 100, method: "initialize",
    params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "zero-call", version: "1.0" } },
  });
  const sZeroId = sZero.headers.get("mcp-session-id");
  await new Promise((r) => setTimeout(r, 80));

  const s1 = await callMcp(adminHdr, {
    jsonrpc: "2.0", id: 101, method: "initialize",
    params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "s1", version: "1.0" } },
  });
  const s1Id = s1.headers.get("mcp-session-id");
  // Touch s1 with a tool call so toolCalls > 0 and sZero gets pruned on request
  const adminCheckAfterZero = JSON.parse(
    (
      await callMcp({ ...adminHdr, "Mcp-Session-Id": s1Id }, {
        jsonrpc: "2.0", id: 102, method: "tools/call",
        params: { name: "get_workspace_status", arguments: {} },
      })
    ).json.result.content[0].text
  );
  assert.equal(
    adminCheckAfterZero.sessions.sessions.some((s) => s.session_id === sZeroId),
    false,
    "Zero-call session must expire after zeroCallSessionTtlMs"
  );

  // Create S2 (making tool call so it uses 2000ms active TTL)
  const s2 = await callMcp(adminHdr, {
    jsonrpc: "2.0", id: 103, method: "initialize",
    params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "s2", version: "1.0" } },
  });
  const s2Id = s2.headers.get("mcp-session-id");
  await callMcp({ ...adminHdr, "Mcp-Session-Id": s2Id }, {
    jsonrpc: "2.0", id: 104, method: "tools/call",
    params: { name: "get_workspace_status", arguments: {} },
  });

  // Touch S1 again to promote S1 to MRU tail, then initialize S3 -> S2 (LRU) must be evicted
  await callMcp({ ...adminHdr, "Mcp-Session-Id": s1Id }, { jsonrpc: "2.0", id: 105, method: "ping" });
  const s3 = await callMcp(adminHdr, {
    jsonrpc: "2.0", id: 106, method: "initialize",
    params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "s3", version: "1.0" } },
  });
  const s3Id = s3.headers.get("mcp-session-id");
  const finalSessions = JSON.parse(
    (
      await callMcp({ ...adminHdr, "Mcp-Session-Id": s3Id }, {
        jsonrpc: "2.0", id: 107, method: "tools/call",
        params: { name: "get_workspace_status", arguments: {} },
      })
    ).json.result.content[0].text
  ).sessions.sessions.map((s) => s.session_id);

  assert.equal(finalSessions.includes(s1Id), true, "MRU session s1 must be retained");
  assert.equal(finalSessions.includes(s2Id), false, "LRU session s2 must be evicted");
  assert.equal(finalSessions.includes(s3Id), true, "New session s3 must be retained");
});
