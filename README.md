<p align="center">
  <img src="./assets/logo.svg" alt="Gemini Handoff MCP Logo" width="128" height="128" />
</p>

<h1 align="center">Gemini Handoff MCP</h1>

<p align="center">
  <strong>Turn Google Gemini APP (web &amp; mobile) into a planning brain for your local codebase — safely read code, keep auto-snapshots on writes, and hand tasks back and forth with local coding agents.</strong><br/>
  Zero-dependency MCP server &amp; CLI built first for <strong>Google Gemini APP</strong> (standard MCP/OAuth 2.1, potentially compatible with Claude.ai / ChatGPT custom connectors — untested).
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Node.js-%3E%3D22.0.0-339933?logo=node.js&logoColor=white" alt="Node.js >= 22" />
  <img src="https://img.shields.io/badge/Dependencies-Zero-4285F4" alt="Zero Dependencies" />
  <img src="https://img.shields.io/badge/Protocol-MCP%20Streamable%20HTTP-EA4335" alt="MCP Streamable HTTP" />
  <img src="https://img.shields.io/badge/License-MIT-34A853" alt="MIT License" />
</p>

<p align="center">
  <strong>English</strong> | <a href="./README.zh-CN.md">简体中文</a>
</p>

---

## What is this? Why build it?

People using **Google Gemini APP** (Deep Research, Pro reasoning, mobile voice) hit an obvious gap: Gemini in the browser or on your phone cannot see your local code or notes, while local coding agents (Antigravity, Claude Code, Codex, Cursor) can edit files and run tests but can't pick up ideas and research straight from your Gemini APP sessions.

**Gemini Handoff MCP** bridges both sides with 4 priorities:
1. **Zero dependencies, zero setup bloat**: Pure Node.js >= 22. No `npm install`, runs in two commands.
2. **Read-only code safety + auto-snapshots on writes**: Mounted repositories and notes are strictly read-only with `.env`, private keys, and `node_modules` automatically blocked. Workspace edits enforce `sha256` conflict checks (`dry_run` supported) and save pre-write snapshots so mistakes roll back cleanly.
3. **Two-way async task handoff (mobile ↔ desktop)**: Dispatch scoped research tasks from your terminal to Gemini APP, or brainstorm on your phone and call `propose_task` so your local coding agent can `pull` the work item when you're back at your desk.
4. **100% official Custom Apps protocol (zero browser scripts)**: Uses Google's official MCP Streamable HTTP & OAuth 2.1 spec (theoretically compatible with Claude.ai / ChatGPT custom connectors, **untested on those two clients**). No DOM injection, no cookie scraping — works on both mobile and web without account-ban risk.

### How is this different from alternatives?

| Approach | Examples | Limitation | Where Gemini Handoff MCP fits |
| :--- | :--- | :--- | :--- |
| **Local CLI calling Gemini** | `pal-mcp-server`, `gemini-mcp-tool` | Works from desktop terminals only; **unusable from mobile Gemini APP** | Reversed flow: puts Gemini APP (mobile/web) in the driver's seat |
| **Browser extensions / cookie scrapers** | `MCP-SuperAssistant`, `Gemini-API` | Desktop-only, breaks when Google changes DOM, cookie scraping risks bans | **Official Custom Apps protocol** (standard-compatible, untested on other clients), mobile-ready, zero DOM hacks |
| **All-in-one desktop control bags** | `gemini-antigravity-bridge` | Bundles dozens of unrelated desktop/camera/UI tools with weak guardrails | **Focused 20-tool surface**: read-only mounts, `sha256` edit checks, auto-rollback snapshots |
| **Generic remote filesystem MCP** | Filesystem MCP + proxy | File I/O only; no task queue, mobile proposals, or agent handoff workflow | Built specifically for **safe async task handoff** with a CLI, Agent Skill, and boundary protection |

> **Why is a public HTTPS URL required?**  
> Google Gemini APP runs on Google's servers and cannot reach `127.0.0.1` on your laptop directly. Exposing your local port through a tunnel (`cloudflared` or `tailscale funnel`) keeps **100% of your files on your own machine — no cloud VPS needed.**

---

## 1. Run Locally in 3 Minutes (No Cloud Server Needed)

> Requirement: **Node.js >= 22.0.0** (zero third-party dependencies — skip `npm install`).

### Step 1: Start the local server

```bash
git clone https://github.com/Sansi-06/gemini-handoff-mcp.git
cd gemini-handoff-mcp

# Optional: register `gemini-handoff` globally (or run `node cli/handoff-cli.mjs`)
npm link

# Generate .env secrets and sandbox directories
gemini-handoff init-env

# Start the server (listens on 127.0.0.1:8787 by default)
npm start
```

### Step 2: Expose a public HTTPS endpoint

Pick either option to tunnel `127.0.0.1:8787`:

- **Option A — 30-second zero-signup trial (`cloudflared`)**:
  ```bash
  cloudflared tunnel --url http://127.0.0.1:8787
  ```
  This prints a temporary `https://xxx.trycloudflare.com` URL.
  > Note: Quick Tunnel subdomains change on every restart and are meant for quick testing only. Use Option B for daily workflows.
- **Option B — Persistent HTTPS URL (Recommended: `Tailscale Funnel` or your own domain)**:
  ```bash
  tailscale funnel 8787
  ```
  Gives you a permanent `https://<machine>.<tailnet>.ts.net` URL that never changes, or use a Cloudflare Named Tunnel with your own domain.

### Step 3: Add the connector in Google Gemini APP

> Prerequisite: Personal Google account with **Custom apps** visible under **Settings → Connected Apps** (English UI / Keep Activity may be required depending on region).

1. Open `https://gemini.google.com` → **Settings** → **Connected Apps** → **Custom apps**.
2. Enter your endpoint URL (pick one):
   - **OAuth 2.1 login**: Enter `https://<your-domain>/mcp`, then approve using the `OWNER_PASSPHRASE` from `.env`.
   - **Direct path-key URL (no OAuth popup)**: Set `MCP_ACCOUNT_KEYS=acc1:your-long-secret` in `.env`, enter `https://<your-domain>/mcp/u/your-long-secret`, and choose **No authentication**.

> **Time-saving tip (skip typing `@MCP` every time)**:  
> Consumer Gemini APP enforces turn-based security — an external MCP cannot wake up an idle chat without a user message (this project intentionally avoids browser DOM auto-click scripts). Create a dedicated **Gem** with instructions like: *"Whenever I say `go`, call `list_tasks` / `get_task`, `claim_task` the highest-priority task, complete it, and call `submit_task_result`."* Then opening the Gem and typing **`go`** starts the workflow immediately.

---

## 2. Mount Local Code & Notes Directly (No Upload Needed)

When running on your own machine, point `.env` directly at local directories instead of pushing files over HTTP:

```env
# Writable sandbox where Gemini can create drafts and reports
FILES_ROOT=/path/to/your/sandbox-workspace

# Read-only code mounts (semicolon-separated; Gemini can never modify these)
REPO_MOUNTS=myapp=/path/to/your/project

# Read-only notes mounts
NOTE_MOUNTS=obsidian=/path/to/your/notes
```

---

## 3. Two-Way Task Handoff CLI

If you just want Gemini to read mounted folders in chat, you are already done.  
To dispatch scoped async tasks between your **local coding agent** (via [skills/gemini-handoff/SKILL.md](./skills/gemini-handoff/SKILL.md)) and **Gemini APP**:

```bash
# 1. Verify connectivity
gemini-handoff health

# 2. (Optional, for remote server setups) Upload reference context or read-only repo files
gemini-handoff push-file ./spec.md research/spec.md --account acc1
gemini-handoff push-repo ./my-project my-project

# 3. Dispatch a task (prints a 1-line prompt for Gemini APP)
gemini-handoff dispatch \
  --title "Architecture research" \
  --objective "Compare auth options and recommend an implementation" \
  --attach research/spec.md \
  --account acc1

# 4. Pull distilled results back locally (stdout wrapped in randomized untrusted-data boundaries)
gemini-handoff list --status completed --account acc1
gemini-handoff pull <task_id> --out ./result.md

# 5. Review & pull proposals initiated from mobile/web Gemini APP
gemini-handoff proposals
gemini-handoff pull <proposed_task_id>
```

---

## 4. Tools Exposed to Gemini APP (20 Tools)

| Category | Tools | Purpose |
| :--- | :--- | :--- |
| **Task Queue** | `list_tasks`, `get_task`, `claim_task`, `checkpoint_task`, `submit_task_result`, `propose_task` | Inspect/claim tasks, save long-task checkpoints, submit reports, or propose new tasks back to desktop |
| **Workspace (`FILES_ROOT`)** | `list_files`, `read_file`, `search_files`, `write_file`, `edit_file`, `list_file_snapshots`, `restore_file_snapshot` | Sandboxed read/write (`edit_file` supports `dry_run` + `sha256` checks and auto-snapshots every write for instant rollback) |
| **Read-Only Notes (`NOTES_ROOT`)** | `list_notes`, `search_notes`, `read_note` | 100% read-only browsing and search |
| **Read-Only Repos (`REPOS_ROOT`)** | `list_repo_tree`, `search_repo_code`, `read_repo_file` | 100% read-only code access with `.env`, keys, and binary files automatically hidden |
| **Status** | `get_workspace_status` | Inspect active mounts, queue counts, and active guardrails |

---

## 5. Security & Usage Notes

1. **Do not sync proprietary or sensitive code**: Consumer Gemini APP with Connected Apps typically requires `Keep Activity` enabled. Only use this with personal projects, open-source code, or sanitized material — **never upload confidential company source code, PII, or production credentials**.
2. **Protect path-key URLs**: If using `/mcp/u/<key>`, ensure reverse proxies strip path keys from logs (see [deploy/Caddyfile.example](./deploy/Caddyfile.example) and [deploy/nginx.conf.example](./deploy/nginx.conf.example)).
3. **Review cloud deliverables before executing commands**: `gemini-handoff pull` wraps stdout output in randomized `<<<UNTRUSTED_REMOTE_ARTIFACT_BEGIN nonce=...>>>` boundaries to reduce second-order prompt injection risk; always inspect pulled reports before running suggested shell commands.
4. **Account isolation**: `TENANT_ISOLATION=true` is enabled by default so different account keys stay isolated in separate queues, files, and snapshots.

See [SECURITY.md](./SECURITY.md) for the full threat model.

---

## 6. Optional: 24/7 Cloud Hosting (Docker / VPS)

Want mobile Gemini APP to stay connected and submit `propose_task` ideas even when your laptop is powered off?

- **Docker Compose + Caddy**: Set `PUBLIC_BASE_URL` in `.env`, copy `deploy/Caddyfile.example` to `deploy/Caddyfile`, and run:
  ```bash
  docker compose --profile caddy up -d --build
  ```
- **Systemd + Nginx**: See [deploy/gemini-handoff.service](./deploy/gemini-handoff.service) and [deploy/nginx.conf.example](./deploy/nginx.conf.example).
- **Split Admin Port (Recommended)**: Set `ADMIN_PORT=8788` and `ADMIN_HOST=127.0.0.1` so `/api/tasks` and `/api/sync` are never exposed on the public MCP port (`8787`).
- **Avoid sleeping free container tiers**: Platforms that sleep after idle periods or wipe ephemeral disks on restart will drop MCP connections and lose unpulled tasks/snapshots.

---

## 7. Run Tests & License

```bash
node --test tests/integration.test.mjs
```

Licensed under the [MIT License](./LICENSE).
