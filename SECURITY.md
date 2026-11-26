# Security Policy (`gemini-handoff-mcp`)

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `1.0.x` | Yes |

## Threat Model & Built-In Defenses

1. **Tenant Isolation (`TENANT_ISOLATION=true`, default)**:
   - Every authenticated OAuth token or `/mcp/u/<key>` connection is pinned to its verified `account`.
   - Named accounts (`acc1`, `acc2`, `personal`, `work`, etc.) isolate task visibility/mutations, `FILES_ROOT` (`DATA_DIR/accounts/<account>/files`), and `SnapshotStore` history/restoration.
   - Only set `TENANT_ISOLATION=false` on a strictly single-owner server where every configured account belongs to the same user.
2. **Loopback Admin API Separation (`ADMIN_PORT`)**:
   - In production deployments behind a public tunnel or reverse proxy, set `ADMIN_PORT=8788` (`ADMIN_HOST=127.0.0.1`) so `/api/tasks` and `/api/sync/*` are unreachable from the public MCP port.
3. **DNS-Rebinding Defense (`Origin` Validation)**:
   - Browser `Origin` headers outside `localhost` / `127.0.0.1` / `[::1]`, `PUBLIC_BASE_URL`, or `ALLOWED_ORIGINS` are rejected with HTTP `403`.
   - Same-origin CSRF-protected `/oauth/authorize` consent submissions are permitted when behind a reverse proxy.
4. **Read-Only Code & Notes Sandboxes**:
   - All sandboxed paths resolve via `fs.realpath` checks blocking `..` traversal, symlinks escaping root, and sensitive credential filenames (`.env*`, `*.pem`, `*.key`, `*credentials*`, `*secret*`).
5. **Cloud-to-Local Second-Order Prompt Injection**:
   - Deliverables returned by cloud models (`submit_task_result`, `propose_task`, `write_file`) may summarize untrusted public web pages. Local coding agents must treat pulled cloud outputs as untrusted data and require user review before executing shell commands.
6. **Consumer Gemini Account Privacy Notice**:
   - Do **not** sync proprietary corporate code, NDA-covered repositories, or personal PII when connecting a personal Google account with `Keep Activity` enabled.

## Reporting a Vulnerability

Please **do not** disclose security vulnerabilities in public GitHub issues. Report suspected vulnerabilities directly to the repository maintainer via GitHub Private Vulnerability Reporting (Security Advisories) with reproduction steps and impact assessment.
