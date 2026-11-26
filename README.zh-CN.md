<p align="center">
  <img src="./assets/logo.svg" alt="Gemini Handoff MCP Logo" width="128" height="128" />
</p>

<h1 align="center">Gemini Handoff MCP</h1>

<p align="center">
  <strong>让 Google Gemini APP（网页/手机端）成为你本地代码的云端规划大脑——安全看代码、自动留备份、和本地 Coding Agent 双向派活。</strong><br/>
  Zero-dependency MCP server &amp; CLI built first for <strong>Google Gemini APP</strong> (standard MCP/OAuth 2.1, potentially compatible with Claude.ai / ChatGPT custom connectors — untested).
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Node.js-%3E%3D22.0.0-339933?logo=node.js&logoColor=white" alt="Node.js >= 22" />
  <img src="https://img.shields.io/badge/Dependencies-Zero-4285F4" alt="Zero Dependencies" />
  <img src="https://img.shields.io/badge/Protocol-MCP%20Streamable%20HTTP-EA4335" alt="MCP Streamable HTTP" />
  <img src="https://img.shields.io/badge/License-MIT-34A853" alt="MIT License" />
</p>

<p align="center">
  <a href="./README.md">English</a> | <strong>简体中文</strong>
</p>

---

## 这是什么？为什么专门做这个？

现在大家用 **Google Gemini APP**（Deep Research 深度调研、Pro 强推理、手机语音）经常卡在一个断层上：手机和网页上的 Gemini 很聪明，却看不到你电脑里的项目；而电脑上的 Coding Agent（Antigravity / Claude Code / Codex）能写代码、跑测试，却接不上你在 Gemini APP 里聊出的方案。

**Gemini Handoff MCP** 专门打通这条链路，主打 4 件事：
1. **零依赖、零折腾**：纯 Node.js >= 22，不用装第三方 npm 包，两条命令就能跑。
2. **代码只读防改坏 + 改文件自动留快照**：代码库与笔记严格只读且自动屏蔽 `.env`/私钥；工作区写文件强制 `sha256` 校验并自动存写前快照，改坏了随时一键撤销。
3. **手机与电脑双向派活**：本地把研究任务和参考上下文推给 Gemini；或者你在外用手机 Gemini 语音聊出方案后，直接存成待办工单（`propose_task`），回电脑一条 `pull` 命令交给本地 Coding Agent 落地写代码。
4. **100% 走官方正门、不碰浏览器脚本**：依托 Google 官方 Custom Apps 标准 MCP 协议（基于通用 MCP + OAuth 2.1 标准，理论上可能兼容 Claude.ai / ChatGPT 远程连接器，**暂未针对这两端实测**），不注入网页 DOM、不抓 Cookie，**手机和电脑都能稳用，零封号风险**。

### 和同类方案有什么区别？

| 方案类型 | 代表做法 / 项目 | 痛点与局限 | 本项目的定位 |
| :--- | :--- | :--- | :--- |
| **本地 CLI 反调 Gemini** | `pal-mcp-server`、`gemini-mcp-tool` | 只能从电脑终端调用 Gemini CLI/API，**手机 Gemini 用不了** | 反转方向：让手机/网页 Gemini 自己作为主脑与本地协作 |
| **浏览器插件 / Cookie 爬虫** | `MCP-SuperAssistant`、`Gemini-API` | 仅限电脑浏览器、页面一改版就挂，抓 Cookie 有封号风险 | **官方 Custom Apps 协议**（理论上按标准可能兼容他端，暂未实测），手机通用、不碰 DOM |
| **多合一桌面控制大杂烩** | `gemini-antigravity-bridge` 等 | 塞满鼠标/摄像头等几十个工具，缺代码只读隔离与回滚 | **克制聚焦 20 个工具**：只读护栏 + `sha256` 防覆盖 + 快照回滚 |
| **纯远程文件读写 MCP** | 通用 Filesystem MCP + Proxy | 只负责文件 I/O，没有任务队列、手机立项与状态流转 | 专为**双向异步派活与安全交接**设计（内置 CLI 与 Skill） |

> **为什么需要一条公网 HTTPS 地址？**  
> Gemini APP 跑在 Google 的云端，不能直接访问你电脑上的 `127.0.0.1`。只要用一条穿透命令（如 `cloudflared` 或 `tailscale funnel`）把本机端口映射出去，**文件依然 100% 留在你自己的电脑里，不需要额外购买云服务器。**

---

## 一、3 分钟在本机跑起来（无需云服务器）

> 环境要求：**Node.js >= 22.0.0**（零第三方依赖，不需要 `npm install`）。

### 第 1 步：启动本地服务

```bash
git clone https://github.com/Sansi-06/gemini-handoff-mcp.git
cd gemini-handoff-mcp

# 可选：全局注册 `gemini-handoff` 命令（不执行也可以直接用 node cli/handoff-cli.mjs）
npm link

# 生成 .env 配置文件和随机密钥
gemini-handoff init-env

# 启动服务（默认监听本机 127.0.0.1:8787）
npm start
```

### 第 2 步：给本机开一个公网 HTTPS 入口

任选一种方式把 `127.0.0.1:8787` 暴露成 HTTPS 地址：

- **方式 A：免注册 30 秒试用（`cloudflared`）**
  ```bash
  cloudflared tunnel --url http://127.0.0.1:8787
  ```
  命令会输出一个 `https://xxx.trycloudflare.com` 地址。
  > 注意：这种临时域名每次重启都会变，只适合体验和调试；长期使用请选方式 B。
- **方式 B：长期固定地址（推荐，`Tailscale Funnel` 或自有域名）**
  ```bash
  tailscale funnel 8787
  ```
  Tailscale 会提供一个永久不变的 `https://<机器名>.<tailnet>.ts.net` 地址，绑定一次后不用再改。也可以用 Cloudflare Named Tunnel 绑定自己的域名。

### 第 3 步：在 Gemini APP 里添加连接器

> 前提：个人 Google 账号，且在 **Settings → Connected Apps** 中可见 **Custom apps** 入口（部分账号需英文界面并开启 Keep Activity）。

1. 打开 `https://gemini.google.com` → **Settings** → **Connected Apps** → **Custom apps**。
2. 填入你的地址（二选一）：
   - **OAuth 登录方式**：填 `https://<你的域名>/mcp`，保存后在弹出的授权页面输入 `.env` 里的 `OWNER_PASSPHRASE` 即可。
   - **免弹窗直连方式**：在 `.env` 配置 `MCP_ACCOUNT_KEYS=acc1:你自己的长密钥` 后，直接填 `https://<你的域名>/mcp/u/你自己的长密钥`，认证方式选 **No authentication**。

> **省事技巧（告别每次手打 `@MCP`）**：  
> 因为消费端 Gemini APP 出于安全限制，必须由你发出一条消息才会触发工具（本项目刻意**不注入网页脚本**、不模拟点击，确保零风控封号）。推荐在 Gemini APP 新建一个专属 **Gem**，系统指令里写上：“只要收到 `go` 或简短确认，就立刻调用 `list_tasks` / `get_task` 并 `claim_task` 认领最高优先级任务，完成后调用 `submit_task_result`”。以后点开这个 Gem，只需敲一个 **`go`** 回车就能自动接单开干。

连上之后，你在 Gemini 对话框里就能直接让它调用工具读你的目录、写报告或领任务了。

---

## 二、把本地代码和笔记直接挂给 Gemini（不用来回传文件）

如果你是在自己电脑上直接运行本服务，编辑 `.env` 把本机目录挂进去就行（不需要用 CLI 上传）：

```env
# 允许 Gemini 读写的工作沙箱目录（存放报告、草稿、中间产物）
FILES_ROOT=/path/to/your/sandbox-workspace

# 只读挂载本地代码库（支持多个，分号隔开；Gemini 绝对改不了里面的源码）
REPO_MOUNTS=myapp=/path/to/your/project

# 只读挂载本地笔记目录
NOTE_MOUNTS=obsidian=/path/to/your/notes
```

---

## 三、常见用法：互相派活与收结果

如果你只是在聊天时让 Gemini 读取上面挂载的目录，**连好就能直接聊**。  
如果你想让**本地 Agent** 和 **Gemini APP** 异步协作（本地派任务 → Gemini 做完保存 → 本地拉取结果），可以使用内置 CLI（[skills/gemini-handoff/SKILL.md](./skills/gemini-handoff/SKILL.md) 提供了给本地 Agent 自动调用的 Skill）：

```bash
# 1. 检查服务是否正常
gemini-handoff health

# 2. 如果服务跑在远程机器上，可手动同步参考文件或只读代码（本机直挂可跳过）
gemini-handoff push-file ./spec.md research/spec.md --account acc1
gemini-handoff push-repo ./my-project my-project

# 3. 给 Gemini 派一个任务（会输出一行提示词，直接发给 Gemini APP 即可）
gemini-handoff dispatch \
  --title "技术方案调研" \
  --objective "对比几种认证方案并输出选型建议" \
  --attach research/spec.md \
  --account acc1

# 4. Gemini 完成后，把报告和产物拉回本地
gemini-handoff list --status completed --account acc1
gemini-handoff pull <task_id> --out ./result.md

# 5. 查看并拉取你在 Gemini APP 里反向创建的新任务提案
gemini-handoff proposals
gemini-handoff pull <proposed_task_id>
```

---

## 四、Gemini APP 能调用哪些工具？（共 20 个）

| 分类 | 工具 | 作用 |
| :--- | :--- | :--- |
| **任务队列** | `list_tasks`、`get_task`、`claim_task`、`checkpoint_task`、`submit_task_result`、`propose_task` | 查看/认领任务、记录进度、提交最终报告，或反向发起新任务提案 |
| **工作目录 (`FILES_ROOT`)** | `list_files`、`read_file`、`search_files`、`write_file`、`edit_file`、`list_file_snapshots`、`restore_file_snapshot` | 读写工作区文件；`edit_file` 支持先试跑（`dry_run`）和 `sha256` 防覆盖校验，每次修改自动留快照可回滚 |
| **只读笔记 (`NOTES_ROOT`)** | `list_notes`、`search_notes`、`read_note` | 100% 只读浏览和搜索笔记 |
| **只读代码 (`REPOS_ROOT`)** | `list_repo_tree`、`search_repo_code`、`read_repo_file` | 100% 只读看代码，自动屏蔽 `.env`、密钥和二进制文件 |
| **状态检查** | `get_workspace_status` | 查看当前目录配置、安全策略和任务队列统计 |

---

## 五、安全与使用注意事项

1. **不要上传公司机密或隐私数据**：消费端 Gemini APP 启用 Connected Apps 通常受平台活动记录与人工抽样审核条款约束。请只用于个人项目、开源代码或脱敏资料，**切勿同步公司闭源源码、客户数据或生产密钥**。
2. **保护好你的路径密钥**：如果使用 `/mcp/u/<key>` 免弹窗地址，请勿在公开日志中打印完整 URL；反代配置示例见 [deploy/Caddyfile.example](./deploy/Caddyfile.example) 与 [deploy/nginx.conf.example](./deploy/nginx.conf.example)（已内置路径脱敏）。
3. **云端报告先看再执行**：Gemini 从公网检索回来的内容或 `propose_task` 提案，在本地落地执行前请先人工核对，不要盲目直接运行其中的命令。
4. **多账号仅作工作区隔离**：默认 `TENANT_ISOLATION=true` 会把不同账号的文件和任务隔开，请勿用于多账号规避配额。

详细威胁模型与安全设计见 [SECURITY.md](./SECURITY.md)。

---

## 六、进阶：部署到 24 小时云服务器（Docker / VPS）

如果你希望**电脑关机时也能用手机 Gemini 派活/记想法**，可以把本项目跑在一台常驻 Linux 主机上：

- **Docker Compose + Caddy 自动 HTTPS**：在 `.env` 填好 `PUBLIC_BASE_URL`，复制 `deploy/Caddyfile.example` 为 `deploy/Caddyfile`，执行：
  ```bash
  docker compose --profile caddy up -d --build
  ```
- **Systemd + Nginx**：参考 [deploy/gemini-handoff.service](./deploy/gemini-handoff.service) 和 [deploy/nginx.conf.example](./deploy/nginx.conf.example)。
- **隔离管理接口（推荐）**：在 `.env` 设置 `ADMIN_PORT=8788` 和 `ADMIN_HOST=127.0.0.1`，只把 `8787`（MCP 端口）暴露给公网，`/api/tasks` 和 `/api/sync` 仅限本机或 SSH 隧道访问。
- **不建议用免费休眠容器（如 Render/Koyeb 免费层）**：容器休眠冷启动会导致 MCP 超时，且免费磁盘重启会清空未拉取的任务和快照。

---

## 七、运行测试与开源许可

```bash
node --test tests/integration.test.mjs
```

本项目基于 [MIT License](./LICENSE) 开源。
