# Dify Agent 行为链安全分析报告
# Dify Agent Behavior-Chain Security Analysis

> **English** | [简体中文](#简体中文)

> Star-Ring AI Behavior Security Lab · 2026-11
> Target: Dify (langgenius/dify, LLM application platform)
> Disclaimer: independent technical analysis, not an official audit, and not a negative judgment of Dify. Dify is an excellent LLM platform; this document only explores one objective risk on its Agent tool-invocation surface — the behavior-chain dimension.

---

## 1. Why Focus on Dify's Agent Tool-Invocation Surface

Dify's Agent applications let an LLM **autonomously invoke tools** — great for productivity, but it also introduces an overlooked risk:

> An individual tool call may be harmless, but **a chain of tool calls can constitute an attack**.

Content moderation governs what an Agent *says*, but it does not govern *which tools an Agent calls, and in what order*.

## 2. Dify's Tool-Invocation Surface (High-Risk Tools)

Dify provides 50+ built-in tools, custom tools (OpenAPI), and MCP tools. The high-risk ones:

| Dify tool | Capability | Risk |
|---|---|---|
| Code execution (Sandbox) | Run Python/Node.js | Read arbitrary files, env vars, secrets |
| HTTP request | Request any URL | Exfiltrate data to any endpoint |
| File storage (S3/OSS) | Upload/download/list | Move internal files outside |
| Email / SMS | Send messages | Leak content to third parties |
| Web scraping | Crawl pages | Read external or internal URLs |

**Key**: individually these are normal capabilities; chained together under a crafted prompt, they become exfiltration paths.

## 3. Dangerous Chain Mapping

Mapping Dify tools to canonical actions reveals several dangerous chains:

| Dangerous chain | Dify tool combination | Verdict |
|---|---|---|
| File exfiltration | file upload + HTTP request | Fuse |
| Half-malicious sensitive read | code execution reading `.env`/secrets | Block |
| Data egress | internal search + email | Fuse |
| Credential exfiltration | code execution reading credentials + email/HTTP | Fuse |

## 4. Live Test (Real Verdicts)

Four simulated Dify Agent chains, judged by the Star-Ring rule engine:

| Chain | Scenario | Verdict |
|---|---|---|
| ① | `web_search → wikipedia` (normal retrieval) | ✅ Allow |
| ② | `file_storage_upload → http_request` (file exfiltration) | 🚫 **Fuse**: file exfiltration chain |
| ③ | `code_interpreter` reading `.env` (half-malicious) | 🚫 **Block**: sensitive path hit |
| ④ | `web_search → email` (data egress) | 🚫 **Fuse**: credential egress |

**Conclusion**: normal retrieval is not flagged, and all three dangerous chains are blocked — the engine distinguishes "legitimate tool combinations" from "dangerous tool combinations".

## 5. Recommendations for Dify Users/Developers

1. **Add behavior-chain auditing to Agents**: don't just do content moderation — judge "what this chain of tools is trying to do" before execution;
2. **Tighten high-risk tool permissions**: code execution, HTTP, file storage should default to least privilege;
3. **Monitor sensitive-file access**: reads of `.env`, key files, and certs should alert separately.

---

*The behavior-chain detection used here comes from the open-source tool star-ring-agent-sentinel (pure offline, free baseline):*
- *GitHub: https://github.com/starring-ai-sec/star-ring-agent-sentinel*
- *PyPI: `pip install langchain-starring` (LangChain callback, one-line integration)*

---

<div id="简体中文"></div>

# Dify Agent 行为链安全分析报告

> 星环AI行为安全实验室 ｜ 2026-11
> 对象：Dify（langgenius/dify，LLM 应用开发平台）
> 声明：本报告为独立技术分析，非官方审计，不构成对 Dify 的负面评价。Dify 是优秀的 LLM 应用平台，本文仅探讨其 Agent 工具调用面在「行为链安全」维度的一个客观风险。

## 一、为什么关注 Dify 的 Agent 工具调用面

Dify 的 Agent 应用允许 LLM **自主调用工具**完成任务——这带来巨大的生产力，也带来一个被普遍忽视的风险：

> 单个工具调用可能无害，但**一串工具调用连起来，可能构成攻击**。

内容安全管「Agent 说了什么」，但管不住「Agent 调用了什么工具、按什么顺序调用」。

## 二、Dify 的工具调用面（危险工具盘点）

Dify 提供 50+ 内置工具 + 自定义工具（OpenAPI）+ MCP 工具。其中**高危工具**：

| Dify 工具 | 能力 | 风险 |
|---|---|---|
| 代码执行（Sandbox） | 执行 Python/Node.js | 可读任意文件、环境变量、密钥 |
| HTTP 请求 | 请求任意 URL | 可把数据外发到任意地址 |
| 文件存储（S3/OSS） | 上传/下载/列举 | 可把内部文件上传到外部 |
| 邮件/SMS | 发送邮件/短信 | 可把内容外发给第三方 |
| 网页抓取 | 爬取网页 | 可读取外部或内部 URL |

**关键**：这些工具单独用是正常能力，但被恶意 prompt 诱导「组合」起来，就是数据外泄链路。

## 三、危险行为链映射

把 Dify 工具映射到「星环标准动作」后，能识别出多条危险链：

| 危险链 | Dify 工具组合 | 星环判定 |
|---|---|---|
| 文件外发链 | 文件上传 + HTTP 请求 | 熔断 |
| 半恶意读敏感文件 | 代码执行读 `.env`/密钥 | 拦截 |
| 数据出境链 | 搜索内部数据 + 邮件外发 | 熔断 |
| 凭据外泄链 | 代码执行读凭据 + 邮件/HTTP | 熔断 |

## 四、实测（真实判定结果）

用星环规则引擎对 4 条模拟的 Dify Agent 行为链判定：

| 链 | 场景 | 判定 |
|---|---|---|
| ① | `web_search → wikipedia`（正常检索） | ✅ 放行 |
| ② | `file_storage_upload → http_request`（文件外发） | 🚫 **熔断**：文件外发链 |
| ③ | `code_interpreter` 读 `.env`（半恶意） | 🚫 **拦截**：路径命中敏感文件 |
| ④ | `web_search → email`（数据出境） | 🚫 **熔断**：外发凭据 |

**结论**：正常检索不误伤，三条危险链全部被拦——且能区分「正常工具组合」和「危险工具组合」。

## 五、给 Dify 用户/开发者的建议

1. **给 Agent 加行为链审计**：不要只做内容审核，要在工具执行前判定「这一串工具想干什么」；
2. **收紧高危工具权限**：代码执行、HTTP、文件存储这类工具，默认最小权限，按需开放；
3. **监控敏感文件访问**：`.env`、密钥文件、证书的读取要单独告警。

---

*本文用到的行为链判定能力，来自开源工具 star-ring-agent-sentinel（纯离线，规则版免费）：*
- *GitHub：https://github.com/starring-ai-sec/star-ring-agent-sentinel*
- *PyPI：`pip install langchain-starring`（LangChain 回调，一行挂载）*
