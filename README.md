# 🛡️ Star-Ring Agent Sentinel

**English** | [简体中文](#简体中文)

> "Content moderation cares what the Agent **says**, we care what the Agent **does**."
> A completely offline, locally-run behavior-chain self-check tool for AI Agents.

![Star-Ring Architecture](./assets/starr-ring-architecture.png)

## 🚨 Why Behavior Security?

Clean input ≠ Safe behavior.

- User: "Check my refund" → Content moderation: Safe.
- Agent action: `read_sms → extract_otp → send_external` → Data leaked.

We judge whether the action should happen *right before* tool execution.

## 🎯 Core Capabilities

- **Behavior Chain Judgement**: Catches "locally legal, globally malicious" attack chains (privilege escalation / credential exfiltration / file exfiltration).
- **Parameter Gate**: Path traversal, over-limit transfer, domain allowlist, batch count — same tool, out-of-bounds params get blocked.
- **Unknown-action Fusing**: Hallucinated tool names fail closed.
- **Zero-Trust Privacy**: Pure local execution. No network required, no silent upload.

## 🚀 Quick Start (Windows)

1. Download `xh-scan.exe` from [Releases](<repo>/releases).
2. Run `xh-scan.exe --machine` to get your machine ID.
3. Open an [Issue](<repo>/issues) (Template: **Free License**) with your machine ID.
4. Put the returned `license.json` into the `license/` folder.
5. Run: `xh-scan.exe --input your_logs.jsonl --out report.md`

Log format (JSONL, one tool call per line):

```json
{"ts":"2026-11-08T10:00:01Z","agent_id":"bot1","tool":"read_sms","params":{}}
```

## 🧪 Deep Inspection (Star-Ring Lab)

The open-source version ships 30 basic risk rules. To get the **Deep Inspection Report** (3-track model + 177 red-team samples, watermarked PDF), run:

```bash
xh-scan.exe --anonymize --input your_logs.jsonl
```

The script auto-replaces phone numbers, emails, paths, IPs and card numbers. Submit the anonymized package via **Issue (Template: Deep Inspection)**. We will manually reply with a watermarked PDF report.

## 🛡️ Tech Specs (Synthetic High-Fidelity Samples)

| Metric | Result |
|---|---:|
| Attack Interception | **172/172 (100%)** |
| False Positive Rate | **0%** (5 benign controls) |
| Reproducibility | **177/177 byte-for-byte identical** |

> ⚠️ Results are from synthetic high-fidelity samples, not real production traffic. Real FPR must be calibrated on your logs.
> The open-source version is a rule-based first pass; the full Star-Ring kernel and sample library are not open-sourced.

## 🤝 Contributing

Issues and PRs welcome. We are onboarding 5 real production scenarios for 1:1 deep inspection.

See [CONTRIBUTING.md](./CONTRIBUTING.md).

---

MIT © 2026 Star-Ring AI Behavior Security Lab

---

<div id="简体中文"></div>

# 🛡️ 星环 Agent 行为安全哨兵

**English** | **简体中文**

> **内容安全管「Agent 说了什么」，我们管「Agent 做了什么」。**
> 一个完全离线、本地运行的 AI Agent 行为链自检工具。

![星环架构](./assets/starr-ring-architecture.png)

## 🚨 为什么需要行为安全？

输入干净 ≠ 行为安全。

- 用户说：「帮我查退款」→ 内容审核：安全，放行。
- Agent 动作：`读短信 → 提取验证码 → 发往外部` → 灾难发生。

我们就在工具执行前的那一步，判定它该不该发生。

## 🎯 核心能力

- **行为链判定**：抓「每一步都合法、串起来要命」的链式攻击（提权链 / 凭据外泄链 / 文件外发链）。
- **参数级闸门**：路径穿越、超额转账、域名白名单、批量次数——同一工具，参数越界就拦。
- **未知动作熔断**：模型幻觉出不存在的工具，直接拒绝（fail-closed）。
- **零信任隐私**：纯本地运行，数据绝不出端，杜绝任何静默上传。

## 🚀 快速开始 (Windows 平台)

1. 前往 [Releases](<repo>/releases) 下载 `xh-scan.exe`。
2. 运行 `xh-scan.exe --machine` 获取机器码。
3. 在 [Issues](<repo>/issues) 提交机器码，申请免费授权文件（模板：**申请免费授权**）。
4. 把返回的 `license.json` 放入 `license/` 文件夹。
5. 运行：`xh-scan.exe --input your_logs.jsonl --out report.md`

日志格式（JSONL，一行一条工具调用）：

```json
{"ts":"2026-11-08T10:00:01Z","agent_id":"bot1","tool":"read_sms","params":{}}
```

## 🧪 获取深度体检（星环实验室专属）

开源基础版内置了 30 项动作风险表。如需获取包含 **三轨模型 + 177 条红队攻击样本** 的深度行为链分析（带水印 PDF 报告），请运行：

```bash
xh-scan.exe --anonymize --input your_logs.jsonl
```

脚本会自动替换手机号、邮箱、路径、IP、卡号等敏感信息。在仓库提交 **Issue（模板：申请深度体检）** 并附上脱敏内容，我们将人工为您出具专业报告。

## 🛡️ 技术背书（基于合成高仿真样本）

| 指标 | 结果 |
|---|---:|
| 攻击样本遏制 | **172/172 (100%)** |
| 误报率 | **0%**（5 条合法对照） |
| 复测一致性 | **177/177 逐样本逐字节一致** |

> ⚠️ 以上为合成高仿真样本跑出的结果，非真实业务流量；真实误报率需用您的日志校准。
> 开源版本仅为基础规则初筛，完整版星环内核及高价值样本库暂未开源。

## 🤝 开源共建

欢迎提交 Issue 和 PR。我们正在寻找 5 个真实业务场景，进行 1v1 深度内测。

贡献方式见 [CONTRIBUTING.md](./CONTRIBUTING.md)。

---

MIT © 2026 星环AI行为安全实验室
