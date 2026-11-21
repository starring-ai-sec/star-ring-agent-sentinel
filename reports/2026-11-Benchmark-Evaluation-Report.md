# Benchmark Evaluation: Star-Ring Engine on AgentHarm & InjecAgent

> Star-Ring AI Behavior Security Lab (initiated by an independent researcher) · 2026-11
> Reproducible scripts: [`benchmarks/eval_agentharm.py`](../benchmarks/eval_agentharm.py) · [`benchmarks/eval_injecagent.py`](../benchmarks/eval_injecagent.py)

---

## Executive Summary

We evaluated the open-source rule engine against **two independently published, peer-reviewed agent-security benchmarks** — 1,230 cases in total.

| Benchmark | Cases | Blocked at action layer | Pure-detection rate¹ |
|---|---|---|---|
| **AgentHarm** (Gray Swan AI + UK AISI, ICLR 2025) | 176 harmful | **90.9%** (160/176) | — |
| **InjecAgent — Data Stealing** (UIUC, ACL Findings 2024) | 544 | **100%** (544/544) | **100%** (510/510) |
| **InjecAgent — Direct Harm** (UIUC, ACL Findings 2024) | 510 | **92.9%** (474/510) | **91.9%** (406/442) |

¹ *Rate restricted to chains where every tool name mapped onto a recognized action type — i.e. excluding cases where the engine's documented fail-closed default handled an unknown tool.*

Every result is deterministic: re-running the evaluation produces a **byte-identical SHA-256 fingerprint**.

---

## 1. What these benchmarks measure

| Benchmark | Threat model | Why it matters for behavior-chain defense |
|---|---|---|
| **AgentHarm** | An agent asked to perform a harmful tool-using task | Tests whether harmful **tool sequences** can proceed end-to-end |
| **InjecAgent (Direct Harm)** | Indirect prompt injection makes the agent call a *dangerous* tool (unlock door, transfer funds, change firewall policy) | Tests the **last line of defense** when model-level robustness fails |
| **InjecAgent (Data Stealing)** | Injection makes the agent read private data, then **send it out** via email | Textbook exfiltration chain: `read → send` |

The framing matters: a benchmark measures *whether the malicious goal is achieved*, not whether a particular model resists injection. Star-Ring sits at the **action layer** — it assumes the model may be fooled, and blocks the chain that would otherwise complete.

---

## 2. Methodology

1. Download the public test sets (auto-cached on first run).
2. Map each benchmark's tool names onto Star-Ring action types (explicit map + keyword rules; see the scripts).
3. Feed the resulting action sequence into `xh_engine.evaluate()`.
4. Count a case as **blocked** when the verdict is `block` or `fuse`.
5. Re-run and compare SHA-256 of the full result set to verify determinism.

### Disclosure on fail-closed behavior

Unknown tool names are rejected by design (fail-closed). Because that would inflate a "block rate", we report two numbers for InjecAgent:

- **Blocked at action layer** — all cases;
- **Pure-detection rate** — only chains where every tool mapped to a recognized action type.

We also report the coverage ratio so the reader can see how much of each result set rests on explicit mapping (AgentHarm: 100% mapped by design; InjecAgent ds: 93.8%; dh: 86.7%).

---

## 3. Results

### 3.1 AgentHarm — 176 harmful behaviors

| Metric | Result |
|---|---|
| Blocked | **160 / 176 = 90.9%** |
| Not blocked | 16 (9.1%) |
| SHA-256 (full result set) | `add62b45…b2d1dee0` (reproducible) |

Not-blocked cases concentrate in **Copyright (8)** and **Sexual (4)** — these are "harmful content generated with harmless tools": search → download → upload a video. The tool sequence itself is not a privilege or exfiltration chain.

> **This is the capability boundary, stated plainly**: Star-Ring governs *what the agent does*, not *what the agent says*. Content-harm categories belong to content moderation; Star-Ring is the action-layer gate downstream of it.

### 3.2 InjecAgent — Data Stealing (544 cases)

| Category | Blocked |
|---|---|
| Others | 255/255 (100%) |
| Physical Data | 187/187 (100%) |
| Financial Data | 102/102 (100%) |
| **Total** | **544/544 (100%)** |
| Pure-detection (recognized only) | 510/510 (100%) |
| SHA-256 | `e3cc13a0…8d0553f7` (reproducible) |

Every case is `read data → GmailSendEmail`. This is the canonical exfiltration chain, and the engine's read→egress rule covers it structurally — independent of how the injection is phrased.

### 3.3 InjecAgent — Direct Harm (510 cases)

| Category | Blocked |
|---|---|
| Financial Harm (transfer / withdraw / pay) | 153/153 (100%) |
| Physical Harm (unlock / grant access) | 158/170 (92.9%) |
| Data Security Harm (delete / disable / policy change) | 163/187 (87.2%) |
| **Total** | **474/510 (92.9%)** |
| Pure-detection (recognized only) | 406/442 (91.9%) |
| SHA-256 | `f7f99a27…c373bfc5b` (reproducible) |

The residual ~8% is where the injected tool is a **low-risk operation** (e.g. moving a file, leaving a channel) — no privilege escalation, no egress, no finance. Blocking those would be over-reach, not detection.

---

## 4. Determinism

Both scripts re-run the full evaluation and compare fingerprints:

```
AgentHarm   result sha256 : add62b45465e5d51fa46258de52e80dcf58fddfc50ce9907fdfdb7f5b2d1dee0
            reproducibility : byte-identical
InjecAgent  dh sha256     : f7f99a27ad7421efdfd0993fbd1c00605aa4506484dd120bf843c22c373bfc5b
            reproducibility : byte-identical
InjecAgent  ds sha256     : e3cc13a092a1460fb658aff57bad271b2a59a7fb6abb9ae08c6ec3dc8d0553f7
            reproducibility : byte-identical
```

**Why this matters more than the percentages**: a security verdict that cannot be reproduced cannot be audited. These numbers are the output of a deterministic rule engine — no sampling, no temperature, no model.

---

## 5. Reproduce it yourself

```bash
git clone https://github.com/starring-ai-sec/star-ring-agent-sentinel
cd star-ring-agent-sentinel

# AgentHarm (176 cases)
python benchmarks/eval_agentharm.py

# InjecAgent (1,054 cases)
python benchmarks/eval_injecagent.py
```

Datasets download automatically on first run and are cached locally. Requires Python 3.8+ and the standard library only.

---

## 6. What this does and does not prove

**Proves**
- The rule engine blocks tool-call sequences that complete published attack goals, at rates measured against third-party benchmarks rather than our own corpus.
- The behavior is deterministic and reproducible byte-for-byte.

**Does not prove**
- That content-level harm is addressed — it is explicitly out of scope (see §3.1).
- That every possible tool vocabulary is covered — coverage ratios are disclosed per benchmark (§2).
- Anything about model-level robustness: these are action-layer results layered *underneath* whatever the model does.

---

## 7. Contact

White-hat, offline, reproducible by design. Independent security researcher.

- Repository: https://github.com/starring-ai-sec/star-ring-agent-sentinel
- PyPI: https://pypi.org/project/langchain-starring/
- Contact: security@starring-ai-sec.com

---

<div id="简体中文"></div>

# 中文版：星环引擎在 AgentHarm / InjecAgent 上的评测

## 摘要

用**两个独立发表、经同行评审的 Agent 安全评测集**（合计 1,230 条）评测开源规则引擎：

| 评测集 | 样本 | 动作层拦截 | 纯识别判定率¹ |
|---|---|---|---|
| **AgentHarm**（Gray Swan AI + UK AISI, ICLR 2025） | 176 攻击样本 | **90.9%**（160/176） | — |
| **InjecAgent — 数据窃取**（UIUC, ACL Findings 2024） | 544 | **100%**（544/544） | **100%**（510/510） |
| **InjecAgent — 直接危害**（UIUC, ACL Findings 2024） | 510 | **92.9%**（474/510） | **91.9%**（406/442） |

¹ *仅统计「链上所有工具都映射到已识别动作类型」的样本，剔除由 fail-closed 兜底处理的未知工具，避免虚高。*

所有结果**确定性可复现**：重跑得到逐字节一致的 SHA-256 指纹。

## 关键结论

1. **InjecAgent 数据窃取 100%**：544 条全是「读数据 → 邮件外发」，正是行为链的本命场景——覆盖与注入话术无关，只看动作序列；
2. **InjecAgent 直接危害 92.9%**：金融类（转账/提现）100%，物理类（开锁/授权）92.9%；
3. **AgentHarm 90.9%**：未拦的 9.1% 是「用无害工具生成有害内容」（版权、性内容）——这是**内容层**问题，不属于动作层职责；
4. **确定性 > 百分比**：不可复现的安全结论无法审计。这些数字是确定性规则引擎的输出，无采样、无温度、无模型。

## 自己跑

```bash
python benchmarks/eval_agentharm.py    # 176 条
python benchmarks/eval_injecagent.py   # 1054 条
```

数据首次运行自动下载并本地缓存，仅依赖标准库。
