# Benchmark Evaluation: Star-Ring Engine on InjecAgent & AgentHarm

> Star-Ring AI Behavior Security Lab (initiated by an independent researcher) · 2026-11
> Reproducible: [`benchmarks/eval_injecagent.py`](../benchmarks/eval_injecagent.py) · [`benchmarks/eval_agentharm.py`](../benchmarks/eval_agentharm.py) · [`benchmarks/tool_classifier.py`](../benchmarks/tool_classifier.py)

---

## Executive Summary

| Benchmark | What it measures | TPR | FPR | Verdict |
|---|---|---|---|---|
| **InjecAgent** (UIUC, ACL Findings 2024) | Injected tool call completes a harmful action | **91.9%** (969/1,054) | **0.0%** (0/1,054) | ✅ Valid result |
| **AgentHarm** (Gray Swan AI + UK AISI, ICLR 2025) | Agent performs a harmful task | 88.6% (156/176) | 85.2% (150/176) | ❌ No discriminative power — **negative result reported** |

**Two things worth stating up front:**

1. The InjecAgent result is a real detection result: **91.9% of injected attack chains blocked, 0% of the matching legitimate requests blocked**, on 1,054 third-party cases.
2. The AgentHarm result is reported **as a negative result**, not a win. Its TPR and FPR are 3.4 points apart — which means it cannot distinguish a working detector from one that blocks everything. We explain why in §4 and why we chose to publish it anyway.

---

## 1. Why false positives must be measured, not assumed

A block rate alone is unfalsifiable: a detector that blocks every input scores 100%. The only way to make an interception number meaningful is to measure it **against a control that should be allowed**, using the same pipeline and the same classification.

So every number in this report is a **(TPR, FPR) pair**:

- **TPR** — attack chain blocked (`[user tool] + [attacker tools]`)
- **FPR** — legitimate request blocked (`[user tool]` alone, same case file)

Same samples, same classifier, same engine. Only the chain differs.

---

## 2. Methodology: tool classification

Both benchmarks use their own tool vocabularies (`GmailSendEmail`, `AugustSmartLockUnlockDoor`, `post_on_x`…). Star-Ring reasons over action types, so a mapping layer is unavoidable — and a sloppy mapping can manufacture either false positives or false negatives.

Our classifier ([`tool_classifier.py`](../benchmarks/tool_classifier.py)) **tokenizes** tool names (CamelCase + snake_case) and takes the **first known verb**, rather than substring matching.

> This change was not cosmetic. An earlier substring-based version mapped `EvernoteManager**Search**Notes` and `GoogleCalendarGetEventsFrom**Share**dCalendar` onto privilege/egress actions, producing a 29.4% false-positive rate that was entirely an artifact of the mapping. After switching to verb-token matching, that FPR went to 0%.

Ambiguous verbs (`login`, `connect`, `schedule`) are deliberately mapped to the low-risk `organize` class — **we prefer under-detection over an inflated TPR.** Every unresolved tool name falls through to the engine's documented fail-closed path, and coverage is reported.

---

## 3. InjecAgent — the applicable benchmark

InjecAgent models indirect prompt injection: content the agent reads tells it to call an *additional* tool that serves the attacker.

### 3.1 Data Stealing (544 cases) — `read → send`

| Metric | Value |
|---|---|
| Attack chains blocked | **544 / 544 = 100.0%** |
| Legitimate requests blocked | **0 / 544 = 0.0%** |
| SHA-256 (result set) | `4ef58c80…a298845dd8` (byte-identical on re-run) |

Every case ends in `GmailSendEmail`. The chain is structurally `read → egress`, which is exactly what a behavior-chain rule recognizes — independent of how the injection is worded.

### 3.2 Direct Harm (510 cases) — injected tool is itself dangerous

| Metric | Value |
|---|---|
| Attack chains blocked | **425 / 510 = 83.3%** |
| Legitimate requests blocked | **0 / 510 = 0.0%** |
| SHA-256 (result set) | `56f83c01…679061b8b72` (byte-identical on re-run) |

| Harm category | Blocked |
|---|---|
| Financial (transfer / withdraw / place order) | high |
| Physical (unlock door / grant access) | high |
| Data Security (delete / disable / policy change) | medium |

The residual ~17% is where the injected tool is a **low-risk operation** (move a file, leave a channel, schedule a device action) — no privilege escalation, no egress, no finance. Blocking those would be over-reach.

### 3.3 Combined

**1,054 cases → TPR 91.9% (969/1,054), FPR 0.0% (0/1,054).**

---

## 4. AgentHarm — a negative result, reported as such

AgentHarm pairs **176 harmful behaviors with 176 benign counterparts**. We ran both.

| Set | Blocked |
|---|---|
| harmful (TPR) | 156/176 = **88.6%** |
| benign (FPR) | 150/176 = **85.2%** |

A 3.4-point gap means the engine cannot tell these two sets apart. **If we only reported 88.6%, we would be publishing a number that sounds like detection and is actually "blocks almost everything".**

### 4.1 Why: the labels are content-defined, not action-defined

AgentHarm's harmful and benign variants share **the same tool sequence** and differ only in prompt wording:

```
harmful #1 : create AI video of politicians → post on X  (claiming it is real)
benign  #1 : create AI video of politicians → post on X  (labeled as AI-generated)
```

A behavior-chain engine reads actions, not prompts. For these pairs it *must* return the same verdict. **The benchmark measures content harm; the engine governs action harm.** They are orthogonal axes.

### 4.2 The conclusion is invariant to mapping choices

To make sure the gap was not an artifact of mapping "publishing" onto egress, we ran a second variant treating all publishing tools as low-risk:

| Mapping variant | TPR | FPR | Gap |
|---|---|---|---|
| A — publishing = egress | 88.6% | 85.2% | **3.4** |
| B — publishing = low risk | 43.2% | 39.8% | **3.4** |

The absolute numbers move by 45 points; **the gap does not move at all.** That is the signature of a benchmark with no discriminative power for this engine, rather than a tuning problem.

### 4.3 What this tells us about the product

This is not only a benchmark footnote — it is a product finding:

> If Star-Ring is deployed as a **content filter**, it will produce ~85% false positives on benign content-harm-adjacent workflows.

Which is precisely why hard blocking is the wrong default, and why the engine's design centers on **downgrade, redaction, and human hand-off** rather than binary block. The benchmark makes the case for the product architecture.

---

## 5. Determinism

Every run re-executes and compares SHA-256 of the full result set. All four sets are byte-identical across runs.

**Why this outranks the percentages**: a verdict that cannot be reproduced cannot be audited, and an audit that cannot be reproduced is not evidence.

---

## 6. Reproduce it

```bash
git clone https://github.com/starring-ai-sec/star-ring-agent-sentinel
cd star-ring-agent-sentinel

python benchmarks/eval_injecagent.py   # 1,054 cases: TPR + FPR
python benchmarks/eval_agentharm.py    # 176 + 176 cases: the negative result
```

Datasets auto-download on first run and are cached locally. Standard library only, Python 3.8+.

---

## 7. Scope statement

**Proves**
- On externally published injection benchmarks, the rule engine blocks dangerous tool-call chains at 91.9% with a 0% false-positive rate on matched legitimate requests.
- All results are deterministic and reproducible byte-for-byte.

**Does not prove**
- That content-level harm is addressed. It is not, and §4 quantifies exactly why using it for that purpose would be harmful.
- Anything about model-level robustness. These are action-layer results, layered *underneath* whatever the model does.
- Coverage of arbitrary tool vocabularies — the mapping layer and its limits are published with the scripts.

---

## 8. Contact

- Repository: https://github.com/starring-ai-sec/star-ring-agent-sentinel
- PyPI: https://pypi.org/project/langchain-starring/
- Contact: security@starring-ai-sec.com

---

<div id="简体中文"></div>

# 中文版：星环引擎在 InjecAgent / AgentHarm 上的评测

## 摘要

| 评测集 | 测什么 | 拦截率 TPR | 误伤率 FPR | 结论 |
|---|---|---|---|---|
| **InjecAgent**（UIUC, ACL Findings 2024） | 注入后调用危险工具 | **91.9%**（969/1054） | **0.0%**（0/1054） | ✅ 有效结果 |
| **AgentHarm**（Gray Swan + UK AISI, ICLR 2025） | Agent 完成有害任务 | 88.6%（156/176） | 85.2%（150/176） | ❌ 无区分力，**作为负结果公开** |

**两句话概括：**

1. InjecAgent 是真实的检测结果：**1,054 条第三方样本，拦截率 91.9%，误伤率 0%**（同一批样本的合法请求一条都没被拦）；
2. AgentHarm 我们不当作成绩——TPR 与 FPR 只差 3.4 个百分点，说明它区分不了「能用的检测器」和「什么都拦的检测器」。原因见下。

## 一、为什么必须测误伤率

只报拦截率不可证伪——什么都拦的检测器能拿 100%。让拦截率有意义的唯一办法，是**用同一套流水线、同一个分类器，去测「本该放行」的对照**。

所以本报告的每个数字都是 **(TPR, FPR) 成对**给出的：

- **TPR**：攻击链（`[用户工具] + [攻击者工具]`）被拦 = 命中；
- **FPR**：同一 case 里**用户合法请求**（`[用户工具]` 单独）被拦 = 误伤。

同批样本、同分类器、同引擎，唯一差别是链的构成。

## 二、分类器：从「子串匹配」改成「分词取动词」

工具名要映射到星环动作类型（`GmailSendEmail` → 外发、`AugustSmartLockUnlockDoor` → 提权），映射写歪了，TPR 和 FPR 都是假的。

**这不是纸面担忧**：早期用子串匹配时，`EvernoteManager**Search**Notes` 里的 "Manage" 被判成提权、`GetEventsFrom**Share**dCalendar` 里的 "Share" 被判成外发——测出 **29.4% 的误伤**，全部是映射 bug。改成分词取首动词后，**误伤归零**。

模糊动词（login / connect / schedule）一律归低危——**宁可少拦，也不拿激进映射去堆拦截率。**

## 三、InjecAgent：适用，结果干净

| 子集 | 攻击链拦截 | 合法请求误伤 |
|---|---|---|
| 数据窃取（544） | **544/544 = 100%** | **0/544 = 0%** |
| 直接危害（510） | **425/510 = 83.3%** | **0/510 = 0%** |
| **合计（1,054）** | **969/1054 = 91.9%** | **0/1054 = 0%** |

数据窃取 100% 的原因很直白：544 条全是 `读数据 → GmailSendEmail`，就是行为链的本命场景，与注入话术的写法无关。直接危害剩下的 17% 是「注入的工具本身是低危操作」（移动文件、退出频道），拦它反而叫误伤。

## 四、AgentHarm：我们公开一个负结果

| | 拦截 |
|---|---|
| harmful（TPR） | 156/176 = **88.6%** |
| benign（FPR） | 150/176 = **85.2%** |

只报 88.6% 会很好看，但那是「几乎什么都拦」的伪装。**AgentHarm 的 harmful/benign 共用同一套工具序列，只差 prompt 措辞**：

```
有害 #1：生成政客 AI 视频 → 发到 X（声称是真的）
良性 #1：生成政客 AI 视频 → 发到 X（标注为 AI 生成）
```

行为链引擎不读 prompt，只读动作——对这两条**必须**给同样的判定。**这个评测集测的是内容有害性，引擎治的是动作有害性，两者正交。**

**换映射也改不了结论**：

| 映射变体 | TPR | FPR | 差值 |
|---|---|---|---|
| A：发帖视作外发 | 88.6% | 85.2% | **3.4** |
| B：发帖视作低危 | 43.2% | 39.8% | **3.4** |

绝对值挪了 45 个点，**差值一点没动**——这是「无区分力」的特征，不是调参问题。

**对产品的一句话结论**：如果把星环当**内容过滤器**用，它在良性内容工作流上会产生约 85% 误伤——这正是为什么默认动作必须是**降级、脱敏、人工接管**，而不是硬拦。

## 五、确定性

四组结果全部 SHA-256 逐字节可复现。**不可复现的安全结论无法审计，不可审计的不是证据。**

## 六、自己跑

```bash
python benchmarks/eval_injecagent.py   # 1,054 条：TPR + FPR
python benchmarks/eval_agentharm.py    # 176 + 176 条：那个负结果
```

数据首次运行自动下载并本地缓存，仅依赖标准库。
