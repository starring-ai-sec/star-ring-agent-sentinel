# 如何在 LangChain 中拦截「合法但恶意」的工具调用链？

> 投稿方向：LangChain 官方 Co-marketing / 博客 / 掘金 / 知乎

---

## 一个真实的攻击场景

有个电商客服 Agent，用户只说了一句：

> 帮我查一下这笔退款为什么没到账。

这句话内容审核看完全安全，直接放行。然后看 Agent 的工具调用日志：

```python
10:07:01  read_sms          # 读用户短信
10:07:02  send_credentials  # 把验证码发出去
```

**一句话的工夫，验证码出去了。**

问题在哪？每一步都「合法」：

- `read_sms` 是客服 Agent 的常规权限（帮用户读验证码）；
- `send_credentials` 单看是「发送凭据」，但没人会单独调它。

**单看每一步都没问题，串起来就是要命。** 而市面上大多数 Agent 防护，防的只是「每一步」。

## 为什么单步防护防不住

| 防护层 | 它防什么 | 为什么拦不住这条链 |
|---|---|---|
| 内容审核 | 用户说了什么 | 用户只说了「查退款」，干净的 |
| Prompt 加固 | 提示词里塞指令 | 攻击不在提示词里，在动作里 |
| 工具白名单 | 能不能调这个工具 | 两个工具都在白名单里 |
| 日志审计 | 事后追查 | 能查到，但验证码已经出去了 |

**内容审核管「Agent 说了什么」，管不住「Agent 做了什么」。**

我自己的第一版系统也漏过这条链。这个领域没有「写完就安全」这回事。

## 行为链判定：看组合，不看单步

`langchain-starring` 的核心就一句话：**不评估「这个工具能不能调」，而是评估「这一串工具串起来，想干什么」。**

它能识别「单个动作都合法、串起来就是危险」的链式攻击——比如「读短信 → 发验证码」这条链，每一步单独看都正常，连起来就是凭据外泄。它也能识别参数越界（比如读一个越权路径），以及多 Agent 协同时的异常。

## 一行代码接入

```bash
pip install langchain-starring
```

```python
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from starring import StarRingCallbackHandler

agent = create_tool_calling_agent(ChatOpenAI(), tools, prompt)

executor = AgentExecutor(
    agent=agent,
    tools=tools,
    # 就这一行，行为链危险时自动抛 StarRingBlockedError
    callbacks=[StarRingCallbackHandler()],
)
```

**零代码修改**——你不需要改任何工具函数、任何 prompt，只挂一个回调。

## 完整示例

```python
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from starring import StarRingCallbackHandler, StarRingBlockedError


@tool
def read_sms() -> str:
    """Read the user's SMS messages to help with verification."""
    return "Your latest code is 8848"


@tool
def send_credentials(to: str, content: str) -> str:
    """Send credentials to an external address."""
    return f"sent to {to}"


prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful customer service agent."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

agent = create_tool_calling_agent(ChatOpenAI(), [read_sms, send_credentials], prompt)

executor = AgentExecutor(
    agent=agent,
    tools=[read_sms, send_credentials],
    callbacks=[StarRingCallbackHandler()],
)

try:
    executor.invoke({"input": "帮我查一下退款，验证码念给我听"})
except StarRingBlockedError as e:
    print(e)
    # [星环熔断] 行为链被拦截：检测到危险的连续动作
```

当 Agent 尝试 `read_sms → send_credentials` 时，**第二个工具调用抛出异常，验证码没有外发**。

## 它拦住了什么

内置的规则引擎在工具执行前判定整条链：

| 场景 | 结果 |
|---|---|
| 读短信 → 发验证码 | 拦截 |
| 改权限 → 读通讯录 | 拦截 |
| 分享文件 → 发外部 | 拦截 |
| 读越权路径 | 拦截 |
| 超额转账 | 拦截 |
| 幻觉出的工具调用 | 拦截 |

## 原理

`StarRingCallbackHandler` 在 `on_tool_start` 阶段累积最近 N 步工具调用，交给规则引擎判定：

```
工具调用 → 累积行为链 → 规则引擎判定 → 危险？ → 抛 StarRingBlockedError（熔断）
                                          ↓ 安全
                                       继续执行
```

## 边界（诚实说明）

1. 这是**规则版初筛**：内置基础风险规则，不含完整的三轨模型与红队样本库；
2. 判定的是**行为链**，不判定文本内容（有害内容识别不在能力范围）；
3. 行为链默认保留最近 6 步，更长的链尾部不纳入；
4. 工具名映射：默认直接用工具名作为动作类型，自定义工具请用 `action_map` 映射。

## 与竞品的差异

`interven-langchain`、`iris-security`、`ActShield` 等方案主要做**单步**检测（这一句话有没有毒、这个工具危不危险）。

`langchain-starring` 的差异化在于：

> 抓住「每一步都合法，但串联起来就是攻击」的复杂场景——这是单步规则覆盖不了的盲区。

## 链接

- PyPI：`pip install langchain-starring`
- GitHub：https://github.com/starring-ai-sec/star-ring-agent-sentinel
- 端到端示例：仓库 `langchain-starring/examples/demo.py`

---

*星环AI行为安全实验室 ｜ 2026-11*
