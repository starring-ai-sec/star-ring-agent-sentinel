# langchain-starring

> **A LangChain callback that blocks malicious agent tool-call chains.**
> Content moderation cares what the Agent *says* — this cares what the Agent *does*.

一个 LangChain 回调处理器：在工具执行前累积**行为链**，判定「每一步都合法、串起来就是攻击」的链式攻击（如 `read_sms → send_credentials`），命中即熔断。

## 为什么需要它

单步安全工具拦不住这条链：

```
read_sms          ← 读用户短信（客服的常规权限，白名单内）
send_credentials  ← 把验证码发出去
```

每一步都合法，串起来就是验证码外泄。传统基于单步规则的防护是盲区，`langchain-starring` 专注**行为链关联分析**。

## 安装

```bash
pip install langchain-starring
```

## 用法（零代码修改，一行挂载）

```python
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_openai import ChatOpenAI
from starring import StarRingCallbackHandler

agent = create_tool_calling_agent(ChatOpenAI(), tools, prompt)

executor = AgentExecutor(
    agent=agent,
    tools=tools,
    # 一行挂载，行为链危险时自动抛 StarRingBlockedError
    callbacks=[StarRingCallbackHandler()],
)

executor.invoke({"input": "帮我查一下退款"})
# 当 Agent 尝试 read_sms -> send_credentials 时，第二个工具调用抛出异常，验证码不外发
```

## 能力

| 能力 | 说明 |
|---|---|
| 行为链判定 | 累积最近 N 步工具调用，判「组合起来是否危险」 |
| 参数闸门 | 路径穿越、超额转账、域名黑名单、批量次数 |
| 未知动作熔断 | 幻觉出的工具名直接拒绝（fail-closed） |
| 自定义映射 | `action_map` 把自定义工具名映射到标准动作 |

## 配置

```python
handler = StarRingCallbackHandler(
    max_history=6,                          # 行为链最多保留 6 步
    action_map={"search_web": "external_http"},  # 工具名映射
    config={"amount_max": 5000, "path_deny": [".."]},  # 参数闸门阈值
    raise_on="block_fuse",                  # block 和 fuse 都熔断
)
```

## 与竞品的差异

`interven-langchain`、`iris-security`、`ActShield` 等方案主要做**单步**检测（这一句话有没有毒、这个工具危不危险）。`langchain-starring` 的差异化在于：

> 抓住「每一步都合法，但串联起来就是攻击」的复杂场景——这是单步规则覆盖不了的盲区。

## 更多

- 端到端示例：`examples/demo.py`
- 完整 CLI（离线自检 + 深度体检）：[star-ring-agent-sentinel](https://github.com/starring-ai-sec/star-ring-agent-sentinel)

---

MIT © 2026 Star-Ring AI Behavior Security Lab
