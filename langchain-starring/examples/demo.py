# -*- coding: utf-8 -*-
"""端到端演示：StarRingCallbackHandler 拦截「合法但恶意」的工具调用链。

不依赖完整 langchain，直接用回调基类模拟工具调用序列，验证：
1. 正常链 read_docs → summarize 放行；
2. 凭据外泄链 read_sms → send_credentials 熔断（抛异常）。

真实 LangChain 用法见文件底部注释。
"""

from __future__ import annotations

import os
import sys

# 让 demo 能 import starring 与 xh_engine
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, ".."))            # starring 包
sys.path.insert(0, os.path.join(_HERE, "..", "..", "src"))  # xh_engine

from starring import StarRingBlockedError, StarRingCallbackHandler


def simulate(handler: StarRingCallbackHandler, tool_name: str,
             input_str: str = "") -> str:
    """模拟一次工具调用：走 on_tool_start，危险则抛异常。"""
    try:
        handler.on_tool_start({"name": tool_name}, input_str)
        return "放行"
    except StarRingBlockedError as exc:
        return "熔断: " + str(exc)


def main() -> None:
    print("=" * 66)
    print("场景 1：正常链路 read_docs -> summarize")
    print("=" * 66)
    h1 = StarRingCallbackHandler()
    for tool in ("read_docs", "summarize"):
        print("  调用 %-16s -> %s" % (tool, simulate(h1, tool)))

    print()
    print("=" * 66)
    print("场景 2：凭据外泄链 read_sms -> send_credentials")
    print("=" * 66)
    h2 = StarRingCallbackHandler()
    for tool in ("read_sms", "send_credentials"):
        print("  调用 %-16s -> %s" % (tool, simulate(h2, tool)))

    print()
    print("=" * 66)
    print("场景 3：路径穿越 read_docs(\"../../etc/passwd\")")
    print("=" * 66)
    h3 = StarRingCallbackHandler()
    print("  调用 %-16s -> %s"
          % ("read_docs", simulate(h3, "read_docs", '{"path":"../../etc/passwd"}')))


# ── 真实 LangChain 用法（需要 pip install langchain langchain-openai）──
#
# from langchain.agents import AgentExecutor, create_tool_calling_agent
# from langchain_core.prompts import ChatPromptTemplate
# from starring import StarRingCallbackHandler
#
# executor = AgentExecutor(
#     agent=agent,
#     tools=[read_sms_tool, send_credentials_tool, ...],
#     callbacks=[StarRingCallbackHandler()],   # 一行挂载，零代码修改
# )
# executor.invoke({"input": "帮我查退款"})
# # 当 Agent 尝试 read_sms -> send_credentials 时，第二个工具调用会抛出
# # StarRingBlockedError，阻止验证码外发。

if __name__ == "__main__":
    main()
