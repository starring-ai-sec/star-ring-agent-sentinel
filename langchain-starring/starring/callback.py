# -*- coding: utf-8 -*-
"""StarRingCallbackHandler：LangChain 行为链熔断回调。

在工具执行前（`on_tool_start`）累积行为链，交给星环规则引擎判定；
命中「凭据外泄 / 提权 / 文件外发」等组合链时抛 `StarRingBlockedError`，中断执行。

用法（零代码修改，只挂一个回调）：:

    from langchain.agents import AgentExecutor
    from starring import StarRingCallbackHandler

    executor = AgentExecutor(
        agent=agent, tools=tools,
        callbacks=[StarRingCallbackHandler()],
    )

只依赖 `langchain-core`（不依赖完整 langchain），可与 LangChain / LangGraph 任意版本共存。
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from langchain_core.callbacks import BaseCallbackHandler

#: 从自测包 src/ 引用规则引擎（作为独立 PyPI 包时，由依赖提供 xh_engine）
try:
    import xh_engine
except ImportError:  # pragma: no cover - 仓库内引用
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
    import xh_engine


class StarRingBlockedError(RuntimeError):
    """行为链被判定为危险时抛出，用于熔断工具执行。"""

    def __init__(self, decision: str, reasons: List[str], actions: List[str]) -> None:
        self.decision = decision
        self.reasons = reasons
        self.actions = actions
        chain = " → ".join(actions)
        super().__init__("[星环熔断] 行为链被拦截（%s）：%s ｜ 链：%s"
                         % (decision, "；".join(reasons), chain))


class StarRingCallbackHandler(BaseCallbackHandler):
    """LangChain 回调：累积工具调用序列，危险即熔断。

    参数
    ----
    max_history : int
        行为链最多保留多少步（超过则只保留最近 N 步），默认 6。
    action_map : dict
        自定义工具名 → 标准动作名映射，例如 ``{"search_web": "external_http"}``。
    config : dict
        透传给规则引擎的参数闸门配置（路径/金额/域名/次数阈值）。
    raise_on : {"block_fuse", "fuse"}
        何时熔断：默认 ``block_fuse``（拦截与熔断都抛异常）；``fuse`` 只在熔断时抛。
    """

    def __init__(
        self,
        max_history: int = 6,
        action_map: Optional[Dict[str, str]] = None,
        config: Optional[Dict[str, Any]] = None,
        raise_on: str = "block_fuse",
    ) -> None:
        super().__init__()
        self.max_history = max(1, int(max_history))
        self.action_map = dict(action_map or {})
        self.config = config
        self.raise_on = raise_on
        self.actions: List[Dict[str, Any]] = []

    # ── 工具名映射 ────────────────────────────────────────
    def _map_action(self, tool_name: str) -> str:
        return self.action_map.get(tool_name, tool_name)

    # ── 参数提取（尽力而为）────────────────────────────────
    @staticmethod
    def _extract_params(input_str: str) -> Dict[str, Any]:
        """从工具输入字符串里提取结构化参数（JSON 优先，键值对兜底）。"""
        if not input_str:
            return {}
        s = input_str.strip()
        try:
            obj = json.loads(s)
            return obj if isinstance(obj, dict) else {}
        except (json.JSONDecodeError, ValueError):
            pass
        params: Dict[str, Any] = {}
        for token in s.replace(",", " ").split():
            if "=" in token:
                k, v = token.split("=", 1)
                params[k.strip()] = v.strip()
        return params

    # ── 核心：工具执行前判定 ───────────────────────────────
    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        tool_name = str(serialized.get("name") or "unknown")
        action_type = self._map_action(tool_name)
        self.actions.append({
            "action_type": action_type,
            "params": self._extract_params(input_str or ""),
        })
        if len(self.actions) > self.max_history:
            self.actions = self.actions[-self.max_history:]

        verdict = xh_engine.evaluate(self.actions, self.config)
        decision = verdict["decision"]
        should_raise = (
            decision in ("block", "fuse") if self.raise_on == "block_fuse"
            else decision == "fuse"
        )
        if should_raise:
            raise StarRingBlockedError(
                decision, verdict["reasons"],
                [a["action_type"] for a in self.actions])

    # ── 会话重置 ──────────────────────────────────────────
    def reset(self) -> None:
        """清空累积的行为链（每次独立会话开始时调用）。"""
        self.actions = []
