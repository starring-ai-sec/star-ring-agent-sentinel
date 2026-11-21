# -*- coding: utf-8 -*-
"""第三方评测集的工具名 → 星环动作 分类器（供 eval_agentharm / eval_injecagent 共用）。

设计要点：
    不用子串匹配（`EvernoteManagerSearchNotes` 会被 "Manage" 误判成提权），
    而是先分词（CamelCase + snake_case），再取**第一个已知动词**决定动作。

已知局限（诚实声明）：
    - 启发式规则，不是语义理解；工具命名不规范时会退化为 fail-closed；
    - 模糊动词（login/connect/schedule）一律归低危 `organize`，
      宁可少拦也不虚增拦截率——拦截率的分子不能靠分类器的激进映射堆出来。
"""

import re

#: 动词 → 星环动作（同一动词只归一类）
VERB_ACTIONS = {
    # 破坏性
    "delete": "delete_bulk",
    "remove": "delete_bulk",
    # 权限与高危
    "unlock": "change_permission",
    "grant": "change_permission",
    "create": "change_permission",
    "update": "change_permission",
    "disable": "change_permission",
    "manage": "change_permission",
    "change": "change_permission",
    "dispatch": "change_permission",
    "login": "change_permission",
    # 金融
    "pay": "transfer",
    "transfer": "transfer",
    "withdraw": "transfer",
    "deposit": "transfer",
    "purchase": "transfer",
    "purchases": "transfer",
    "order": "transfer",
    # 外发
    "send": "external_http",
    "share": "external_http",
    "upload": "external_http",
    "post": "external_http",
    "publish": "external_http",
    "comment": "external_http",
    "dm": "external_http",
    "reply": "external_http",
    # 敏感读取
    "autofill": "read_contacts",
    # 读取
    "read": "read_docs",
    "search": "read_docs",
    "get": "read_docs",
    "view": "read_docs",
    "list": "read_docs",
    "fetch": "read_docs",
    "query": "read_docs",
    "download": "read_docs",
    "navigate": "read_docs",
    "access": "read_docs",
    "extract": "read_docs",
    "scrape": "read_docs",
    "export": "read_docs",
    # 低风险（明确归低危，避免被 fail-closed 误算成「拦截成功」或误算成误伤）
    "move": "organize",
    "leave": "organize",
    "generate": "organize",
    "schedule": "organize",
    "go": "organize",
    "fill": "organize",
    "edit": "organize",
    "submit": "organize",
    "follow": "organize",
    "repost": "organize",
    "report": "organize",
    "verify": "organize",
    "log": "organize",
    "connect": "organize",
    "make": "organize",
}

_TOKEN_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+")


def tokenize(tool_name):
    """CamelCase / snake_case → 小写 token 列表。"""
    out = []
    for part in str(tool_name).split("_"):
        out.extend(t.lower() for t in _TOKEN_RE.findall(part))
    return out


def classify(tool_name):
    """返回 (星环动作名, 是否识别)。识别失败时原样返回工具名（引擎走 fail-closed）。"""
    for token in tokenize(tool_name):
        action = VERB_ACTIONS.get(token)
        if action:
            return action, True
    return str(tool_name), False
