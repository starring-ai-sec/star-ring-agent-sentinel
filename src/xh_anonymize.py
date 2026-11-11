# -*- coding: utf-8 -*-
"""日志脱敏：替换敏感值，保留行为链结构（动作类型 / 组合 / 参数键）。

设计原则
--------
- **脱敏的是"值"，不是"结构"**：`tool`、`action_type`、`params` 的键原样保留，
  只有字符串值里的敏感信息被替换——这样才能既保护隐私，又不丢行为判定的依据。
- **路径脱敏但保留穿越信号**：`../` 这类目录穿越特征必须保留（否则深度体检的
  路径穿越检测会失效），只替换具体目录名 / 文件名。
- 全程离线、本地完成，上传的是脱敏后的副本，原始日志永不离开本机。
"""

from __future__ import annotations

import re
from typing import Any

def _路径脱敏(m: re.Match) -> str:
    """路径整体替换，但保留 `..` 穿越信号。"""
    raw = m.group(0)
    ups = raw.count("..")
    if ups:
        return "../" * ups + "[路径]"
    return "[路径]"


# 敏感信息正则 → 占位符
_RULES = [
    # 手机号（中国大陆 11 位）
    (re.compile(r"1[3-9]\d{9}"), "[手机号]"),
    # 邮箱
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[邮箱]"),
    # IPv4
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP]"),
    # 身份证（18 位，末位可能 X）
    (re.compile(r"\b\d{17}[\dXx]\b"), "[身份证]"),
    # 银行卡 / 长数字序列（16-19 位）
    (re.compile(r"\b\d{16,19}\b"), "[卡号]"),
    # 通用 6 位以上数字串（令牌 / 验证码 / 账号，排除明显的时间戳靠前的规则先匹配）
    (re.compile(r"\b\d{6,15}\b"), "[数字]"),
    # 路径：含 / 或 \ 的连续串，相对/绝对都覆盖（Windows 盘符冒号保留）
    (re.compile(r"[\w.\-]+(?:[\\/]+[\w.\-]+)+"), _路径脱敏),
]


def anonymize_text(text: str) -> str:
    for pat, repl in _RULES:
        text = pat.sub(repl, text)
    return text


def anonymize_value(value: Any) -> Any:
    """递归脱敏：字符串替换，dict/list 递归，其余原样。"""
    if isinstance(value, str):
        return anonymize_text(value)
    if isinstance(value, dict):
        return {k: anonymize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [anonymize_value(x) for x in value]
    return value


def anonymize_record(record: dict) -> dict:
    """脱敏一条日志记录（保留结构，脱敏值）。"""
    return anonymize_value(record)


def anonymize_lines(text: str) -> str:
    """脱敏整个 JSONL 文本：逐行解析→脱敏→重序列化，保留每行结构。"""
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s:
            continue
        import json
        try:
            obj = json.loads(s)
            obj = anonymize_value(obj)
            out.append(json.dumps(obj, ensure_ascii=False))
        except json.JSONDecodeError:
            # 非 JSON 行原样保留（不因一行坏掉整批）
            out.append(s)
    return "\n".join(out)
