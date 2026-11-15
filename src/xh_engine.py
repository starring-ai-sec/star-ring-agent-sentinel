# -*- coding: utf-8 -*-
"""星环 · Agent 行为自检引擎（分发包用的轻量规则版）。

为什么是「轻量规则版」而不是完整基座
----------------------------------
分发给客户的东西必须**不含核心资产**：
* 不含 177 条攻击样本库（这是可复现、可验证的护城河）
* 不含三轨模型权重（48 维 / 16 维）
* 不含真神领域台与红队剧本

所以这里只保留**规则层**：动作风险 + 参数闸门 + 组合链 + 未知动作 fail-closed。
这足以做「初筛」，且逆向出来也只拿到规则，拿不到样本与模型。

判定顺序（任一命中即停）
-----------------------
1. 未知动作      → 拒绝（模型幻觉出的工具名）
2. 参数越界      → 拒绝（路径穿越 / 超额 / 非白名单域名 / 批量次数）
3. 组合链        → 提权后敏感、外发链
4. 单动作风险    → LOW 放行 / MEDIUM 确认 / HIGH 拦截 / CRITICAL 熔断
"""

from __future__ import annotations

import fnmatch
import posixpath
from typing import Any, Dict, List, Optional, Tuple

#: 动作风险表（与基座 agent_guard.ACTION_RISK + 扩展表口径一致）
ACTION_RISK: Dict[str, Tuple[float, str]] = {
    "read_screen": (0.05, "LOW"), "open_app": (0.10, "LOW"), "organize": (0.10, "LOW"),
    "read_docs": (0.05, "LOW"), "summarize": (0.05, "LOW"), "list_docs": (0.05, "LOW"),
    "send_report": (0.30, "MEDIUM"),
    "send_message": (0.30, "MEDIUM"), "read_location": (0.40, "MEDIUM"),
    "invoke_agent_tool": (0.50, "MEDIUM"),
    "read_contacts": (0.55, "HIGH"), "share_file": (0.60, "HIGH"),
    "read_sms": (0.60, "HIGH"), "change_permission": (0.70, "HIGH"),
    "external_http": (0.70, "HIGH"), "read_otp": (0.80, "HIGH"),
    "delete_bulk": (0.85, "CRITICAL"), "payment": (0.90, "CRITICAL"),
    "transfer": (0.95, "CRITICAL"), "send_credentials": (0.98, "CRITICAL"),
    "sandbox_read_outside": (0.85, "CRITICAL"), "access_other_process": (0.85, "CRITICAL"),
    "restricted_syscall": (0.85, "CRITICAL"), "port_scan": (0.80, "CRITICAL"),
    "accessibility_bypass": (0.85, "CRITICAL"), "automation_batch_click": (0.85, "CRITICAL"),
    "recursive_loop": (0.75, "HIGH"), "sensor_battery_drain": (0.70, "HIGH"),
    "bulk_message": (0.60, "HIGH"), "root": (0.90, "CRITICAL"),
    "escalate": (0.88, "CRITICAL"), "sudo": (0.85, "CRITICAL"), "chmod": (0.75, "HIGH"),
}

#: 动作族（用于「换个同族动作名」的链判定）
FAMILY = {
    "transfer": "finance", "payment": "finance", "read_otp": "finance",
    "external_http": "egress", "share_file": "egress", "send_credentials": "egress",
    "change_permission": "privilege", "escalate": "privilege", "root": "privilege",
    "sudo": "privilege", "chmod": "privilege", "accessibility_bypass": "privilege",
    "read_contacts": "collect", "read_sms": "collect", "read_screen": "collect",
    "read_location": "collect", "read_docs": "collect",
    "sandbox_read_outside": "escape", "access_other_process": "escape",
    "restricted_syscall": "escape", "port_scan": "escape",
    "recursive_loop": "exhaust", "sensor_battery_drain": "exhaust",
    "automation_batch_click": "automation", "bulk_message": "automation",
}

_FAMILY_PREFIX = (
    ("read_", "collect"), ("get_", "collect"), ("list_", "collect"),
    ("send_", "egress"), ("share_", "egress"), ("external_", "egress"),
    ("upload_", "egress"), ("export_", "egress"),
    ("change_", "privilege"), ("grant_", "privilege"), ("set_perm", "privilege"),
    ("sandbox_", "escape"), ("transfer", "finance"), ("pay", "finance"),
    ("automation_", "automation"), ("bulk_", "automation"),
)

PRIVILEGE_OPS = {"change_permission", "escalate", "root", "sudo", "chmod"}
PRIVILEGE_SINKS = {"read_contacts", "read_sms", "read_location", "external_http",
                   "share_file", "send_credentials", "read_otp"}

DECISION_ORDER = ["allow", "confirm", "block", "fuse"]

#: 默认参数闸门（客户可用 config.json 覆盖）
DEFAULT_CONFIG = {
    # 路径禁用片段：穿越 + 系统目录 + 敏感凭据文件（防「半恶意」夹带读 .env / 私钥）
    "path_deny": ["..", "/etc/", "~/", "C:\\Windows",
                  ".env", ".ssh", "id_rsa", ".pem", ".key",
                  "secret", "password", "credential",
                  ".git/config", ".npmrc", ".aws/"],
    "amount_max": 5000,
    "domain_deny": ["attacker", "evil.", "example.com", "pastebin", "tmpfiles"],
    "count_max": 50,
    "exempt_ops": [],
}

#: 输出标注（三色）
MARK_CONFIRM = "【确认拦截】"
MARK_REVIEW = "【需复核】"
MARK_FALSE = "【疑似误报】"


def family_of(op: str) -> str:
    if op in FAMILY:
        return FAMILY[op]
    for prefix, fam in _FAMILY_PREFIX:
        if op.startswith(prefix):
            return fam
    if op.endswith("_loop"):
        return "exhaust"
    return op


def _num(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _check_params(action_type: str, params: Dict[str, Any], cfg: Dict[str, Any]) -> List[str]:
    """参数闸门：返回违规描述列表。"""
    out: List[str] = []
    raw_path = str(params.get("path") or params.get("target") or "")
    if raw_path:
        norm = posixpath.normpath(raw_path.replace("\\", "/"))
        for bad in cfg.get("path_deny") or []:
            if str(bad) in raw_path.replace("\\", "/") or str(bad) in norm:
                out.append("路径命中禁用片段 %r（%s）" % (bad, raw_path))
                break

    if action_type in ("transfer", "payment"):
        amount = _num(params.get("amount"))
        limit = float(cfg.get("amount_max") or 0)
        if amount is None:
            out.append("金额缺失或非数字，无法确认在额度内")
        elif limit and amount > limit:
            out.append("金额 %.2f 超过上限 %.2f" % (amount, limit))

    target = str(params.get("to") or params.get("url") or params.get("domain") or "")
    if target:
        low = target.lower()
        for bad in cfg.get("domain_deny") or []:
            if str(bad).lower() in low:
                out.append("目标域名命中禁用片段 %r（%s）" % (bad, target))
                break

    if action_type in ("automation_batch_click", "bulk_message"):
        count = _num(params.get("count"))
        limit = float(cfg.get("count_max") or 0)
        if count is not None and limit and count > limit:
            out.append("次数 %.0f 超过上限 %.0f" % (count, limit))
    return out


def evaluate(actions: List[Dict[str, Any]], cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """评估一条行为链，返回裁决 + 标注 + 依据。"""
    conf = dict(DEFAULT_CONFIG)
    conf.update(cfg or {})
    exempt = set(str(x) for x in (conf.get("exempt_ops") or []))

    types = [str(a.get("action_type") or a.get("tool") or "") for a in actions]
    params_list = [dict(a.get("params") or {}) for a in actions]
    reasons: List[str] = []

    # 空行为链：无可判定对象，放行（否则下方 max 会因空序列崩溃）
    if not types:
        return {"decision": "allow", "mark": "", "reasons": ["空行为链"], "types": []}

    # ① 未知动作 fail-closed
    unknowns = [t for t in types if t and t not in ACTION_RISK and family_of(t) == t]
    if unknowns:
        return {"decision": "block", "mark": MARK_CONFIRM,
                "reasons": ["未知动作（fail-closed）：%s" % ",".join(sorted(set(unknowns)))],
                "types": types}

    # ② 参数闸门
    for action_type, params in zip(types, params_list):
        if action_type in exempt:
            continue
        for problem in _check_params(action_type, params, conf):
            reasons.append("%s：%s" % (action_type, problem))
    if reasons:
        return {"decision": "block", "mark": MARK_CONFIRM,
                "reasons": reasons, "types": types}

    # ③ 组合链
    type_set = set(types)
    if PRIVILEGE_OPS & type_set and PRIVILEGE_SINKS & type_set:
        return {"decision": "fuse", "mark": MARK_CONFIRM,
                "reasons": ["提权链：%s + %s"
                            % (sorted(PRIVILEGE_OPS & type_set),
                               sorted(PRIVILEGE_SINKS & type_set))],
                "types": types}
    if {"share_file", "external_http"} <= type_set:
        return {"decision": "fuse", "mark": MARK_CONFIRM,
                "reasons": ["文件外发链：share_file + external_http"], "types": types}
    # 凭据外泄链：读取短信/验证码/通讯录 → 外发
    cred_src = {"read_sms", "read_otp", "read_contacts"} & type_set
    cred_sink = {"send_credentials", "external_http", "share_file"} & type_set
    if cred_src and cred_sink:
        return {"decision": "fuse", "mark": MARK_CONFIRM,
                "reasons": ["凭据外泄链：%s → %s"
                            % (sorted(cred_src), sorted(cred_sink))], "types": types}

    # ④ 单动作风险（取最高）
    levels = []
    for action_type in types:
        if action_type in exempt:
            levels.append(("LOW", 0.10))
            continue
        levels.append(ACTION_RISK.get(action_type, (0.5, "MEDIUM")))
    worst_level = max((lv for _score, lv in levels),
                      key=lambda x: DECISION_ORDER.index(
                          {"LOW": "allow", "MEDIUM": "confirm",
                           "HIGH": "block", "CRITICAL": "fuse"}[x]))
    decision = {"LOW": "allow", "MEDIUM": "confirm",
                "HIGH": "block", "CRITICAL": "fuse"}[worst_level]
    reasons.append("最高动作等级 %s" % worst_level)

    # 标注：HIGH 级单动作若无组合证据 → 需复核；MEDIUM → 需复核；LOW → 放行
    mark = MARK_CONFIRM if decision in ("block", "fuse") else (
        MARK_REVIEW if decision == "confirm" else "")
    return {"decision": decision, "mark": mark, "reasons": reasons, "types": types}
