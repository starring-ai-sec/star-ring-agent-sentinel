# -*- coding: utf-8 -*-
"""星环 · Agent 行为自检引擎（分发包用的轻量规则版）。

为什么是「轻量规则版」而不是完整基座
----------------------------------
分发给客户的东西必须**不含核心资产**：
* 不含 177 条攻击样本库（这是可复现、可验证的护城河）
* 不含三轨模型权重
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
import re
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
    # 代码执行类：工具本身无风险（LOW），判定完全交给 payload 扫描
    # —— 若设为 MEDIUM，良性代码会全部落到「需确认」，等于没有放行（实测 FPR 假 0）
    "code_execution": (0.10, "LOW"), "code_interpreter": (0.10, "LOW"),
    "run_code": (0.10, "LOW"), "execute_code": (0.10, "LOW"),
    "python_exec": (0.10, "LOW"), "terminal": (0.10, "LOW"),
    "shell": (0.10, "LOW"), "bash": (0.10, "LOW"),
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
    "code_execution": "code", "code_interpreter": "code", "run_code": "code",
    "execute_code": "code", "python_exec": "code", "terminal": "code",
    "shell": "code", "bash": "code",
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

#: 有序行为链模式（共筑 BehaviorSequenceTracker 的「有序子序列匹配」机制落地）
#: 比「无序集合组合链」更精确：能表达动作的先后因果顺序（先读后发、先提权后读）
SEQUENCE_PATTERNS = [
    {"name": "凭据外泄链（有序）", "sequence": ["read_sms", "send_credentials"],
     "decision": "fuse", "desc": "先读短信/验证码，后外发凭据"},
    {"name": "验证码外泄链（有序）", "sequence": ["read_otp", "send_credentials"],
     "decision": "fuse", "desc": "先读验证码，后外发"},
    {"name": "提权读取链（有序）", "sequence": ["change_permission", "read_contacts"],
     "decision": "fuse", "desc": "先提权，后读通讯录"},
    {"name": "侦察外发链（有序）", "sequence": ["list_docs", "read_docs", "share_file"],
     "decision": "block", "desc": "先列出，再读取，后外发文件"},
]

#: 无序组合链规则（跨 turn 累积判定用：src 与 sink 同现即命中）
_CHAIN_RULES = [
    ("提权链", PRIVILEGE_OPS, PRIVILEGE_SINKS),
    ("文件外发链", {"share_file"}, {"external_http"}),
    ("凭据外泄链", {"read_sms", "read_otp", "read_contacts"},
     {"send_credentials", "external_http", "share_file"}),
]

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


def _match_sequence(types: List[str], sequence: List[str]) -> bool:
    """有序子序列匹配：types 是否包含 sequence 作为子序列（可跳过中间动作）。

    对应共筑 BehaviorSequenceTracker.subsequenceIndices 的机制——不要求连续，
    只要求按顺序出现（中间可以夹别的动作，如「read_sms → summarize → send_credentials」
    仍命中「read_sms → send_credentials」）。
    """
    p = 0
    for t in types:
        if t == sequence[p]:
            p += 1
            if p == len(sequence):
                return True
    return False


def _num(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


#: 代码执行类动作（payload 需单独扫描，不能只看 action_type）
CODE_ACTIONS = {"code_execution", "code_interpreter", "run_code", "execute_code",
                "python_exec", "terminal", "shell", "bash"}

#: 代码 payload 可能出现的键名
_CODE_KEYS = ("code", "script", "source", "command", "cmd", "payload", "expression")

#: 恶意 payload 特征（命中即 block）：命令执行、原始套接字、符号直调、动态属性拼接
_CODE_HOSTILE = (
    (r"os\.system\s*\(", "os.system 命令执行"),
    (r"os\.popen\s*\(", "os.popen 命令执行"),
    (r"subprocess\.\w+\s*\([^)]*(?:curl|wget|nc\b|ncat|nmap|/bin/sh|/bin/bash|powershell)",
     "subprocess 调用下载/反弹工具"),
    (r"ctypes\.(?:CDLL|WinDLL|cdll|windll)[^\n]{0,80}\.system\s*\(", "ctypes 直调 system"),
    (r"\.system\s*\(\s*b?['\"]", "system() 调用"),
    (r"\.connect\s*\(", "原始套接字 connect"),
    (r"getattr\s*\([^)]*\+", "getattr 字符串拼接（绕过关键字扫描）"),
    (r"(?:exec|eval)\s*\(\s*(?:base64|bytes\.fromhex|__import__|codecs\.decode)",
     "动态执行编码载荷"),
    (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "payload 内出现原始 IP 地址"),
)

#: 一般出网特征（命中 → confirm，需人工确认；不直接熔断，避免误杀正常 API 调用）
_CODE_EGRESS = (
    (r"requests\.(?:get|post|put|delete|head|patch|request)\s*\(", "requests 出网"),
    (r"urllib\.(?:request|urlopen)", "urllib 出网"),
    (r"http\.client", "http.client 出网"),
    (r"\bfetch\s*\(", "fetch 出网"),
)


def _code_payload(params: Dict[str, Any]) -> str:
    """取代码执行类动作的 payload 文本（多键兜底；非字符串忽略）。"""
    for key in _CODE_KEYS:
        val = params.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return ""


def _scan_code_payload(params: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """扫描代码 payload，返回 (恶意特征, 一般出网特征)。

    设计取舍：原始套接字 / 命令执行 / 符号直调一律判恶意；
    普通 HTTP 客户端（无法区分正常 API 与 C2）只降级为「需确认」，
    因为把它当熔断会让正常业务代码全部阵亡 —— 这正是「引导优于熔断」的落地。
    """
    code = _code_payload(params)
    if not code:
        return [], []
    hostile, soft = [], []
    for pattern, label in _CODE_HOSTILE:
        if re.search(pattern, code):
            hostile.append(label)
    for pattern, label in _CODE_EGRESS:
        if re.search(pattern, code):
            soft.append(label)
    return hostile, soft


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


def new_session_state() -> Dict[str, Any]:
    """新建会话级状态：跨 turn 累积动作集合，不丢历史（取代「6 步滑动窗口」）。"""
    return {"actions_seen": set()}


def evaluate(actions: List[Dict[str, Any]], cfg: Optional[Dict[str, Any]] = None,
             session_state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """评估一条行为链，返回裁决 + 标注 + 依据。

    session_state：可选，跨 turn 累积的动作集合。传入后组合链改为「会话级」判定——
    本次窗口命中为强信号（fuse/block），跨 turn 累积命中为弱信号（confirm 需复核）。
    """
    conf = dict(DEFAULT_CONFIG)
    conf.update(cfg or {})
    exempt = set(str(x) for x in (conf.get("exempt_ops") or []))

    types = [str(a.get("action_type") or a.get("tool") or "") for a in actions]
    params_list = [dict(a.get("params") or {}) for a in actions]
    reasons: List[str] = []

    # 空行为链：无可判定对象，放行（否则下方 max 会因空序列崩溃）
    if not types:
        return {"decision": "allow", "mark": "", "reasons": ["空行为链"], "types": []}

    # 会话累积集合（跨 turn）：本次动作并入，得到「整个会话见过的动作」
    type_set = set(types)
    if session_state is not None:
        session_state.setdefault("actions_seen", set()).update(type_set)
        cum_set = session_state["actions_seen"]
    else:
        cum_set = type_set

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

    # ②b 代码 payload 扫描（代码执行工具本身合法，payload 不一定合法）
    code_soft: List[str] = []
    for action_type, params in zip(types, params_list):
        if action_type not in CODE_ACTIONS or action_type in exempt:
            continue
        hostile, soft = _scan_code_payload(params)
        if hostile:
            return {"decision": "block", "mark": MARK_CONFIRM,
                    "reasons": ["代码 payload 命中出网/命令执行：%s（动作 %s）"
                                % ("、".join(hostile), action_type)],
                    "types": types}
        if not _code_payload(params):
            # 代码执行但拿不到 payload：无从核验，不能默认放行（降级为需确认）
            code_soft.append("payload 缺失，无法核验")
        code_soft.extend(soft)

    # ③a 有序行为链（共筑 BehaviorSequenceTracker 机制落地：有序子序列匹配）
    for pat in SEQUENCE_PATTERNS:
        if _match_sequence(types, pat["sequence"]):
            return {"decision": pat["decision"], "mark": MARK_CONFIRM,
                    "reasons": ["有序行为链（%s）：%s"
                                % (pat["name"], " → ".join(pat["sequence"]))],
                    "types": types}

    # ③ 组合链（跨 turn 累积：本次窗口同时命中=强 fuse，跨 turn 命中=弱 confirm）
    for name, src_set, sink_set in _CHAIN_RULES:
        hit_src = src_set & cum_set
        hit_sink = sink_set & cum_set
        if hit_src and hit_sink:
            strong = bool(src_set & type_set and sink_set & type_set)
            decision = "fuse" if strong else "confirm"
            mark = MARK_CONFIRM if strong else MARK_REVIEW
            reason = "%s：%s + %s" % (name, sorted(hit_src), sorted(hit_sink))
            if not strong:
                reason += "（跨 turn 累积，需复核）"
            return {"decision": decision, "mark": mark, "reasons": [reason], "types": types}

    # ④ 单动作风险（取最高）
    levels = []
    for action_type in types:
        if action_type in exempt:
            levels.append((0.10, "LOW"))
            continue
        levels.append(ACTION_RISK.get(action_type, (0.5, "MEDIUM")))
    worst_level = max((lv for _score, lv in levels),
                      key=lambda x: DECISION_ORDER.index(
                          {"LOW": "allow", "MEDIUM": "confirm",
                           "HIGH": "block", "CRITICAL": "fuse"}[x]))
    decision = {"LOW": "allow", "MEDIUM": "confirm",
                "HIGH": "block", "CRITICAL": "fuse"}[worst_level]
    reasons.append("最高动作等级 %s" % worst_level)

    # 代码 payload 含一般出网调用：不熔断，但降级为「需确认」（引导优于熔断）
    if code_soft and decision == "allow":
        decision = "confirm"
        reasons.append("代码 payload 含出网调用（%s），需确认"
                       % "、".join(sorted(set(code_soft))))

    # 标注：HIGH 级单动作若无组合证据 → 需复核；MEDIUM → 需复核；LOW → 放行
    mark = MARK_CONFIRM if decision in ("block", "fuse") else (
        MARK_REVIEW if decision == "confirm" else "")
    return {"decision": decision, "mark": mark, "reasons": reasons, "types": types}
