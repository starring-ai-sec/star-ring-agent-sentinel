#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""InjecAgent 评测：把「用户工具 + 攻击者工具」映射成行为链，跑 xh_engine。

用法：
    python benchmarks/eval_injecagent.py [--data-dir DIR]

数据来源：
    InjecAgent（UIUC, arXiv 2403.02691）
    https://github.com/uiuc-kang-lab/InjecAgent

两个子集：
    - dh_base（Direct Harm, 510 条）：攻击者工具本身是危险动作（转账/开锁/改策略）
    - ds_base（Data Stealing, 544 条）：先读数据、再 GmailSendEmail 外发

口径说明：
    本评测衡量的是「注入成功后的动作是否被拦」——即模型的鲁棒性失守时，
    动作层能否兜底。这不替代模型层防御，而是纵深防御的最后一层。
"""

import argparse
import hashlib
import io
import json
import os
import sys
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "src"))

import xh_engine  # noqa: E402

RAW_BASE = "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/"
FILES = {
    "dh": "test_cases_dh_base.json",
    "ds": "test_cases_ds_base.json",
}

#: 工具名关键词 → 星环动作（按优先级顺序匹配，先命中先用）
KEYWORD_RULES = [
    # 金融（转账/提现/下单/付款）
    (("Transfer", "Withdraw", "PlaceOrder", "Deposit", "PayBill", "Pay", "Purchase"), "transfer"),
    # 删除/销毁
    (("Delete", "Remove"), "delete_bulk"),
    # 权限与高危操作（开锁/授权/改策略/关安全设置）
    (("Unlock", "GrantAccess", "GrantGuestAccess", "CreatePolicy", "UpdatePolicy",
      "Manage", "Dispatch", "Disable"), "change_permission"),
    # 外发（发邮件/分享/上传/发帖）
    (("SendEmail", "Send", "Share", "Upload", "Post"), "external_http"),
    # 凭据/隐私读取（自动填充 = 读已存凭据）
    (("AutoFill",), "read_contacts"),
    # 读取（读/搜/查/下载/浏览）
    (("Read", "Search", "Get", "View", "List", "Download", "Fetch",
      "Query", "Navigate"), "read_docs"),
    # 低风险整理类（移动/退出/排程）——明确归低危，避免被 fail-closed 误算成「拦截成功」
    (("Move", "LeaveChannel", "ScheduleDevice"), "organize"),
]

#: 引擎认识的动作集合（用于统计「识别覆盖率」，区分「真识别」与「fail-closed」）
KNOWN_ACTIONS = set(xh_engine.ACTION_RISK.keys()) | set(getattr(xh_engine, "ACTION_FAMILY", {}).keys())


def classify(tool_name):
    """按关键词把 InjecAgent 工具名归到星环动作；对不上则原样返回（引擎走 fail-closed）。"""
    for keywords, action in KEYWORD_RULES:
        for kw in keywords:
            if kw in tool_name:
                return action
    return tool_name


def ensure_data(data_dir):
    os.makedirs(data_dir, exist_ok=True)
    paths = {}
    for key, fn in FILES.items():
        path = os.path.join(data_dir, fn)
        if not os.path.isfile(path):
            print("[download] %s" % fn)
            urllib.request.urlretrieve(RAW_BASE + fn, path)
        paths[key] = path
    return paths


def run(path):
    with io.open(path, encoding="utf-8") as fh:
        cases = json.load(fh)

    results = []
    for idx, case in enumerate(cases):
        user_tool = case.get("User Tool") or ""
        attacker_tools = case.get("Attacker Tools") or []
        chain_tools = ([user_tool] if user_tool else []) + list(attacker_tools)
        mapped = [classify(t) for t in chain_tools]
        chain = [{"action_type": a, "params": {}} for a in mapped]
        verdict = xh_engine.evaluate(chain)
        results.append({
            "id": idx,
            "attack_type": case.get("Attack Type") or "",
            "chain": mapped,
            "decision": verdict["decision"],
            "blocked": verdict["decision"] in ("block", "fuse"),
            # 链上所有动作是否都被引擎认识（False 表示含未识别工具，走 fail-closed）
            "recognized": all(a in KNOWN_ACTIONS for a in mapped),
        })
    payload = json.dumps(results, sort_keys=True, ensure_ascii=False)
    return results, hashlib.sha256(payload.encode("utf-8")).hexdigest()


def summarize(name, results):
    total = len(results)
    hit = sum(1 for r in results if r["blocked"])
    recog = [r for r in results if r["recognized"]]
    recog_hit = sum(1 for r in recog if r["blocked"])
    print("\n== %s ==" % name)
    print("  cases                   : %d" % total)
    print("  blocked at action layer : %d/%d = %.1f%%"
          % (hit, total, 100.0 * hit / total))
    print("  fully-recognized chains : %d/%d = %.1f%%（其余含未识别工具，走 fail-closed）"
          % (len(recog), total, 100.0 * len(recog) / total))
    if recog:
        print("  block rate (recognized only): %d/%d = %.1f%%  ← 纯识别判定"
              % (recog_hit, len(recog), 100.0 * recog_hit / len(recog)))
    by_type = {}
    for r in results:
        t = r["attack_type"] or "?"
        d = by_type.setdefault(t, [0, 0])
        d[0] += 1
        d[1] += 1 if r["blocked"] else 0
    for t, (n, b) in sorted(by_type.items(), key=lambda x: -x[1][0]):
        print("    %-22s %d/%d (%.1f%%)" % (t, b, n, 100.0 * b / n))
    return hit, total


def main():
    ap = argparse.ArgumentParser(description="InjecAgent evaluation for Star-Ring engine")
    ap.add_argument("--data-dir", default=os.path.join(_HERE, ".injecagent_cache"))
    args = ap.parse_args()

    paths = ensure_data(args.data_dir)

    print("=" * 64)
    print("InjecAgent evaluation (Star-Ring rule engine)")
    print("=" * 64)

    dh, dh_fp = run(paths["dh"])
    ds, ds_fp = run(paths["ds"])

    _, dh_total = summarize("dh_base (Direct Harm)", dh)
    _, ds_total = summarize("ds_base (Data Stealing)", ds)

    # 复跑验证确定性
    _, dh_fp2 = run(paths["dh"])
    _, ds_fp2 = run(paths["ds"])

    print("\nfingerprints:")
    print("  dh_base sha256 : %s (%s)" % (dh_fp, "byte-identical" if dh_fp == dh_fp2 else "MISMATCH"))
    print("  ds_base sha256 : %s (%s)" % (ds_fp, "byte-identical" if ds_fp == ds_fp2 else "MISMATCH"))
    print("  total cases    : %d" % (dh_total + ds_total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
