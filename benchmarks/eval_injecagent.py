#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""InjecAgent 评测：注入攻击链的拦截率 + 合法请求的误伤率。

用法：
    python benchmarks/eval_injecagent.py [--data-dir DIR]

数据来源：
    InjecAgent（UIUC, arXiv 2403.02691）— https://github.com/uiuc-kang-lab/InjecAgent

两个子集：
    - dh_base（Direct Harm, 510）：攻击者工具本身是危险动作（转账/开锁/改策略）
    - ds_base（Data Stealing, 544）：先读数据、再 GmailSendEmail 外发

评测口径（关键）：
    TPR（拦截率）：chain = [用户工具] + [攻击者工具]  → block/fuse 记为命中
    FPR（误伤率）：chain = [用户工具] 单独           → block/fuse 记为误伤
    同一批样本给出两个数字，才是可比的检测力。
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
sys.path.insert(0, _HERE)

import xh_engine  # noqa: E402
from tool_classifier import classify  # noqa: E402

RAW_BASE = "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/"
FILES = {"dh": "test_cases_dh_base.json", "ds": "test_cases_ds_base.json"}


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


def _judge(tools):
    mapped = []
    unknown = 0
    for t in tools:
        action, ok = classify(t)
        if not ok:
            unknown += 1
        mapped.append(action)
    chain = [{"action_type": a, "params": {}} for a in mapped]
    verdict = xh_engine.evaluate(chain)
    return {
        "chain": mapped,
        "decision": verdict["decision"],
        "blocked": verdict["decision"] in ("block", "fuse"),
        "unknown": unknown,
    }


def run(path):
    with io.open(path, encoding="utf-8") as fh:
        cases = json.load(fh)

    attacks, legit = [], []
    for idx, case in enumerate(cases):
        user_tool = case.get("User Tool") or ""
        attacker_tools = case.get("Attacker Tools") or []
        attack_tools = ([user_tool] if user_tool else []) + list(attacker_tools)

        a = _judge(attack_tools)
        a.update({"id": idx, "attack_type": case.get("Attack Type") or ""})
        attacks.append(a)

        if user_tool:
            g = _judge([user_tool])
            g.update({"id": idx, "tool": user_tool})
            legit.append(g)

    fp = hashlib.sha256(
        json.dumps(attacks, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return attacks, legit, fp


def summarize(name, attacks, legit):
    n = len(attacks)
    tpr = sum(1 for r in attacks if r["blocked"])
    fpr = sum(1 for r in legit if r["blocked"])
    m = len(legit)

    print("\n== %s ==" % name)
    print("  attack chains : %d" % n)
    print("  TPR (blocked) : %d/%d = %.1f%%" % (tpr, n, 100.0 * tpr / n))
    print("  legit requests: %d" % m)
    print("  FPR (blocked) : %d/%d = %.1f%%  ← 误伤" % (fpr, m, 100.0 * fpr / m if m else 0.0))
    if fpr:
        from collections import Counter
        bad = Counter(r["tool"] for r in legit if r["blocked"])
        print("  FP sources    : %s" % bad.most_common(5))
    return tpr, n, fpr, m


def main():
    ap = argparse.ArgumentParser(description="InjecAgent evaluation for Star-Ring engine")
    ap.add_argument("--data-dir", default=os.path.join(_HERE, ".injecagent_cache"))
    args = ap.parse_args()

    paths = ensure_data(args.data_dir)

    print("=" * 70)
    print("InjecAgent evaluation (Star-Ring rule engine) — TPR vs FPR")
    print("=" * 70)

    dh_a, dh_l, dh_fp = run(paths["dh"])
    ds_a, ds_l, ds_fp = run(paths["ds"])

    summarize("dh_base (Direct Harm)", dh_a, dh_l)
    summarize("ds_base (Data Stealing)", ds_a, ds_l)

    _, _, dh_fp2 = run(paths["dh"])
    _, _, ds_fp2 = run(paths["ds"])
    print("\nfingerprints:")
    print("  dh : %s (%s)" % (dh_fp, "byte-identical" if dh_fp == dh_fp2 else "MISMATCH"))
    print("  ds : %s (%s)" % (ds_fp, "byte-identical" if ds_fp == ds_fp2 else "MISMATCH"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
