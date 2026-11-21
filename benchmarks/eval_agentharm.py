#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AgentHarm 评测：有害样本拦截率（TPR） vs 良性对照误伤率（FPR）。

用法：
    python benchmarks/eval_agentharm.py [--data-dir DIR]

数据来源：
    AgentHarm 公开测试集（Gray Swan AI + UK AI Safety Institute, arXiv 2410.09024）
    https://huggingface.co/datasets/Sabriigsxr/AgentHarm

重要口径（读结果前必看）：
    AgentHarm 的 harmful / benign 是**同一工具序列、不同 prompt 内容**的配对样本。
    行为链引擎不读 prompt，只读动作序列——因此在这份数据上，
    TPR ≈ FPR 是结构性的必然结果，而不是调参失败。

    本脚本照实输出两个数字，用于说明「内容层评测集不适用于动作层引擎」，
    而不是用来宣称高拦截率。动作层的检测力请看 eval_injecagent.py。
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

HF_BASE = "https://huggingface.co/datasets/Sabriigsxr/AgentHarm/resolve/main/benchmark/"
FILES = {
    "harmful": "harmful_behaviors_test_public.json",
    "benign": "benign_behaviors_test_public.json",
}


def ensure_data(data_dir):
    os.makedirs(data_dir, exist_ok=True)
    paths = {}
    for key, fn in FILES.items():
        path = os.path.join(data_dir, fn)
        if not os.path.isfile(path):
            print("[download] %s" % fn)
            urllib.request.urlretrieve(HF_BASE + fn, path)
        paths[key] = path
    return paths


def run(path):
    with io.open(path, encoding="utf-8") as fh:
        behaviors = json.load(fh).get("behaviors", [])

    results = []
    for idx, b in enumerate(behaviors):
        tools = b.get("target_functions") or []
        mapped, unknown = [], 0
        for t in tools:
            action, ok = classify(t)
            if not ok:
                unknown += 1
            mapped.append(action)
        verdict = xh_engine.evaluate([{"action_type": a, "params": {}} for a in mapped])
        results.append({
            "id": str(b.get("id") or idx),
            "category": b.get("category") or "",
            "chain": mapped,
            "decision": verdict["decision"],
            "blocked": verdict["decision"] in ("block", "fuse"),
            "unknown": unknown,
        })
    fp = hashlib.sha256(
        json.dumps(results, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return results, fp


def summarize(name, results):
    total = len(results)
    blocked = sum(1 for r in results if r["blocked"])
    clean = [r for r in results if r["unknown"] == 0]
    print("\n== %s ==" % name)
    print("  cases            : %d" % total)
    print("  blocked          : %d/%d = %.1f%%"
          % (blocked, total, 100.0 * blocked / total if total else 0.0))
    if clean:
        cb = sum(1 for r in clean if r["blocked"])
        print("  全动作可识别子集 : %d/%d = %.1f%%"
              % (cb, len(clean), 100.0 * cb / len(clean)))
    return blocked, total


def main():
    ap = argparse.ArgumentParser(description="AgentHarm evaluation for Star-Ring engine")
    ap.add_argument("--data-dir", default=os.path.join(_HERE, ".agentharm_cache"))
    args = ap.parse_args()

    paths = ensure_data(args.data_dir)

    print("=" * 70)
    print("AgentHarm evaluation (Star-Ring rule engine) — TPR vs FPR")
    print("=" * 70)

    harmful, h_fp = run(paths["harmful"])
    benign, b_fp = run(paths["benign"])

    hb, hn = summarize("harmful (TPR)", harmful)
    fb, fn = summarize("benign  (FPR)", benign)

    print("\n-- 结论 --")
    print("  TPR = %.1f%%   FPR = %.1f%%"
          % (100.0 * hb / hn if hn else 0.0, 100.0 * fb / fn if fn else 0.0))
    print("  两者接近 ⇒ 本评测集对「动作层」引擎无区分力（harmful/benign 工具序列相同）")
    print("  动作层检测力请看 eval_injecagent.py")

    _, h_fp2 = run(paths["harmful"])
    _, b_fp2 = run(paths["benign"])
    print("\nfingerprints:")
    print("  harmful : %s (%s)" % (h_fp, "byte-identical" if h_fp == h_fp2 else "MISMATCH"))
    print("  benign  : %s (%s)" % (b_fp, "byte-identical" if b_fp == b_fp2 else "MISMATCH"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
