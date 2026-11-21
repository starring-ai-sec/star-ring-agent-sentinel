#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AgentHarm 评测：把 target_functions 映射到星环动作，跑 xh_engine，统计拦截率。

用法：
    python benchmarks/eval_agentharm.py [--data-dir DIR]

数据来源：
    AgentHarm 公开测试集（Gray Swan AI + UK AI Safety Institute）
    https://huggingface.co/datasets/Sabriigsxr/AgentHarm

说明：
    - 数据集缺失时自动下载（首次运行需联网，之后离线可跑）；
    - AgentHarm 的 harmful/benign 靠 prompt 内容区分，工具序列高度重叠，
      因此本脚本只统计「工具序列层面的拦截率」，不把 benign 当误报率样本。
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

HF_BASE = "https://huggingface.co/datasets/Sabriigsxr/AgentHarm/resolve/main/benchmark/"
FILES = ["harmful_behaviors_test_public.json", "benign_behaviors_test_public.json"]

#: AgentHarm 工具名 → 星环标准动作（前缀规则覆盖不了的部分显式映射）
TOOL_MAP = {
    # 外发（社交发布 / 邮件 / 上传）
    "post_on_x": "external_http",
    "post_on_facebook": "external_http",
    "post_on_instagram": "external_http",
    "post_x_reply": "external_http",
    "post_to_blog": "external_http",
    "create_instagram_post": "external_http",
    "create_instagram_story": "external_http",
    "send_email": "external_http",
    # 读取（搜索 / 下载 / 读邮件）
    "query_google_search": "read_docs",
    "query_bing_search": "read_docs",
    "query_onion_search": "read_docs",
    "query_posts_on_x": "read_docs",
    "download_image": "read_docs",
    "download_file": "read_docs",
    "download_pdf": "read_docs",
    "get_webpage": "read_docs",
    "get_latest_emails": "read_docs",
    # 终端执行（高危）
    "terminal": "change_permission",
    # 生成 / 转换（低危）
    "run_stable_diffusion_model": "read_docs",
    "create_ai_video": "read_docs",
    "convert_pdf_to_text": "read_docs",
    "convert_text_to_pdf": "read_docs",
    # 金融转账
    "transfer_money": "transfer",
    "transfer_money_crypto": "transfer",
    "paypal_transfer": "transfer",
    # 通讯录 / 私信
    "get_friends_info": "read_contacts",
    "send_message_whatsapp": "send_credentials",
    "send_direct_message_instagram": "send_credentials",
}


def ensure_data(data_dir):
    os.makedirs(data_dir, exist_ok=True)
    for fn in FILES:
        path = os.path.join(data_dir, fn)
        if os.path.isfile(path):
            continue
        print("[download] %s" % fn)
        urllib.request.urlretrieve(HF_BASE + fn, path)
    return {fn: os.path.join(data_dir, fn) for fn in FILES}


def map_action(tool):
    return TOOL_MAP.get(tool, tool)  # 未映射的交给 xh_engine 前缀规则


def load_behaviors(path):
    with io.open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("behaviors", data)


def run(path):
    """返回 (结果列表, 指纹)。结果列表顺序固定，指纹用于验证确定性。"""
    results = []
    for idx, b in enumerate(load_behaviors(path)):
        funcs = b.get("target_functions") or []
        chain = [{"action_type": map_action(f), "params": {}} for f in funcs]
        verdict = xh_engine.evaluate(chain)
        results.append({
            "id": str(b.get("id") or idx),
            "category": b.get("category") or "",
            "chain": [map_action(f) for f in funcs],
            "decision": verdict["decision"],
            "blocked": verdict["decision"] in ("block", "fuse"),
        })
    payload = json.dumps(results, sort_keys=True, ensure_ascii=False)
    return results, hashlib.sha256(payload.encode("utf-8")).hexdigest()


def main():
    ap = argparse.ArgumentParser(description="AgentHarm evaluation for Star-Ring engine")
    ap.add_argument("--data-dir", default=os.path.join(_HERE, ".agentharm_cache"),
                    help="dataset cache directory (auto-downloaded if missing)")
    args = ap.parse_args()

    paths = ensure_data(args.data_dir)
    harmful, fp_a = run(paths["harmful_behaviors_test_public.json"])

    hit = sum(1 for r in harmful if r["blocked"])
    total = len(harmful)

    print("=" * 60)
    print("AgentHarm evaluation (Star-Ring rule engine)")
    print("=" * 60)
    print("harmful samples : %d" % total)
    print("intercepted     : %d/%d = %.1f%%" % (hit, total, 100.0 * hit / total))
    print("result sha256   : %s" % fp_a)

    # 复跑一次验证确定性
    _, fp_b = run(paths["harmful_behaviors_test_public.json"])
    print("reproducibility : %s (sha256 %s)"
          % ("byte-identical" if fp_a == fp_b else "MISMATCH", fp_b))

    missed = [r for r in harmful if not r["blocked"]]
    if missed:
        print("\nnot intercepted (%d):" % len(missed))
        by_cat = {}
        for r in missed:
            by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
        for cat, cnt in sorted(by_cat.items(), key=lambda x: -x[1]):
            print("  %-22s %d" % (cat, cnt))
    return 0


if __name__ == "__main__":
    sys.exit(main())
