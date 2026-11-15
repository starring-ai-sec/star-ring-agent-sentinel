# -*- coding: utf-8 -*-
"""星环 · Agent 行为自检工具（命令行入口，开源基础版）。

用法
----
    # 1) 拿机器码（申请免费授权时提供）
    xh-scan --machine

    # 2) 跑基础规则扫描（需免费授权文件 license.json）
    xh-scan --input logs.jsonl --out report.md

    # 3) 生成脱敏包（换取深度体检，去 GitHub 提 Issue）
    xh-scan --anonymize --input logs.jsonl

日志格式（JSONL，一行一条工具调用）
--------------------------------
    {"ts":"2026-11-05T10:23:11Z","agent_id":"bot1","tool":"read_docs","params":{"path":"docs/a.md"}}

也支持「一行一条链」：
    {"ts":"...","agent_id":"bot1","actions":[{"action_type":"read_sms","params":{}}, ...]}
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import xh_engine
import xh_license
import xh_anonymize

VERSION = "1.0"
BRAND = "星环AI行为安全实验室"
PRODUCT = "Agent 行为自检包"

_DECISION_CN = {"allow": "放行", "confirm": "需确认", "block": "拦截", "fuse": "熔断"}


# ── 日志读取与聚合 ────────────────────────────────────────
def _load_records(path: Path) -> List[Dict[str, Any]]:
    if not path.is_file():
        raise SystemExit("[错误] 日志文件不存在：%s" % path)
    rows: List[Dict[str, Any]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        text = line.strip()
        if not text:
            continue
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SystemExit("[错误] 第 %d 行不是合法 JSON：%s" % (lineno, exc))
        if not isinstance(obj, dict):
            raise SystemExit("[错误] 第 %d 行不是对象" % lineno)
        rows.append(obj)
    return rows


def _to_actions(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    if isinstance(row.get("actions"), list):
        return [dict(a) for a in row["actions"] if isinstance(a, dict)]
    tool = row.get("tool") or row.get("action_type")
    if not tool:
        return []
    return [{"action_type": str(tool), "params": dict(row.get("params") or {})}]


def _ts_minutes(ts: str) -> int | None:
    """时间戳 → 当天分钟数（取 HH:MM），解析失败返回 None。"""
    if not ts:
        return None
    m = re.search(r"(\d{1,2}):(\d{2})", ts)
    if not m:
        return None
    return int(m.group(1)) * 60 + int(m.group(2))


def _gap_minutes(ts_a: str, ts_b: str) -> int | None:
    """两个时间戳的分钟间隔（跨天自动 +1440），解析失败返回 None。"""
    a, b = _ts_minutes(ts_a), _ts_minutes(ts_b)
    if a is None or b is None:
        return None
    gap = b - a
    return gap + 1440 if gap < 0 else gap


def _group_chains(rows: List[Dict[str, Any]], max_steps: int = 6,
                  window_min: int = 5, dedup: bool = True) -> List[Dict[str, Any]]:
    """按 session 聚合，并做「连续去重（重试压缩）」+「时间窗口断开」。

    - dedup：相邻两个动作类型相同 → 视为重试，只计一次；
    - window_min：相邻动作时间间隔超过 N 分钟 → 断开成新链（避免整个 session
      被聚成一条跨越数小时的巨链，误伤并发/异步任务）。
    """
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for idx, row in enumerate(rows):
        key = str(row.get("session_id") or row.get("agent_id") or ("_row%d" % idx))
        buckets.setdefault(key, []).append(row)

    chains: List[Dict[str, Any]] = []
    for key, items in buckets.items():
        # 展开成带时间戳的动作序列
        seq: List[tuple] = []
        for row in items:
            ts = str(row.get("ts") or "")
            for a in _to_actions(row):
                seq.append((ts, a))
        if not seq:
            continue

        cur: List[tuple] = [seq[0]]
        for ts, a in seq[1:]:
            prev_ts, prev_a = cur[-1]
            # 连续去重：相邻同动作（重试）→ 压缩
            if dedup and prev_a.get("action_type") == a.get("action_type"):
                continue
            # 时间窗口：间隔超阈值 → 断开新链
            gap = _gap_minutes(prev_ts, ts)
            if gap is not None and gap > window_min:
                chains.append({
                    "key": key, "ts": cur[0][0],
                    "actions": [x for _, x in cur][:max_steps],
                    "steps": len(cur), "truncated": len(cur) > max_steps,
                })
                cur = []
            cur.append((ts, a))
        chains.append({
            "key": key, "ts": cur[0][0],
            "actions": [x for _, x in cur][:max_steps],
            "steps": len(cur), "truncated": len(cur) > max_steps,
        })
    return chains


# ── 报告 ─────────────────────────────────────────────────
def build_report(chains: List[Dict[str, Any]], cfg: Dict[str, Any],
                 lic: Dict[str, Any], source: str) -> Dict[str, Any]:
    results = []
    for chain in chains:
        verdict = xh_engine.evaluate(chain["actions"], cfg)
        results.append({
            "key": chain["key"],
            "ts": chain["ts"],
            "types": " → ".join(verdict["types"]),
            "decision": verdict["decision"],
            "mark": verdict["mark"],
            "reasons": "；".join(verdict["reasons"]),
            "truncated": chain["truncated"],
        })
    counter = Counter(r["decision"] for r in results)
    flagged = [r for r in results if r["decision"] != "allow"]
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source": source,
        "total": len(results),
        "counter": dict(counter),
        "flagged": flagged,
        "results": results,
        "license": lic,
    }


def to_markdown(report: Dict[str, Any]) -> str:
    lic = report.get("license") or {}
    lines = [
        "# Agent 行为自检报告",
        "",
        "> **%s** ｜ %s v%s（开源基础版）" % (BRAND, PRODUCT, VERSION),
        "> 授权：%s ｜ 生成时间：%s" % (lic.get("license_id") or "-", report["generated_at"]),
        "> 数据源：`%s` ｜ 行为链 **%d** 条" % (report["source"], report["total"]),
        "",
        "---",
        "",
        "## 一、汇总",
        "",
        "| 裁决 | 数量 | 说明 |",
        "|---|---:|---|",
    ]
    explain = {
        "allow": "未发现风险，正常执行",
        "confirm": "存在可疑点，建议人工确认",
        "block": "命中确定性证据，应拒绝",
        "fuse": "高危组合，应熔断并排查",
    }
    for key in ("allow", "confirm", "block", "fuse"):
        lines.append("| %s | %d | %s |"
                     % (_DECISION_CN[key], report["counter"].get(key, 0), explain[key]))
    lines += ["", "## 二、被拦记录（含标注）", ""]

    if report["flagged"]:
        lines += ["| # | 会话 | 时间 | 工具链 | 裁决 | 标注 |",
                  "|---:|---|---|---|---|---|"]
        for idx, row in enumerate(report["flagged"], 1):
            lines.append("| %d | %s | %s | %s | %s | %s |"
                         % (idx, row["key"], row["ts"][:19] or "-",
                            row["types"], _DECISION_CN[row["decision"]], row["mark"]))
        lines += ["", "## 三、依据明细", ""]
        for idx, row in enumerate(report["flagged"], 1):
            lines.append("### %d · %s（%s）" % (idx, row["key"], _DECISION_CN[row["decision"]]))
            lines.append("")
            lines.append("- 工具链：`%s`" % row["types"])
            lines.append("- 标注：**%s**" % (row["mark"] or "-"))
            lines.append("- 依据：%s" % row["reasons"])
            if row["truncated"]:
                lines.append("- 注意：该链超过 6 步，仅评估前 6 步")
            lines.append("")
    else:
        lines += ["未发现被拦记录。", ""]

    lines += [
        "## 四、整改建议",
        "",
        "| 若标注为 | 建议动作 |",
        "|---|---|",
        "| 【确认拦截】 | 无需处理，属真实风险 |",
        "| 【需复核】 | 判断是否为业务正常形态；是则加入 `exempt_ops` 白名单 |",
        "| 【疑似误报】 | 调整动作映射或参数阈值后重跑 |",
        "",
        "## 五、边界声明（请勿外推）",
        "",
        "1. 本工具为**开源规则版初筛**，不含完整星环引擎的三轨模型与 177 条红队样本，结论用于定位风险方向，不构成合规认证；",
        "2. 仅评估**行为链**，不判定文本内容（有害内容识别不在能力范围）；",
        "3. 每条链最多评估前 6 步；超长链的尾部行为未纳入；",
        "4. 结论仅对本次日志有效，样本构成变化后需重跑。",
        "",
        "---",
        "",
        "> 本报告由开源基础版（规则引擎）生成，仅作风险定位，不构成合规认证。",
        "> %s" % xh_license.watermark(lic),
        "",
    ]
    return "\n".join(lines)


# ── 深度体检引导（数据诱饵）──────────────────────────────
def _print_hook(report: Dict[str, Any]) -> None:
    flagged_n = len(report["flagged"])
    print("")
    print("[+] 基础规则扫描完成。发现 %d 处潜在越权风险。" % flagged_n)
    print("[!] 星环深度体检引擎（三轨模型 + 177 条红队样本）未激活。")
    print("[>] 请前往我们的 GitHub 仓库，点击「New Issue」（模板：申请深度体检）")
    print("    提交您的脱敏报告，我们将为您出具专属的完整版 PDF。")
    print("    生成脱敏报告：xh-scan --anonymize --input 你的日志.jsonl")


# ── 脱敏包（深度体检用）──────────────────────────────────
def _cmd_anonymize(args: argparse.Namespace) -> int:
    in_path = Path(args.input)
    if not in_path.is_file():
        print("[错误] 日志文件不存在：%s" % in_path, file=sys.stderr)
        return 2
    text = in_path.read_text(encoding="utf-8")
    out_text = xh_anonymize.anonymize_lines(text)
    out_path = Path(args.out or (in_path.stem + "-anonymized.jsonl"))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(out_text, encoding="utf-8")
    lines_n = len([l for l in out_text.splitlines() if l.strip()])
    print("[+] 已脱敏 %d 条记录，敏感信息（手机号 / 邮箱 / 路径 / IP / 卡号）已替换。" % lines_n)
    print("[+] 脱敏文件：%s" % out_path)
    print("")
    print("[>] 请前往 GitHub 仓库，点击「New Issue」（模板：申请深度体检），")
    print("    把上面这个脱敏文件的内容粘贴进去，我们将人工出具深度体检报告（带水印 PDF）。")
    print("")
    print("[提示] 上传的是脱敏后的行为链结构，原始日志从未离开本机。")
    return 0


# ── 主入口 ───────────────────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser(prog="xh-scan", description="%s · %s（开源基础版）" % (BRAND, PRODUCT))
    ap.add_argument("--machine", action="store_true", help="输出本机机器码")
    ap.add_argument("--input", help="日志文件（JSONL）")
    ap.add_argument("--out", help="报告输出路径（.md）")
    ap.add_argument("--config", help="参数配置 JSON（可选）")
    ap.add_argument("--license", default="license/LICENSE.lic", help="授权文件路径")
    ap.add_argument("--anonymize", action="store_true", help="生成脱敏包（深度体检用），不跑扫描")
    ap.add_argument("--version", action="version", version="%s v%s（开源基础版）" % (PRODUCT, VERSION))
    args = ap.parse_args()

    if args.machine:
        print(xh_license.machine_id())
        return 0

    if args.anonymize:
        if not args.input:
            print("[错误] --anonymize 需要配合 --input 使用", file=sys.stderr)
            return 2
        return _cmd_anonymize(args)

    if not args.input or not args.out:
        ap.print_help()
        return 2

    # 免费授权校验
    ok, message, lic = xh_license.verify(args.license)
    if not ok:
        print("[!] 未检测到有效授权：%s" % message, file=sys.stderr)
        print("[>] 基础版免费，但需申请免费授权：", file=sys.stderr)
        print("    1. 运行 xh-scan --machine 获取机器码", file=sys.stderr)
        print("    2. 前往 GitHub 提 Issue（模板：申请免费授权）附上机器码", file=sys.stderr)
        print("    3. 拿到 license.json 后放入 license/ 目录重跑", file=sys.stderr)
        return 3

    cfg: Dict[str, Any] = {}
    if args.config:
        cfg_path = Path(args.config)
        if not cfg_path.is_file():
            print("[错误] 配置文件不存在：%s" % cfg_path, file=sys.stderr)
            return 2
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))

    rows = _load_records(Path(args.input))
    chains = _group_chains(rows)
    if not chains:
        print("[错误] 日志中没有可评估的工具调用", file=sys.stderr)
        return 2

    report = build_report(chains, cfg, lic, str(args.input))
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(to_markdown(report), encoding="utf-8")

    print("[完成] 行为链 %d 条｜放行 %d｜需确认 %d｜拦截 %d｜熔断 %d"
          % (report["total"], report["counter"].get("allow", 0),
             report["counter"].get("confirm", 0), report["counter"].get("block", 0),
             report["counter"].get("fuse", 0)))
    print("[报告] %s" % out_path)
    _print_hook(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
