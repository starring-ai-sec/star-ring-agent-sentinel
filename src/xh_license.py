# -*- coding: utf-8 -*-
"""星环 · 授权校验（开源版：仅公钥验签，不含私钥）。

安全模型
--------
采用 Ed25519 非对称签名：

* **签发**：实验室内部用私钥（不随仓库分发，见内部工具）；
* **验签**：客户端用内置公钥——公钥开源无害，无法用它伪造签名。

与旧版 HMAC 对称密钥的区别：旧版密钥内置在 exe 里，反编译即可提取并伪造授权；
现在即使拿到全部源码 + 公钥，也无法签发合法授权。真正的私钥只在实验室内部。

依赖：`cryptography`（客户端验签需要）。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import uuid
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

#: Ed25519 公钥（开源无害：公钥无法伪造签名，私钥在实验室内部）
_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEARzeFrq40ce1rSYP7VJofGi7FlpuQR+9VSylLAQ+Khpw=
-----END PUBLIC KEY-----"""

try:
    _PUBLIC_KEY = serialization.load_pem_public_key(_PUBLIC_KEY_PEM)
except Exception:  # pragma: no cover - 公钥解析失败属于部署错误
    _PUBLIC_KEY = None

_APP_DIR = Path(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")) / "XingHuan"
_ACT_FILE = _APP_DIR / "activation.json"


def machine_id() -> str:
    """机器码：MAC + 主机名 + 架构，取 sha256 前 16 位。"""
    raw = "|".join([
        "%012x" % uuid.getnode(),
        platform.node() or "",
        platform.machine() or "",
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _canonical(payload: Dict[str, Any]) -> bytes:
    body = {k: v for k, v in payload.items() if k != "sig"}
    return json.dumps(body, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _load_activation() -> Dict[str, Any]:
    if not _ACT_FILE.is_file():
        return {}
    try:
        return json.loads(_ACT_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_activation(license_id: str, machine: str) -> None:
    _APP_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "license_id": license_id,
        "machine": machine,
        "activated_at": datetime.now().isoformat(timespec="seconds"),
    }
    _ACT_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                         encoding="utf-8")


def verify(license_path, today: date | None = None) -> Tuple[bool, str, Dict[str, Any]]:
    """校验授权：签名 → 有效期 → 机器绑定。返回 (通过, 说明, 授权内容)。"""
    path = Path(license_path)
    if not path.is_file():
        return False, "授权文件不存在：%s" % path, {}
    try:
        lic = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, "授权文件无法解析：%s" % exc, {}

    if _PUBLIC_KEY is None:
        return False, "验签公钥未加载，无法校验授权", lic

    sig_b64 = str(lic.get("sig") or "")
    try:
        sig = base64.b64decode(sig_b64)
    except (ValueError, TypeError):
        return False, "授权签名格式非法", lic
    try:
        _PUBLIC_KEY.verify(sig, _canonical(lic))
    except InvalidSignature:
        return False, "授权签名无效（文件被修改或非本实验室签发）", lic
    except Exception:
        return False, "授权签名校验失败", lic

    now = today or date.today()
    try:
        expires = date.fromisoformat(str(lic.get("expires_at")))
    except ValueError:
        return False, "授权到期日格式非法", lic
    if now > expires:
        return False, "授权已过期（有效期至 %s）" % expires.isoformat(), lic

    mid = machine_id()
    bound = str(lic.get("machine") or "").strip()
    if bound and bound != mid:
        return False, ("授权绑定的机器与当前机器不一致（授权机器 %s，本机 %s）"
                       % (bound, mid)), lic

    record = _load_activation()
    if record.get("license_id") and record.get("license_id") != lic.get("license_id"):
        return False, ("本机已激活另一份授权（%s），一个名额只能激活一份"
                       % record.get("license_id")), lic
    if record.get("machine") and record.get("machine") != mid:
        return False, "本机激活记录与当前机器不符，授权可能被复制", lic

    if not record:
        _save_activation(str(lic.get("license_id")), mid)
    return True, "授权有效（%s，有效期至 %s）" % (
        lic.get("license_id"), expires.isoformat()), lic


def watermark(lic: Dict[str, Any]) -> str:
    """报告水印：可追溯到具体名额。"""
    return ("本报告由 星环AI行为安全实验室 生成 ｜ 授权 %s ｜ 机器 %s ｜ %s"
            % (lic.get("license_id") or "-", machine_id(), lic.get("holder") or "-"))


if __name__ == "__main__":
    print("机器码：%s" % machine_id())
    print("激活记录：%s" % _ACT_FILE)
