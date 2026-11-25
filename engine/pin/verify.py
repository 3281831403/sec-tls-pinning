"""证书固定集校验的唯一实现文件。

本模块当前恰好包含 8 个待修函数，全部是桩。测试是验收契约，不要为了
让测试变绿而修改 tests、增加跳过标记或把异常吞掉。
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime


def _parse_datetime(value) -> datetime | None:
    """把 ISO 8601 文本解析为 datetime；缺失返回 None，错误抛 ValueError。"""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"生效期必须是 ISO 8601 字符串: {value!r}")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"无法解析生效期: {value!r}") from exc


def parse_pin_set(text: str) -> dict:
    """把 JSON 固定集文本解析成内部结构。

    输入至少包含 ``primary`` 与 ``backup`` 两个字符串列表，可包含
    ISO 8601 的 ``not_before`` / ``not_after`` 与布尔值
    ``allow_fallback``。返回的每个固定项都必须是::

        {"pin": "sha256:...", "not_before": datetime, "not_after": datetime}

    ``primary`` 与 ``backup`` 都要保留并保持原顺序。缺少生效期时保留
    ``None``，由 validate_pin_set 报告，不能静默视为永久有效。格式错误
    应抛 ValueError。
    """
    try:
        data = json.loads(text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"固定集不是合法 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("固定集必须是 JSON 对象")

    not_before = _parse_datetime(data.get("not_before"))
    not_after = _parse_datetime(data.get("not_after"))

    parsed: dict = {"allow_fallback": bool(data.get("allow_fallback", False))}
    for key in ("primary", "backup"):
        values = data.get(key)
        if values is None:
            values = []
        if not isinstance(values, list) or not all(
            isinstance(item, str) for item in values
        ):
            raise ValueError(f"{key} 必须是字符串列表")
        # primary 与 backup 都完整保留并保持原顺序
        parsed[key] = [
            {"pin": item, "not_before": not_before, "not_after": not_after}
            for item in values
        ]
    return parsed


def pin_of(cert: dict) -> str:
    """返回证书固定值。

    ``cert`` 至少包含 ``der``（完整证书字节）与 ``public_key``（公钥字节）。
    固定值必须是对完整 ``der`` 做 SHA-256 得到的 ``sha256:`` 加小写
    十六进制字符串；不得只摘要公钥、序列号或其它单个字段。
    """
    der = cert["der"]
    if isinstance(der, str):
        der = der.encode("utf-8")
    return "sha256:" + hashlib.sha256(der).hexdigest()


def pin_active(pin: dict, now: datetime) -> bool:
    """判断一个固定项在 ``now`` 是否仍生效。

    生效区间为闭区间，必须同时满足 ``not_before <= now <= not_after``。
    缺少任一端点、端点不是带时区的 datetime 或已经越过 ``not_after``
    都必须返回 False，不得只比较起始时间。
    """
    not_before = pin.get("not_before")
    not_after = pin.get("not_after")
    if not isinstance(not_before, datetime) or not isinstance(not_after, datetime):
        return False
    if not_before.tzinfo is None or not_after.tzinfo is None:
        return False
    if not isinstance(now, datetime) or now.tzinfo is None:
        return False
    return not_before <= now <= not_after


def match_any(cert: dict, pins: list[dict], now: datetime) -> bool:
    """判断证书是否命中 ``pins`` 中某个仍生效的固定项。

    既要比对完整证书摘要，也要调用生效期判定；过期固定项必须视为不命中。
    空固定项列表返回 False。
    """
    if not pins:
        return False
    digest = pin_of(cert)
    for pin in pins:
        if pin.get("pin") == digest and pin_active(pin, now):
            return True
    return False


def check_chain_binding(chain: list[dict], pin: str) -> bool:
    """判断固定值是否来自证书链上的某张证书。

    ``chain`` 是已经按叶子到根排好序的证书字典列表。必须逐个计算链上
    证书的完整摘要并精确比较；空 pin、空链、以及来自链外任意证书的 pin
    都必须返回 False，不能只检查 pin 非空。
    """
    if not pin or not chain:
        return False
    for cert in chain:
        if pin_of(cert) == pin:
            return True
    return False


def check_fallback(chain: list[dict], pin_set: dict, policy: dict) -> bool:
    """执行受限回退并记录审计。

    只有同时满足以下条件才允许回退并返回 True：

    * ``pin_set["allow_fallback"]`` 为 True；
    * ``policy["now"]`` 是带时区的求值时间；
    * 至少有一个备份 pin 在求值时间仍生效；
    * 该备份 pin 精确出现在 ``chain`` 的证书摘要中。

    ``policy["audit"]`` 必须是列表。回退成功时向其中追加一条
    ``{"event": "pin_fallback", "pin": <备份固定值>}`` 后再返回 True；
    任何失败路径都不得写记录。不允许在没有备份 pin 时静默退回仅校验链。
    """
    if not pin_set.get("allow_fallback"):
        return False
    now = policy.get("now")
    if not isinstance(now, datetime) or now.tzinfo is None:
        return False
    audit = policy.get("audit")
    if not isinstance(audit, list):
        return False
    for backup in pin_set.get("backup") or []:
        pin_value = backup.get("pin")
        # 备份 pin 同样受生效期约束，过期不得用于回退
        if not pin_value or not pin_active(backup, now):
            continue
        # 备份 pin 必须精确绑定到链上某张证书
        if check_chain_binding(chain, pin_value):
            audit.append({"event": "pin_fallback", "pin": pin_value})
            return True
    return False


def validate_pin_set(pin_set: dict) -> list[str]:
    """返回固定集配置问题码列表。

    按以下固定顺序检查并返回：

    * ``missing_backup``：没有配置任何备份 pin；
    * ``missing_validity``：任一固定项缺少 not_before 或 not_after；
    * ``fallback_to_chain``：允许回退但没有任何备份 pin，实际只剩链校验。

    合法固定集返回空列表。
    """
    problems: list[str] = []
    backups = pin_set.get("backup") or []
    if not backups:
        problems.append("missing_backup")
    all_pins = (pin_set.get("primary") or []) + backups
    if any(
        pin.get("not_before") is None or pin.get("not_after") is None
        for pin in all_pins
    ):
        problems.append("missing_validity")
    if pin_set.get("allow_fallback") and not backups:
        problems.append("fallback_to_chain")
    return problems


def pin_batch(peers: list[dict], policy: dict, now: datetime) -> dict:
    """批量校验多条连接，每条连接互相独立。

    ``peers`` 中每项包含 ``id``、``cert``、``chain``、``pin_set``。返回以
    ``id`` 为键的字典，值为::

        {"accepted": bool, "pin": str, "fallback": bool}

    每条连接都必须用当条连接的证书重新计算完整证书摘要，不得复用前一条
    连接的摘要或 pin。先匹配仍生效的主 pin；主 pin 不命中时才走
    check_fallback，并让审计记录落到 ``policy["audit"]``。没有主 pin 或
    受限备份回退可用时必须失败关闭。
    """
    audit = policy.get("audit")
    if not isinstance(audit, list):
        audit = []
    results: dict = {}
    for peer in peers:
        # 每条连接独立重算摘要，绝不复用前一条连接的结果
        digest = pin_of(peer["cert"])
        pin_set = peer["pin_set"]
        entry = {"accepted": False, "pin": digest, "fallback": False}

        if match_any(peer["cert"], pin_set.get("primary") or [], now):
            entry["accepted"] = True
        else:
            fallback_policy = {"now": now, "audit": audit}
            before = len(audit)
            if check_fallback(peer["chain"], pin_set, fallback_policy):
                entry["accepted"] = True
                entry["fallback"] = True
                if len(audit) > before:
                    entry["pin"] = audit[-1]["pin"]
        results[peer["id"]] = entry
    return results
