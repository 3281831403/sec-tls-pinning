"""证书固定与备份回退的 15 条验收测试。

前 10 条分别锁定题面中的 10 个缺陷，后 5 条覆盖主 pin、备份 pin、
过期固定、未知 pin 失败关闭，以及批量校验与单独校验的一致性。
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from engine.pin.verify import (
    check_chain_binding,
    check_fallback,
    match_any,
    parse_pin_set,
    pin_active,
    pin_batch,
    pin_of,
    validate_pin_set,
)

UTC = timezone.utc
T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
T1 = datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)
T2 = datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC)
LATER = datetime(2027, 6, 1, 0, 0, 0, tzinfo=UTC)
AFTER_T2 = T2 + timedelta(seconds=1)


def make_cert(label: str, public_key: bytes | None = None) -> dict:
    """构造只用于契约测试的证书字典。"""
    der = ("complete-certificate:" + label).encode("utf-8")
    if public_key is None:
        public_key = ("spki:" + label).encode("utf-8")
    return {"der": der, "public_key": public_key, "label": label}


def pin_for(cert: dict) -> str:
    """测试侧的独立期望值：完整 der 的 SHA-256。"""
    return "sha256:" + hashlib.sha256(cert["der"]).hexdigest()


CERT_ALPHA = make_cert("alpha")
CERT_ALPHA_REISSUED = make_cert("alpha-reissued", public_key=CERT_ALPHA["public_key"])
CERT_BETA = make_cert("beta")
CERT_ROGUE = make_cert("rogue")

ALPHA_PIN = pin_for(CERT_ALPHA)
REISSUED_PIN = pin_for(CERT_ALPHA_REISSUED)
BETA_PIN = pin_for(CERT_BETA)
ROGUE_PIN = pin_for(CERT_ROGUE)


def make_pin(pin: str, *, not_before: datetime = T0, not_after: datetime = T2) -> dict:
    return {"pin": pin, "not_before": not_before, "not_after": not_after}


def make_pin_set(
    primary: list[str],
    backup: list[str],
    *,
    allow_fallback: bool = False,
) -> dict:
    return {
        "primary": [make_pin(value) for value in primary],
        "backup": [make_pin(value) for value in backup],
        "allow_fallback": allow_fallback,
    }


def pin_set_text(
    primary: list[str],
    backup: list[str],
    *,
    allow_fallback: bool = False,
) -> str:
    return json.dumps(
        {
            "primary": primary,
            "backup": backup,
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2027-01-01T00:00:00Z",
            "allow_fallback": allow_fallback,
        }
    )


def test_defect_01_pin_of_hashes_complete_certificate() -> None:
    # 同公钥、不同完整证书字节必须得到不同固定值。
    assert CERT_ALPHA["public_key"] == CERT_ALPHA_REISSUED["public_key"]
    assert ALPHA_PIN != REISSUED_PIN
    assert pin_of(CERT_ALPHA) == ALPHA_PIN
    assert pin_of(CERT_ALPHA_REISSUED) == REISSUED_PIN
    assert pin_of(CERT_ALPHA) != pin_of(CERT_ALPHA_REISSUED)


def test_defect_02_parse_pin_set_keeps_backup_pins() -> None:
    parsed = parse_pin_set(
        pin_set_text([ALPHA_PIN], [BETA_PIN, ROGUE_PIN], allow_fallback=True)
    )
    assert [item["pin"] for item in parsed["primary"]] == [ALPHA_PIN]
    assert [item["pin"] for item in parsed["backup"]] == [BETA_PIN, ROGUE_PIN]
    assert parsed["allow_fallback"] is True
    assert parsed["primary"][0]["not_before"] == T0
    assert parsed["primary"][0]["not_after"] == T2
    assert parsed["backup"][0]["not_before"] == T0


def test_defect_03_pin_active_rejects_after_not_after() -> None:
    pin = make_pin(ALPHA_PIN)
    assert pin_active(pin, T0) is True
    assert pin_active(pin, T2) is True
    assert pin_active(pin, AFTER_T2) is False
    assert pin_active(pin, T0 - timedelta(microseconds=1)) is False


def test_defect_04_match_any_rejects_expired_pin() -> None:
    active = make_pin(ALPHA_PIN)
    expired = make_pin(ALPHA_PIN, not_after=T1)
    assert match_any(CERT_ALPHA, [active], T1) is True
    assert match_any(CERT_ALPHA, [expired], AFTER_T2) is False


def test_defect_05_expired_backup_pin_cannot_fallback() -> None:
    pin_set = make_pin_set([ALPHA_PIN], [BETA_PIN], allow_fallback=True)
    pin_set["backup"][0]["not_after"] = T1
    policy = {"now": LATER, "audit": []}
    assert check_fallback([CERT_BETA], pin_set, policy) is False
    assert policy["audit"] == []


def test_defect_06_chain_binding_rejects_foreign_pin() -> None:
    chain = [CERT_ALPHA, CERT_BETA]
    assert check_chain_binding(chain, ALPHA_PIN) is True
    assert check_chain_binding(chain, ROGUE_PIN) is False
    assert check_chain_binding([], ALPHA_PIN) is False


def test_defect_07_fallback_requires_permission() -> None:
    pin_set = make_pin_set([ALPHA_PIN], [BETA_PIN], allow_fallback=False)
    policy = {"now": T1, "audit": []}
    assert check_fallback([CERT_BETA], pin_set, policy) is False
    assert policy["audit"] == []


def test_defect_08_successful_fallback_is_audited() -> None:
    pin_set = make_pin_set([ALPHA_PIN], [BETA_PIN], allow_fallback=True)
    policy = {"now": T1, "audit": []}
    assert check_fallback([CERT_BETA], pin_set, policy) is True
    assert len(policy["audit"]) == 1
    record = policy["audit"][0]
    assert record["event"] == "pin_fallback"
    assert record["pin"] == BETA_PIN


def test_defect_09_validate_pin_set_checks_backup_and_chain_fallback() -> None:
    valid = make_pin_set([ALPHA_PIN], [BETA_PIN], allow_fallback=True)
    assert validate_pin_set(valid) == []

    no_backup = make_pin_set([ALPHA_PIN], [], allow_fallback=True)
    assert validate_pin_set(no_backup) == [
        "missing_backup",
        "fallback_to_chain",
    ]

    missing_validity = make_pin_set([ALPHA_PIN], [BETA_PIN])
    missing_validity["backup"][0]["not_after"] = None
    assert validate_pin_set(missing_validity) == ["missing_validity"]


def test_defect_10_batch_recomputes_pin_per_connection() -> None:
    pin_set = make_pin_set([ALPHA_PIN], [])
    peers = [
        {"id": "first", "cert": CERT_ALPHA, "chain": [CERT_ALPHA], "pin_set": pin_set},
        {
            "id": "second",
            "cert": CERT_ALPHA_REISSUED,
            "chain": [CERT_ALPHA_REISSUED],
            "pin_set": pin_set,
        },
    ]
    result = pin_batch(peers, {"audit": []}, T1)
    assert result["first"]["accepted"] is True
    assert result["first"]["pin"] == ALPHA_PIN
    assert result["first"]["fallback"] is False
    assert result["second"]["accepted"] is False
    assert result["second"]["pin"] == REISSUED_PIN
    assert result["second"]["fallback"] is False
    assert result["first"]["pin"] != result["second"]["pin"]


def test_primary_pin_matches() -> None:
    pin_set = make_pin_set([ALPHA_PIN], [])
    assert match_any(CERT_ALPHA, pin_set["primary"], T1) is True
    result = pin_batch(
        [{"id": "alpha", "cert": CERT_ALPHA, "chain": [CERT_ALPHA], "pin_set": pin_set}],
        {"audit": []},
        T1,
    )
    assert result["alpha"]["accepted"] is True
    assert result["alpha"]["fallback"] is False


def test_backup_pin_matches_and_logs_fallback() -> None:
    pin_set = make_pin_set([ALPHA_PIN], [BETA_PIN], allow_fallback=True)
    policy = {"audit": []}
    assert match_any(CERT_BETA, pin_set["backup"], T1) is True
    result = pin_batch(
        [{"id": "beta", "cert": CERT_BETA, "chain": [CERT_BETA], "pin_set": pin_set}],
        policy,
        T1,
    )
    assert result["beta"]["accepted"] is True
    assert result["beta"]["fallback"] is True
    assert result["beta"]["pin"] == BETA_PIN
    assert len(policy["audit"]) == 1
    assert policy["audit"][0] == {"event": "pin_fallback", "pin": BETA_PIN}


def test_expired_pin_is_rejected() -> None:
    expired = make_pin(ALPHA_PIN, not_after=T1)
    assert pin_active(expired, LATER) is False
    assert match_any(CERT_ALPHA, [expired], LATER) is False


def test_unknown_pin_without_fallback_fails_closed() -> None:
    denied = make_pin_set([ALPHA_PIN], [], allow_fallback=False)
    policy = {"now": T1, "audit": []}
    assert match_any(CERT_ROGUE, denied["primary"], T1) is False
    assert check_fallback([CERT_ROGUE], denied, policy) is False
    assert policy["audit"] == []

    allowed_but_no_backup = make_pin_set([ALPHA_PIN], [], allow_fallback=True)
    assert check_fallback(
        [CERT_ROGUE], allowed_but_no_backup, {"now": T1, "audit": []}
    ) is False

    active_backup_but_no_binding = make_pin_set(
        [ALPHA_PIN], [BETA_PIN], allow_fallback=True
    )
    assert check_fallback(
        [CERT_ROGUE], active_backup_but_no_binding, {"now": T1, "audit": []}
    ) is False


def test_two_batches_match_individual_checks() -> None:
    alpha_set = make_pin_set([ALPHA_PIN], [])
    beta_set = make_pin_set([BETA_PIN], [])
    peers = [
        {"id": "alpha", "cert": CERT_ALPHA, "chain": [CERT_ALPHA], "pin_set": alpha_set},
        {"id": "beta", "cert": CERT_BETA, "chain": [CERT_BETA], "pin_set": beta_set},
        {"id": "rogue", "cert": CERT_ROGUE, "chain": [CERT_ROGUE], "pin_set": alpha_set},
    ]

    first_batch = pin_batch(peers[:1], {"audit": []}, T1)
    second_batch = pin_batch(peers[1:], {"audit": []}, T1)
    separate = {**first_batch, **second_batch}

    all_at_once = pin_batch(peers, {"audit": []}, T1)
    assert all_at_once == separate

    for peer in peers:
        individually_allowed = match_any(peer["cert"], peer["pin_set"]["primary"], T1)
        assert separate[peer["id"]]["accepted"] is individually_allowed

    assert separate["alpha"]["accepted"] is True
    assert separate["beta"]["accepted"] is True
    assert separate["rogue"]["accepted"] is False