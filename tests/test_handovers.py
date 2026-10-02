from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.clock import FrozenClock
from app.core.errors import ConflictError
from app.database import transaction
from app.forensics.service import ForensicService
from tests.test_forensics_workflow import create_stored_lot


def _clock(service: ForensicService) -> FrozenClock:
    clock = FrozenClock(datetime(2026, 10, 2, 8, 0, tzinfo=UTC))
    service.handovers.clock = clock
    service.custody.clock = clock
    return clock


def _create_request_session(service: ForensicService, suffix: str = "001", ttl: int = 120) -> dict:
    forensic_case, specimen, placement = create_stored_lot(service, suffix)
    target = service.custody.create_location({
        "location_code": f"COURT-{suffix}", "facility": "法院物证柜", "room": "庭审区",
        "rack": "C1", "shelf": "S1", "capacity_units": 1000, "reference_value": 4, "humidity_percent": 45,
    })
    session = service.handovers.create_session({
        "session_no": f"HO-{suffix}", "case_id": forensic_case["id"], "direction": "调取",
        "legal_basis": f"出庭调取函 COURT-{suffix}", "basis_document_no": f"TJH-{suffix}",
        "initiating_party": "接收方", "initiated_by": "法院接收人",
        "handover_party": "鉴定机构保管室", "receiver_party": "区人民法院",
        "target_location_id": target["id"], "ttl_minutes": ttl,
        "items": [{"specimen_id": specimen["id"], "expected_seal_code": f"SEAL-{suffix}"}],
    })
    return session


def _both_parties_scan(service: ForensicService, session: dict, specimen_no: str, seal: str, suffix: str = "001") -> None:
    for party, who in (("交出方", "保管员"), ("接收方", "法院接收人")):
        service.handovers.scan(session["id"], {
            "party": party, "scan_kind": "specimen", "code": specimen_no,
            "idempotency_key": f"scan-{suffix}-{party}-spec", "scanned_by": who,
        })
        service.handovers.scan(session["id"], {
            "party": party, "scan_kind": "seal", "code": seal, "specimen_code": specimen_no,
            "idempotency_key": f"scan-{suffix}-{party}-seal", "scanned_by": who,
        })


def test_expected_manifest_is_generated_from_case_and_basis(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        session = _create_request_session(service)
        assert session["status"] == "open"
        assert session["direction"] == "调取"
        item = session["expected_items"][0]
        assert item["expected_seal_code"] == "SEAL-001"
        assert item["baseline_placement_id"] is not None
        assert [event["stage"] for event in session["stage_events"]] == ["created"]
        assert session["expires_at"] > session["created_at"]


def test_real_time_differences_missing_unexpected_duplicate_and_seal_mismatch(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        session = _create_request_session(service)
        specimen_no = session["expected_items"][0]["specimen"]["specimen_no"]

        # 交出方只扫检材、漏扫封识 -> 缺件（双方各自的封识扫描都缺）
        result = service.handovers.scan(session["id"], {
            "party": "交出方", "scan_kind": "specimen", "code": specimen_no,
            "idempotency_key": "scan-h-spec-1", "scanned_by": "保管员",
        })
        assert result["differences"]["missing"]
        assert result["replayed"] is False

        # 封识编号与调取函不符
        mismatch = service.handovers.scan(session["id"], {
            "party": "交出方", "scan_kind": "seal", "code": "SEAL-WRONG", "specimen_code": specimen_no,
            "idempotency_key": "scan-h-seal-1", "scanned_by": "保管员",
        })
        assert mismatch["differences"]["seal_mismatches"][0]["expected_seal_code"] == "SEAL-001"

        # 重复扫描不增加次数（幂等重放 + 真正重复都计为差异）
        replay = service.handovers.scan(session["id"], {
            "party": "交出方", "scan_kind": "specimen", "code": specimen_no,
            "idempotency_key": "scan-h-spec-1", "scanned_by": "保管员",
        })
        assert replay["replayed"] is True
        duplicate = service.handovers.scan(session["id"], {
            "party": "交出方", "scan_kind": "specimen", "code": specimen_no,
            "idempotency_key": "scan-h-spec-2", "scanned_by": "保管员",
        })
        assert duplicate["scan"]["scan_result"] == "duplicate"
        assert any(d["scan_kind"] == "specimen" for d in duplicate["differences"]["duplicates"])

        # 多件：扫到调取函之外、系统中也不存在的封袋
        unexpected = service.handovers.scan(session["id"], {
            "party": "交出方", "scan_kind": "specimen", "code": "GHOST-BAG-999",
            "idempotency_key": "scan-h-ghost", "scanned_by": "保管员",
        })
        assert unexpected["scan"]["scan_result"] == "unexpected"
        assert unexpected["differences"]["unexpected"]


def test_voiding_duplicate_and_unexpected_clears_differences(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        session = _create_request_session(service)
        specimen_no = session["expected_items"][0]["specimen"]["specimen_no"]
        service.handovers.scan(session["id"], {
            "party": "交出方", "scan_kind": "specimen", "code": specimen_no,
            "idempotency_key": "s1", "scanned_by": "保管员",
        })
        dup = service.handovers.scan(session["id"], {
            "party": "交出方", "scan_kind": "specimen", "code": specimen_no,
            "idempotency_key": "s2", "scanned_by": "保管员",
        })
        service.handovers.void_scan(session["id"], dup["scan"]["id"], {"actor": "保管员", "reason": "误扫重复"})
        service.handovers.scan(session["id"], {
            "party": "交出方", "scan_kind": "seal", "code": "SEAL-001", "specimen_code": specimen_no,
            "idempotency_key": "s3", "scanned_by": "保管员",
        })
        diff = service.handovers.evaluate(session["id"])
        assert not diff["duplicates"]
        # 接收方尚未扫描，仍未就绪
        assert diff["consistent"] is False
        assert any(m["party"] == "接收方" for m in diff["missing"])


def test_cannot_confirm_until_manifest_consistent(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        session = _create_request_session(service)
        with pytest.raises(ConflictError) as exc:
            service.handovers.confirm(session["id"], {"party": "交出方", "confirmer": "保管员"}, confirmer_id=1)
        assert "不能确认" in str(exc.value)


def test_completion_transfers_all_custody_at_once_with_distinct_identities(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        _clock(service)
        session = _create_request_session(service)
        item = session["expected_items"][0]
        specimen_no = item["specimen"]["specimen_no"]
        _both_parties_scan(service, session, specimen_no, "SEAL-001")

        # 同一用户不能代表双方确认
        service.handovers.confirm(session["id"], {"party": "交出方", "confirmer": "保管员"}, confirmer_id=7)
        with pytest.raises(ConflictError):
            service.handovers.confirm(session["id"], {"party": "接收方", "confirmer": "法院接收人"}, confirmer_id=7)
        completed = service.handovers.confirm(
            session["id"], {"party": "接收方", "confirmer": "法院接收人"}, confirmer_id=9
        )

        assert completed["status"] == "completed"
        assert completed["completed_at"]
        chain = completed["liability_chain"]
        assert len(chain) == 1
        transfer = chain[0]
        assert transfer["from_party"] == "鉴定机构保管室"
        assert transfer["to_party"] == "区人民法院"
        assert transfer["seal_before"] == "SEAL-001"
        assert transfer["custody_event_id"] is not None

        # 责任和位置一次性转移：旧摆放移除、新摆放落在法院库位、生成交接事件
        specimen = service.repository.specimen_detail(int(item["specimen_id"]))
        active = [p for p in specimen["placements"] if not p["removed_at"]]
        assert len(active) == 1
        assert active[0]["location_id"] == session["target_location_id"]
        movements = specimen["movements"]
        assert movements[-1]["movement_type"] == "交接"


def test_timeout_invalidates_without_partial_transfer(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        clock = _clock(service)
        session = _create_request_session(service, ttl=30)
        specimen_no = session["expected_items"][0]["specimen"]["specimen_no"]
        _both_parties_scan(service, session, specimen_no, "SEAL-001")
        service.handovers.confirm(session["id"], {"party": "交出方", "confirmer": "保管员"}, confirmer_id=1)

        clock.advance(minutes=31)
        result = service.handovers.expire_due_sessions()
        assert session["id"] in result["expired_session_ids"]
        expired = service.handovers.detail(session["id"])
        assert expired["status"] == "expired"
        # 第二方确认被拒绝
        with pytest.raises(ConflictError):
            service.handovers.confirm(session["id"], {"party": "接收方", "confirmer": "法院接收人"}, confirmer_id=2)
        # 没有写入任何交接责任链或流转
        assert expired["liability_chain"] == []
        specimen = service.repository.specimen_detail(int(session["expected_items"][0]["specimen_id"]))
        assert all(m["movement_type"] != "交接" for m in specimen["movements"])


def test_revocation_invalidates_session(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        session = _create_request_session(service)
        revoked = service.handovers.revoke(session["id"], {"actor": "法院接收人", "reason": "庭审改期，撤销调取"})
        assert revoked["status"] == "revoked"
        assert revoked["closure_reason"]
        with pytest.raises(ConflictError):
            service.handovers.scan(session["id"], {
                "party": "交出方", "scan_kind": "specimen", "code": "SP-001",
                "idempotency_key": "late-scan", "scanned_by": "保管员",
            })


def test_external_move_before_confirmation_invalidates_session(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        clock = _clock(service)
        session = _create_request_session(service, suffix="002")
        placement = service.repository.require_placement(int(session["expected_items"][0]["baseline_placement_id"]))
        other = service.custody.create_location({
            "location_code": "OTHER-002", "facility": "长期库", "room": "二室", "rack": "R9", "shelf": "S9",
            "capacity_units": 1000, "reference_value": -18, "humidity_percent": 30,
        })
        clock.advance(minutes=10)
        # 会话进行中，保管员在普通移库路径上把检材挪走
        service.custody.move_placement(placement["id"], {
            "target_location_id": other["id"], "expected_version": 1,
            "idempotency_key": "external-move-002", "actor": "保管员", "reason": "库位整理",
        })
        detail = service.handovers.detail(session["id"])
        assert detail["status"] == "invalidated"
        assert "失效" in detail["closure_reason"]
        # 失效后扫描与确认都必须失败，且没有写入任何责任转移
        assert detail["liability_chain"] == []
        with pytest.raises(ConflictError):
            service.handovers.confirm(session["id"], {"party": "交出方", "confirmer": "保管员"}, confirmer_id=1)


def test_same_scan_event_replay_does_not_increment(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        session = _create_request_session(service)
        specimen_no = session["expected_items"][0]["specimen"]["specimen_no"]
        payload = {
            "party": "交出方", "scan_kind": "specimen", "code": specimen_no,
            "idempotency_key": "stable-key", "scanned_by": "保管员",
        }
        service.handovers.scan(session["id"], payload)
        service.handovers.scan(session["id"], payload)
        service.handovers.scan(session["id"], payload)
        count = connection.execute(
            "SELECT COUNT(*) FROM handover_scans WHERE idempotency_key='stable-key'"
        ).fetchone()[0]
        assert count == 1


def test_return_session_reuses_manifest_and_freezes_on_seal_change(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        _clock(service)
        session = _create_request_session(service, suffix="007")
        specimen_no = session["expected_items"][0]["specimen"]["specimen_no"]
        _both_parties_scan(service, session, specimen_no, "SEAL-007", suffix="007")
        service.handovers.confirm(session["id"], {"party": "交出方", "confirmer": "保管员"}, confirmer_id=1)
        service.handovers.confirm(session["id"], {"party": "接收方", "confirmer": "法院接收人"}, confirmer_id=2)

        # 庭后归还沿用原会话生成清单，封识发生变化
        return_target = service.custody.create_location({
            "location_code": "BACK-007", "facility": "检材保管室", "room": "归还区",
            "rack": "R1", "shelf": "S2", "capacity_units": 1000, "reference_value": 4, "humidity_percent": 45,
        })
        ret = service.handovers.create_session({
            "session_no": "HO-RET-007", "case_id": session["forensic_case_id"], "direction": "归还",
            "legal_basis": "庭审结束归还", "origin_session_id": session["id"],
            "initiating_party": "交出方", "initiated_by": "法院接收人",
            "handover_party": "区人民法院", "receiver_party": "鉴定机构保管室",
            "target_location_id": return_target["id"], "ttl_minutes": 60, "items": [],
        })
        assert ret["expected_items"][0]["expected_seal_code"] == "SEAL-007"

        # 归还时双方扫描：法院交出用原封识，机构接收发现封识已变（复封 RESEAL-007）
        for party, who, seal in (
            ("交出方", "法院接收人", "SEAL-007"),
            ("接收方", "保管员", "RESEAL-007"),
        ):
            service.handovers.scan(ret["id"], {
                "party": party, "scan_kind": "specimen", "code": specimen_no,
                "idempotency_key": f"ret-{party}-spec", "scanned_by": who,
            })
            service.handovers.scan(ret["id"], {
                "party": party, "scan_kind": "seal", "code": seal, "specimen_code": specimen_no,
                "idempotency_key": f"ret-{party}-seal", "scanned_by": who,
            })

        diff = service.handovers.evaluate(ret["id"])
        assert diff["seal_changes"] and diff["return_consistent"]

        service.handovers.confirm(ret["id"], {"party": "交出方", "confirmer": "法院接收人"}, confirmer_id=2)
        done = service.handovers.confirm(ret["id"], {"party": "接收方", "confirmer": "保管员"}, confirmer_id=1)
        assert done["status"] == "completed"

        specimen = service.repository.specimen_detail(int(ret["expected_items"][0]["specimen_id"]))
        assert specimen["status"] == "held"
        holds = [h for h in specimen["holds"] if not h["released_at"]]
        assert holds and holds[0]["hold_type"] == "争议"
        assert "RESEAL-007" in holds[0]["reason"]

        # 责任链回指机构，位置归还到入库库位
        chain = done["liability_chain"][0]
        assert chain["to_party"] == "鉴定机构保管室"
        assert chain["to_location_id"] == return_target["id"]


def test_return_requires_origin_completed_session(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        open_session = _create_request_session(service, suffix="008")
        target = service.repository.require_location(open_session["target_location_id"])
        with pytest.raises(ConflictError):
            service.handovers.create_session({
                "session_no": "HO-RET-008", "case_id": open_session["forensic_case_id"], "direction": "归还",
                "legal_basis": "归还", "origin_session_id": open_session["id"],
                "initiating_party": "交出方", "initiated_by": "法院接收人",
                "handover_party": "区人民法院", "receiver_party": "鉴定机构保管室",
                "target_location_id": target["id"], "ttl_minutes": 60, "items": [],
            })
