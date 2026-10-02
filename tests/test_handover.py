from __future__ import annotations

from datetime import UTC, datetime

from app.core.clock import FrozenClock
from app.database import transaction
from app.forensics.service import ForensicService
from tests.test_forensics_workflow import create_stored_lot


PASSWORD_A = "Handover!23456"
PASSWORD_B = "Receiver!23456"


def _make_user(service: ForensicService, username: str, display: str, password: str) -> dict:
    from app.core.security import hash_password
    from app.core.clock import to_storage

    timestamp = to_storage(service.handover.clock.now())
    cursor = service.connection.execute(
        "INSERT INTO users(username,password_hash,display_name,status,password_changed_at,created_at,updated_at) "
        "VALUES(?,?,?,'active',?,?,?)",
        (username, hash_password(password), display, timestamp, timestamp, timestamp),
    )
    role_id = service.connection.execute("SELECT id FROM roles WHERE code='registrar'").fetchone()[0]
    service.connection.execute(
        "INSERT INTO user_roles(user_id,role_id,assigned_by,assigned_at) VALUES(?,?,1,?)",
        (cursor.lastrowid, role_id, timestamp),
    )
    return {"id": int(cursor.lastrowid), "display_name": display}


def _setup(service: ForensicService, suffix: str = "H1") -> dict:
    forensic_case, specimen, placement = create_stored_lot(service, suffix)
    service.connection.execute(
        "UPDATE specimens SET seal_code=? WHERE id=?", (f"SEAL-{suffix}", specimen["id"])
    )
    # 再登记一个同案检材用于多件/缺件场景
    specimen_b = service.custody.create_specimen({
        "specimen_no": f"SP-{suffix}B", "case_id": forensic_case["id"], "parent_specimen_id": None,
        "received_year": 2026, "initial_quantity": 200, "integrity_percent": 100,
        "packaging": "防拆封袋", "sealed_on": "2026-09-02", "seal_code": f"SEAL-{suffix}B", "created_by": "登记员",
    })
    target = service.custody.create_location({
        "location_code": f"COURT-{suffix}", "facility": "法院物证室", "room": "接收区", "rack": "C1", "shelf": "S1",
        "capacity_units": 1000, "reference_value": 4, "humidity_percent": 45,
    })
    placed_b = service.custody.place_specimen({
        "specimen_id": specimen_b["id"], "location_id": placement["location_id"], "quantity": 200,
        "container_code": f"BOX-{suffix}B", "idempotency_key": f"place-{suffix}-b001", "actor": "保管员",
    })
    party_a = _make_user(service, f"keeper_{suffix.lower()}", "保管员甲", PASSWORD_A)
    party_b = _make_user(service, f"court_{suffix.lower()}", "法院接收人乙", PASSWORD_B)
    return {
        "case": forensic_case, "specimen": specimen, "specimen_b": specimen_b,
        "placement": placement, "placement_b": placed_b["placement"],
        "target": target, "keeper": party_a, "court": party_b,
    }


def _create_session(service: ForensicService, ctx: dict, *, ttl: int = 60) -> dict:
    return service.handover.create_session({
        "case_id": ctx["case"]["id"], "purpose": "调取",
        "legal_basis": f"法院调取函 {ctx['case']['case_no']}",
        "specimen_ids": [ctx["specimen"]["id"], ctx["specimen_b"]["id"]],
        "target_location_id": ctx["target"]["id"],
        "handover_user_id": ctx["keeper"]["id"], "receiver_user_id": ctx["court"]["id"],
        "expires_in_minutes": ttl, "created_by": "内勤",
    })


def _scan_both(service: ForensicService, session_id: int, ctx: dict) -> None:
    """双方各自扫描清单上的两件检材，默认全部匹配。"""
    lines = [
        (ctx["specimen"]["specimen_no"], f"SEAL-{ctx['specimen']['specimen_no'][3:]}"),
        (ctx["specimen_b"]["specimen_no"], f"SEAL-{ctx['specimen_b']['specimen_no'][3:]}"),
    ]
    seq = 0
    for party in ("handover", "receiver"):
        user = ctx["keeper"] if party == "handover" else ctx["court"]
        for code, seal in lines:
            seq += 1
            service.handover.scan(session_id, {
                "party": party, "specimen_code": code, "seal_code": seal,
                "scan_key": f"scan-{session_id}-{seq:03d}",
                "user_id": user["id"], "scanner": user["display_name"],
            })


def test_handover_create_builds_expected_list_from_case_and_basis(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        ctx = _setup(service)
        session = _create_session(service, ctx)
        assert session["status"] == "open"
        assert len(session["items"]) == 2
        assert {item["specimen_no"] for item in session["items"]} == {"SP-H1", "SP-H1B"}
        assert session["discrepancies"]["consensus"] is False
        assert {d["party"] for d in session["discrepancies"]["missing"]} == {"handover", "receiver"}


def test_full_handover_transfers_custody_once(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        ctx = _setup(service)
        session = _create_session(service, ctx)
        _scan_both(service, session["id"], ctx)
        detail = service.handover.session_detail(session["id"])
        assert detail["discrepancies"]["consensus"] is True
        service.handover.confirm(session["id"], {
            "party": "handover", "password": PASSWORD_A, "user_id": ctx["keeper"]["id"],
        })
        half = service.handover.session_detail(session["id"])
        assert half["handover_confirmed_at"] and not half["receiver_confirmed_at"]
        service.handover.confirm(session["id"], {
            "party": "receiver", "password": PASSWORD_B, "user_id": ctx["court"]["id"],
        })
        done = service.handover.session_detail(session["id"])
        assert done["status"] == "completed"
        assert len(done["responsibility_chain"]) == 2
        for item in done["items"]:
            fresh = service.repository.specimen_detail(int(item["specimen_id"]))
            assert int(fresh["placements"][-1]["location_id"]) == ctx["target"]["id"]
            transfer = [m for m in fresh["movements"] if m["movement_type"] == "移交"]
            assert len(transfer) == 1
            assert int(transfer[0]["to_location_id"]) == ctx["target"]["id"]


def test_scan_feedback_detects_missing_surplus_duplicate_and_seal_mismatch(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        ctx = _setup(service)
        session = _create_session(service, ctx)
        # 交出方只扫一件 -> 另一件对交出方显示缺件；同时误扫清单外检材 -> 多件
        service.handover.scan(session["id"], {
            "party": "handover", "specimen_code": ctx["specimen"]["specimen_no"],
            "seal_code": "SEAL-H1", "scan_key": "scan-x-001",
            "user_id": ctx["keeper"]["id"], "scanner": "保管员甲",
        })
        # 多件：扫到不在清单的另案/未知编号（用已知存储但不在清单的——新登记一个）
        outsider = service.custody.create_specimen({
            "specimen_no": "SP-OUT", "case_id": ctx["case"]["id"], "parent_specimen_id": None,
            "received_year": 2026, "initial_quantity": 10, "integrity_percent": 100,
            "packaging": "封袋", "sealed_on": "2026-09-02", "seal_code": "SEAL-OUT", "created_by": "登记员",
        })
        surplus = service.handover.scan(session["id"], {
            "party": "handover", "specimen_code": outsider["specimen_no"],
            "seal_code": "SEAL-OUT", "scan_key": "scan-x-002",
            "user_id": ctx["keeper"]["id"], "scanner": "保管员甲",
        })
        assert surplus["scan"]["scan_result"] == "surplus"
        # 重复扫描同封识不再增加有效次数
        replay = service.handover.scan(session["id"], {
            "party": "handover", "specimen_code": ctx["specimen"]["specimen_no"],
            "seal_code": "SEAL-H1", "scan_key": "scan-x-003",
            "user_id": ctx["keeper"]["id"], "scanner": "保管员甲",
        })
        assert replay["scan"]["scan_result"] == "duplicate"
        # 同一扫描事件重放（相同 scan_key）返回重放标记，不新增记录
        replayed = service.handover.scan(session["id"], {
            "party": "handover", "specimen_code": ctx["specimen"]["specimen_no"],
            "seal_code": "SEAL-H1", "scan_key": "scan-x-001",
            "user_id": ctx["keeper"]["id"], "scanner": "保管员甲",
        })
        assert replayed["replayed"] is True
        count_after_replay = service.connection.execute(
            "SELECT COUNT(*) FROM handover_scans WHERE session_id=?", (session["id"],)
        ).fetchone()[0]
        detail = service.handover.session_detail(session["id"])
        assert count_after_replay == 3
        assert len(detail["discrepancies"]["duplicates"]) == 1
        assert len(detail["discrepancies"]["surplus"]) == 1
        assert any(
            d["specimen_no"] == ctx["specimen_b"]["specimen_no"] and d["party"] == "handover"
            for d in detail["discrepancies"]["missing"]
        )
        # 封识不符：接收方扫出错误封识
        wrong = service.handover.scan(session["id"], {
            "party": "receiver", "specimen_code": ctx["specimen"]["specimen_no"],
            "seal_code": "SEAL-FAKE", "scan_key": "scan-x-004",
            "user_id": ctx["court"]["id"], "scanner": "法院接收人乙",
        })
        assert wrong["scan"]["scan_result"] == "seal_mismatch"
        detail2 = service.handover.session_detail(session["id"])
        assert any(d["scanned_seal_code"] == "SEAL-FAKE" for d in detail2["discrepancies"]["seal_mismatches"])


def test_wrong_party_cannot_scan_or_confirm(client):
    with transaction(immediate=True) as connection:
        from app.core.errors import ConflictError

        service = ForensicService(connection)
        ctx = _setup(service)
        session = _create_session(service, ctx)
        try:
            service.handover.scan(session["id"], {
                "party": "receiver", "specimen_code": ctx["specimen"]["specimen_no"],
                "seal_code": "SEAL-H1", "scan_key": "scan-w-001",
                "user_id": ctx["keeper"]["id"], "scanner": "保管员甲",
            })
        except ConflictError:
            pass
        else:
            raise AssertionError("非指定身份不应能代扫")
        _scan_both(service, session["id"], ctx)
        try:
            service.handover.confirm(session["id"], {
                "party": "handover", "password": PASSWORD_A, "user_id": ctx["court"]["id"],
            })
        except ConflictError:
            pass
        else:
            raise AssertionError("接收方不应能代表交出方确认")
        try:
            service.handover.confirm(session["id"], {
                "party": "handover", "password": "wrong-password", "user_id": ctx["keeper"]["id"],
            })
        except ConflictError:
            pass
        else:
            raise AssertionError("口令错误不应能确认")
        assert service.handover.session_detail(session["id"])["status"] == "open"


def test_cannot_confirm_with_discrepancy(client):
    with transaction(immediate=True) as connection:
        from app.core.errors import ConflictError

        service = ForensicService(connection)
        ctx = _setup(service)
        # 新建会话：交出方完整扫描，接收方只扫一件 -> 缺件
        session2 = service.handover.create_session({
            "case_id": ctx["case"]["id"], "purpose": "调取", "legal_basis": "调取函-2",
            "specimen_ids": [ctx["specimen"]["id"], ctx["specimen_b"]["id"]],
            "target_location_id": ctx["target"]["id"],
            "handover_user_id": ctx["keeper"]["id"], "receiver_user_id": ctx["court"]["id"],
            "expires_in_minutes": 60, "created_by": "内勤",
        })
        for code, seal, key in [
            (ctx["specimen"]["specimen_no"], "SEAL-H1", "s2-1"),
            (ctx["specimen_b"]["specimen_no"], "SEAL-H1B", "s2-2"),
        ]:
            service.handover.scan(session2["id"], {
                "party": "handover", "specimen_code": code, "seal_code": seal, "scan_key": key,
                "user_id": ctx["keeper"]["id"], "scanner": "保管员甲",
            })
        service.handover.scan(session2["id"], {
            "party": "receiver", "specimen_code": ctx["specimen"]["specimen_no"], "seal_code": "SEAL-H1",
            "scan_key": "s2-3", "user_id": ctx["court"]["id"], "scanner": "法院接收人乙",
        })
        try:
            service.handover.confirm(session2["id"], {
                "party": "handover", "password": PASSWORD_A, "user_id": ctx["keeper"]["id"],
            })
        except ConflictError as exc:
            assert any(
                d.get("specimen_no") == ctx["specimen_b"]["specimen_no"]
                for d in exc.context["discrepancies"]["missing"]
            )
        else:
            raise AssertionError("清单不一致时不应能确认")
        assert service.handover.session_detail(session2["id"])["status"] == "open"


def test_session_expires_within_ttl_and_writes_no_transfer(client):
    clock = FrozenClock(datetime(2026, 10, 2, 8, 0, tzinfo=UTC))
    with transaction(immediate=True) as connection:
        service = ForensicService(connection, clock)
        ctx = _setup(service)
        session = _create_session(service, ctx, ttl=30)
        clock.advance(minutes=31)
        detail = service.handover.session_detail(session["id"])
        assert detail["status"] == "expired"
        from app.core.errors import ConflictError

        try:
            service.handover.scan(session["id"], {
                "party": "handover", "specimen_code": ctx["specimen"]["specimen_no"],
                "seal_code": "SEAL-H1", "scan_key": "late-001",
                "user_id": ctx["keeper"]["id"], "scanner": "保管员甲",
            })
        except ConflictError as err:
            assert "expired" in str(err)
        events = service.connection.execute(
            "SELECT COUNT(*) FROM custody_events WHERE movement_type='移交'"
        ).fetchone()[0]
        assert events == 0


def test_movement_before_confirmation_voids_session(client):
    with transaction(immediate=True) as connection:
        from app.core.errors import ConflictError

        service = ForensicService(connection)
        ctx = _setup(service)
        session = _create_session(service, ctx)
        _scan_both(service, session["id"], ctx)
        # 第三人在双方确认前对清单上的检材做普通移库
        other = service.custody.create_location({
            "location_code": "OTHER-H1", "facility": "备用库房", "room": "一室", "rack": "R9", "shelf": "S9",
            "capacity_units": 2000, "reference_value": 4, "humidity_percent": 45,
        })
        service.custody.move_placement(ctx["placement"]["id"], {
            "target_location_id": other["id"], "expected_version": ctx["placement"]["version"],
            "idempotency_key": f"move-interfere-{session['id']}", "actor": "夜班保管", "reason": "未经会话的整理",
        })
        detail = service.handover.session_detail(session["id"])
        assert detail["status"] == "voided"
        assert "移动" in detail["closure_reason"]
        # 确认时也应被拒绝（会话已结束）
        try:
            service.handover.confirm(session["id"], {
                "party": "handover", "password": PASSWORD_A, "user_id": ctx["keeper"]["id"],
            })
        except ConflictError:
            pass
        else:
            raise AssertionError("失效会话不应能确认")
        # 普通移库写入了一条移库事件，但不产生任何“移交”部分流转
        transfers = service.connection.execute(
            "SELECT COUNT(*) FROM custody_events WHERE movement_type='移交'"
        ).fetchone()[0]
        assert transfers == 0


def test_cancel_voids_session_and_no_partial_transfer(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        ctx = _setup(service)
        session = _create_session(service, ctx)
        _scan_both(service, session["id"], ctx)
        service.handover.cancel(session["id"], ctx["keeper"]["id"], {"reason": "调取函临时变更", "actor": "保管员甲"})
        detail = service.handover.session_detail(session["id"])
        assert detail["status"] == "cancelled"
        assert detail["responsibility_chain"] == []
        transfers = service.connection.execute(
            "SELECT COUNT(*) FROM custody_events WHERE movement_type='移交'"
        ).fetchone()[0]
        assert transfers == 0


def test_surplus_can_be_excluded_then_handover_completes(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        ctx = _setup(service)
        session = _create_session(service, ctx)
        _scan_both(service, session["id"], ctx)
        # 接收方多扫了一件清单外检材
        outsider = service.custody.create_specimen({
            "specimen_no": "SP-EXTRA", "case_id": ctx["case"]["id"], "parent_specimen_id": None,
            "received_year": 2026, "initial_quantity": 10, "integrity_percent": 100,
            "packaging": "封袋", "sealed_on": "2026-09-02", "seal_code": "SEAL-EXTRA", "created_by": "登记员",
        })
        extra = service.handover.scan(session["id"], {
            "party": "receiver", "specimen_code": outsider["specimen_no"],
            "seal_code": "SEAL-EXTRA", "scan_key": "extra-001",
            "user_id": ctx["court"]["id"], "scanner": "法院接收人乙",
        })
        assert service.handover.session_detail(session["id"])["discrepancies"]["consensus"] is False
        service.handover.resolve_discrepancy(session["id"], {
            "scan_id": extra["scan"]["id"], "reason": "多带封袋，非本函检材，现场剔除",
            "user_id": ctx["court"]["id"], "actor": "法院接收人乙",
        })
        assert service.handover.session_detail(session["id"])["discrepancies"]["consensus"] is True
        service.handover.confirm(session["id"], {
            "party": "handover", "password": PASSWORD_A, "user_id": ctx["keeper"]["id"],
        })
        service.handover.confirm(session["id"], {
            "party": "receiver", "password": PASSWORD_B, "user_id": ctx["court"]["id"],
        })
        assert service.handover.session_detail(session["id"])["status"] == "completed"


def test_return_session_uses_original_seal_baseline_and_freezes_on_change(client):
    with transaction(immediate=True) as connection:
        from app.core.errors import ConflictError

        service = ForensicService(connection)
        ctx = _setup(service)
        first = _create_session(service, ctx)
        _scan_both(service, first["id"], ctx)
        service.handover.confirm(first["id"], {"party": "handover", "password": PASSWORD_A, "user_id": ctx["keeper"]["id"]})
        service.handover.confirm(first["id"], {"party": "receiver", "password": PASSWORD_B, "user_id": ctx["court"]["id"]})
        assert service.handover.session_detail(first["id"])["status"] == "completed"

        # 归还沿用原会话；交出方/接收方角色互换语义（法院交出、保管室接收）
        returning = service.handover.create_session({
            "case_id": None, "purpose": "归还", "legal_basis": "检验完毕随庭审归还",
            "specimen_ids": [], "parent_session_id": first["id"],
            "handover_user_id": ctx["court"]["id"], "receiver_user_id": ctx["keeper"]["id"],
            "expires_in_minutes": 60, "created_by": "内勤",
        })
        assert returning["purpose"] == "归还"
        # 法院交出时发现封识被换
        service.handover.scan(returning["id"], {
            "party": "handover", "specimen_code": ctx["specimen"]["specimen_no"],
            "seal_code": "SEAL-H1", "scan_key": "ret-001",
            "user_id": ctx["court"]["id"], "scanner": "法院接收人乙",
        })
        changed = service.handover.scan(returning["id"], {
            "party": "handover", "specimen_code": ctx["specimen_b"]["specimen_no"],
            "seal_code": "SEAL-BROKEN", "scan_key": "ret-002",
            "user_id": ctx["court"]["id"], "scanner": "法院接收人乙",
        })
        assert changed["scan"]["scan_result"] == "seal_mismatch"
        holds = service.repository.active_holds(ctx["specimen_b"]["id"])
        assert len(holds) == 1 and holds[0]["hold_type"] == "争议"
        detail = service.handover.session_detail(returning["id"])
        assert detail["discrepancies"]["consensus"] is False
        try:
            service.handover.confirm(returning["id"], {
                "party": "handover", "password": PASSWORD_B, "user_id": ctx["court"]["id"],
            })
        except ConflictError:
            pass
        else:
            raise AssertionError("封识不符的归还不应能完成")
        # 未写入新的移交记录
        transfers = service.connection.execute(
            "SELECT COUNT(*) FROM custody_events WHERE movement_type='移交'"
        ).fetchone()[0]
        assert transfers == 2  # 仍只有调取时的两条


def test_return_session_completes_when_seals_unchanged(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        ctx = _setup(service)
        first = _create_session(service, ctx)
        _scan_both(service, first["id"], ctx)
        service.handover.confirm(first["id"], {"party": "handover", "password": PASSWORD_A, "user_id": ctx["keeper"]["id"]})
        service.handover.confirm(first["id"], {"party": "receiver", "password": PASSWORD_B, "user_id": ctx["court"]["id"]})

        returning = service.handover.create_session({
            "case_id": None, "purpose": "归还", "legal_basis": "庭审结束归还",
            "specimen_ids": [], "parent_session_id": first["id"],
            "handover_user_id": ctx["court"]["id"], "receiver_user_id": ctx["keeper"]["id"],
            "expires_in_minutes": 60, "created_by": "内勤",
        })
        # 法院交出、保管室接收，双方均按原封识核对
        lines = [
            (ctx["specimen"]["specimen_no"], "SEAL-H1"),
            (ctx["specimen_b"]["specimen_no"], "SEAL-H1B"),
        ]
        seq = 0
        for party, user in (("handover", ctx["court"]), ("receiver", ctx["keeper"])):
            for code, seal in lines:
                seq += 1
                service.handover.scan(returning["id"], {
                    "party": party, "specimen_code": code, "seal_code": seal,
                    "scan_key": f"retscan-{returning['id']}-{seq:03d}",
                    "user_id": user["id"], "scanner": user["display_name"],
                })
        service.handover.confirm(returning["id"], {"party": "handover", "password": PASSWORD_B, "user_id": ctx["court"]["id"]})
        service.handover.confirm(returning["id"], {"party": "receiver", "password": PASSWORD_A, "user_id": ctx["keeper"]["id"]})
        done = service.handover.session_detail(returning["id"])
        assert done["status"] == "completed"
        vault_location_id = ctx["placement"]["location_id"]
        for item in done["items"]:
            fresh = service.repository.specimen_detail(int(item["specimen_id"]))
            assert int(fresh["placements"][-1]["location_id"]) == vault_location_id
        transfers = service.connection.execute(
            "SELECT COUNT(*) FROM custody_events WHERE movement_type='移交'"
        ).fetchone()[0]
        assert transfers == 4  # 调取 2 条 + 归还 2 条
        # 原会话仍可追溯，且不能对同一调取重复发起未完成归还
        from app.core.errors import ConflictError

        try:
            service.handover.create_session({
                "case_id": None, "purpose": "归还", "legal_basis": "重复归还",
                "specimen_ids": [], "parent_session_id": first["id"],
                "handover_user_id": ctx["court"]["id"], "receiver_user_id": ctx["keeper"]["id"],
                "expires_in_minutes": 60, "created_by": "内勤",
            })
        except ConflictError:
            pass
        else:
            raise AssertionError("已完成归还的调取会话不应再发起归还")


def test_completing_one_session_voids_other_open_sessions_with_same_specimen(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        ctx = _setup(service)
        first = _create_session(service, ctx)
        second = service.handover.create_session({
            "case_id": ctx["case"]["id"], "purpose": "调取", "legal_basis": "另一份调取函",
            "specimen_ids": [ctx["specimen"]["id"]],
            "target_location_id": ctx["target"]["id"],
            "handover_user_id": ctx["keeper"]["id"], "receiver_user_id": ctx["court"]["id"],
            "expires_in_minutes": 60, "created_by": "内勤",
        })
        _scan_both(service, first["id"], ctx)
        service.handover.confirm(first["id"], {"party": "handover", "password": PASSWORD_A, "user_id": ctx["keeper"]["id"]})
        service.handover.confirm(first["id"], {"party": "receiver", "password": PASSWORD_B, "user_id": ctx["court"]["id"]})
        assert service.handover.session_detail(first["id"])["status"] == "completed"
        other = service.handover.session_detail(second["id"])
        assert other["status"] == "voided"
        # 第二个会话不产生任何移交事件
        assert other["responsibility_chain"] == []


def test_handover_list_and_stage_events_visible(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        ctx = _setup(service)
        session = _create_session(service, ctx)
        _scan_both(service, session["id"], ctx)
        listing = service.handover.list_sessions(case_id=ctx["case"]["id"], status="open", limit=20, offset=0)
        assert listing["total"] >= 1
        detail = service.handover.session_detail(session["id"])
        stages = [event["stage"] for event in detail["stage_events"]]
        assert stages[0] == "created"
        assert stages.count("scanned") == 4
