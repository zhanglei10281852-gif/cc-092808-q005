from __future__ import annotations


def _make_user(client, admin, username, display_name):
    created = client.post("/api/users", headers=admin["headers"], json={
        "username": username, "password": "Handover!2345", "display_name": display_name,
        "role_codes": ["registrar"],
    })
    assert created.status_code == 201, created.text
    login = client.post("/api/auth/login", json={
        "username": username, "password": "Handover!2345", "client_label": "handover-tests",
    })
    assert login.status_code == 200, login.text
    token = login.json()["token"]
    return {"headers": {"Authorization": f"Bearer {token}"}, "user": login.json()["user"],
            "display_name": display_name}


def _setup_case_with_specimen(client, headers, suffix="H1"):
    agency = client.post("/api/forensics/agencies", headers=headers, json={
        "agency_code": f"HORG-{suffix}", "agency_name": "区分局", "jurisdiction_code": "CN",
        "contact_address": "司法路 1 号", "restrictions": {},
    })
    assert agency.status_code == 201, agency.text
    case = client.post("/api/forensics/cases", headers=headers, json={
        "case_no": f"HCASE-{suffix}", "case_name": "庭审调取鉴定", "discipline": "法医物证",
        "entrusted_matter": "出庭质证", "agency_id": agency.json()["id"], "case_source": "委托",
        "accepted_on": "2026-09-20", "passport": {"commission_document": f"DOC-{suffix}"}, "created_by": "登记员",
    })
    assert case.status_code == 201, case.text
    accepted = client.post(f"/api/forensics/cases/{case.json()['id']}/transition", headers=headers, json={
        "target_status": "accepted", "reason": "齐全", "expected_version": 1, "actor": "审核员",
    })
    assert accepted.status_code == 200, accepted.text
    vault = client.post("/api/forensics/locations", headers=headers, json={
        "location_code": f"HVAULT-{suffix}", "facility": "保管室", "room": "冷藏区", "rack": "R1", "shelf": "S1",
        "capacity_units": 1000, "reference_value": 4, "humidity_percent": 45,
    })
    assert vault.status_code == 201, vault.text
    court = client.post("/api/forensics/locations", headers=headers, json={
        "location_code": f"HCOURT-{suffix}", "facility": "法院物证柜", "room": "庭审区", "rack": "C1", "shelf": "S1",
        "capacity_units": 1000, "reference_value": 4, "humidity_percent": 45,
    })
    assert court.status_code == 201, court.text
    specimen = client.post("/api/forensics/specimens", headers=headers, json={
        "specimen_no": f"HSP-{suffix}", "case_id": accepted.json()["id"], "received_year": 2026,
        "initial_quantity": 3, "integrity_percent": 100, "packaging": "防拆封袋",
        "sealed_on": "2026-09-21", "created_by": "登记员",
    })
    assert specimen.status_code == 201, specimen.text
    placed = client.post("/api/forensics/placements", headers=headers, json={
        "specimen_id": specimen.json()["id"], "location_id": vault.json()["id"], "quantity": 3,
        "container_code": f"HBOX-{suffix}", "idempotency_key": f"hplace-{suffix}", "actor": "保管员",
    })
    assert placed.status_code == 201, placed.text
    return accepted.json(), specimen.json(), vault.json(), court.json()


def test_handover_api_full_flow_with_two_identities(client, admin):
    headers = admin["headers"]
    case, specimen, vault, court = _setup_case_with_specimen(client, headers)

    created = client.post("/api/forensics/handovers", headers=headers, json={
        "session_no": "HHO-1", "case_id": case["id"], "direction": "调取",
        "legal_basis": "出庭调取函 HCOURT-2026", "basis_document_no": "TJH-2026-1",
        "initiating_party": "接收方", "initiated_by": "法院接收人",
        "handover_party": "鉴定机构保管室", "receiver_party": "区人民法院",
        "target_location_id": court["id"], "ttl_minutes": 60,
        "items": [{"specimen_id": specimen["id"], "expected_seal_code": "HSEAL-1"}],
    })
    assert created.status_code == 201, created.text
    session = created.json()
    session_id = session["id"]
    assert session["status"] == "open"
    assert session["expected_items"][0]["baseline_placement_id"]

    keeper = _make_user(client, admin, "keeper01", "保管员")
    court_user = _make_user(client, admin, "receiver01", "法院接收人")

    def scan(auth, party, who, kind, code, key, specimen_code=None):
        resp = client.post(f"/api/forensics/handovers/{session_id}/scans", headers=auth, json={
            "party": party, "scan_kind": kind, "code": code, "specimen_code": specimen_code,
            "idempotency_key": key, "scanned_by": who,
        })
        assert resp.status_code == 201, resp.text
        return resp.json()

    # 封袋编号不在调取函上：多件被实时指出
    ghost = scan(keeper["headers"], "交出方", "保管员", "specimen", "BAG-NOT-ON-LIST", "ghost-001")
    assert ghost["scan"]["scan_result"] == "unexpected"
    assert ghost["differences"]["unexpected"]
    client.post(f"/api/forensics/handovers/{session_id}/scans/{ghost['scan']['id']}/void",
                headers=keeper["headers"], json={"actor": "保管员", "reason": "非本次检材，移出"})

    scan(keeper["headers"], "交出方", "保管员", "specimen", "HSP-H1", "keeper-spec-1")
    mismatch = scan(keeper["headers"], "交出方", "保管员", "seal", "HSEAL-BAD", "keeper-seal-bad",
                    specimen_code="HSP-H1")
    assert mismatch["differences"]["seal_mismatches"]
    # 封识不符时确认被拒
    blocked = client.post(f"/api/forensics/handovers/{session_id}/confirm", headers=keeper["headers"],
                          json={"party": "交出方", "confirmer": "保管员"})
    assert blocked.status_code == 409, blocked.text

    # 作废误扫的封识，改扫正确封识
    client.post(f"/api/forensics/handovers/{session_id}/scans/{mismatch['scan']['id']}/void",
                headers=keeper["headers"], json={"actor": "保管员", "reason": "误扫旧封识"})
    scan(keeper["headers"], "交出方", "保管员", "seal", "HSEAL-1", "keeper-seal-1", specimen_code="HSP-H1")

    scan(court_user["headers"], "接收方", "法院接收人", "specimen", "HSP-H1", "recv-spec-1")
    scan(court_user["headers"], "接收方", "法院接收人", "seal", "HSEAL-1", "recv-seal-1", specimen_code="HSP-H1")

    # 相同扫描事件重放不增加次数
    replay = scan(court_user["headers"], "接收方", "法院接收人", "seal", "HSEAL-1", "recv-seal-1",
                  specimen_code="HSP-H1")
    assert replay["replayed"] is True

    # 交出方先用自己身份确认
    ok1 = client.post(f"/api/forensics/handovers/{session_id}/confirm", headers=keeper["headers"],
                      json={"party": "交出方", "confirmer": "保管员"})
    assert ok1.status_code == 200, ok1.text

    # 同一登录身份不能再代表接收方确认
    same = client.post(f"/api/forensics/handovers/{session_id}/confirm", headers=keeper["headers"],
                       json={"party": "接收方", "confirmer": "保管员"})
    assert same.status_code == 409, same.text

    # 必须由接收方本人身份确认后责任才一次性转移
    ok2 = client.post(f"/api/forensics/handovers/{session_id}/confirm", headers=court_user["headers"],
                      json={"party": "接收方", "confirmer": "法院接收人"})
    assert ok2.status_code == 200, ok2.text
    completed = ok2.json()
    assert completed["status"] == "completed"

    detail = client.get(f"/api/forensics/handovers/{session_id}", headers=headers)
    assert detail.status_code == 200, detail.text
    body = detail.json()
    # 双方各自的身份确认
    assert body["handover_confirmer"] == "保管员"
    assert body["receiver_confirmer"] == "法院接收人"
    assert body["handover_confirmer_id"] != body["receiver_confirmer_id"]
    # 阶段、差异处置、最终责任链可通过 API 查看
    stages = [e["stage"] for e in body["stage_events"]]
    assert "created" in stages and "party_confirmed" in stages and "completed" in stages
    assert "disposition_recorded" in stages
    chain = body["liability_chain"]
    assert len(chain) == 1
    assert chain[0]["from_party"] == "鉴定机构保管室"
    assert chain[0]["to_party"] == "区人民法院"
    assert chain[0]["to_location_id"] == court["id"]


def test_handover_api_requires_authentication(client):
    assert client.get("/api/forensics/handovers").status_code == 401


def test_handover_api_rejects_confirmation_with_unexpected_bag(client, admin):
    headers = admin["headers"]
    case, specimen, vault, court = _setup_case_with_specimen(client, headers, suffix="H2")
    created = client.post("/api/forensics/handovers", headers=headers, json={
        "session_no": "HHO-2", "case_id": case["id"], "direction": "调取",
        "legal_basis": "出庭调取函", "basis_document_no": "TJH-2",
        "initiating_party": "接收方", "initiated_by": "法院接收人",
        "handover_party": "鉴定机构保管室", "receiver_party": "区人民法院",
        "target_location_id": court["id"], "ttl_minutes": 60,
        "items": [{"specimen_id": specimen["id"], "expected_seal_code": "HSEAL-2"}],
    })
    assert created.status_code == 201, created.text
    session_id = created.json()["id"]
    # 完全不扫描直接确认 -> 缺件
    resp = client.post(f"/api/forensics/handovers/{session_id}/confirm", headers=headers,
                       json={"party": "交出方", "confirmer": "保管员"})
    assert resp.status_code == 409
    assert resp.json()["error"]["context"]["missing"] == 2


def test_handover_read_path_lazily_persists_expiry(client):
    # GET 列表/详情端点在读取前先执行 expire_due_sessions()，这里按相同顺序验证
    from datetime import UTC, datetime

    from app.core.clock import FrozenClock
    from app.database import transaction
    from app.forensics.service import ForensicService
    from tests.test_forensics_workflow import create_stored_lot

    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        clock = FrozenClock(datetime(2026, 10, 2, 8, 0, tzinfo=UTC))
        service.handovers.clock = clock
        forensic_case, specimen, _placement = create_stored_lot(service, "HAPI")
        target = service.custody.create_location({
            "location_code": "COURT-HAPI", "facility": "法院物证柜", "room": "庭审区",
            "rack": "C1", "shelf": "S1", "capacity_units": 1000, "reference_value": 4, "humidity_percent": 45,
        })
        session = service.handovers.create_session({
            "session_no": "HO-HAPI", "case_id": forensic_case["id"], "direction": "调取",
            "legal_basis": "出庭调取函", "basis_document_no": "TJH-HAPI",
            "initiating_party": "接收方", "initiated_by": "法院接收人",
            "handover_party": "鉴定机构保管室", "receiver_party": "区人民法院",
            "target_location_id": target["id"], "ttl_minutes": 120,
            "items": [{"specimen_id": specimen["id"], "expected_seal_code": "SEAL-HAPI"}],
        })
        clock.advance(minutes=121)
        # 与 GET 端点一致：先落定超时，再取详情
        result = service.handovers.expire_due_sessions()
        assert session["id"] in result["expired_session_ids"]
        detail = service.handovers.detail(session["id"])
        assert detail["status"] == "expired"
        assert any(e["stage"] == "expired" for e in detail["stage_events"])
