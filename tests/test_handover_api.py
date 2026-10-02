from __future__ import annotations


def _bootstrap_case(client, headers, suffix="APIH"):
    source = client.post("/api/forensics/agencies", headers=headers, json={
        "agency_code": f"ORG-{suffix}", "agency_name": "市公安局物证中心", "jurisdiction_code": "CN",
        "contact_address": "司法路 8 号", "restrictions": {},
    })
    assert source.status_code == 201, source.text
    case = client.post("/api/forensics/cases", headers=headers, json={
        "case_no": f"CASE-{suffix}", "case_name": "开庭前调取", "discipline": "法医物证",
        "entrusted_matter": "庭审出示", "agency_id": source.json()["id"], "case_source": "委托",
        "accepted_on": "2026-10-01", "passport": {"warrant": f"调字-{suffix}"}, "created_by": "内勤",
    })
    assert case.status_code == 201, case.text
    accepted = client.post(f"/api/forensics/cases/{case.json()['id']}/transition", headers=headers, json={
        "target_status": "accepted", "reason": "齐全", "expected_version": 1, "actor": "审核员",
    })
    assert accepted.status_code == 200, accepted.text
    vault = client.post("/api/forensics/locations", headers=headers, json={
        "location_code": f"VAULT-{suffix}", "facility": "保管室", "room": "冷藏", "rack": "R1", "shelf": "S1",
        "capacity_units": 1000, "reference_value": 4, "humidity_percent": 45,
    })
    court = client.post("/api/forensics/locations", headers=headers, json={
        "location_code": f"COURT-{suffix}", "facility": "法院物证室", "room": "接收区", "rack": "C1", "shelf": "S1",
        "capacity_units": 1000, "reference_value": 4, "humidity_percent": 45,
    })
    specimen = client.post("/api/forensics/specimens", headers=headers, json={
        "specimen_no": f"SP-{suffix}", "case_id": accepted.json()["id"], "received_year": 2026,
        "initial_quantity": 100, "integrity_percent": 100, "packaging": "防拆封袋",
        "sealed_on": "2026-10-01", "seal_code": f"SEAL-{suffix}", "created_by": "登记员",
    })
    assert specimen.status_code == 201, specimen.text
    placed = client.post("/api/forensics/placements", headers=headers, json={
        "specimen_id": specimen.json()["id"], "location_id": vault.json()["id"], "quantity": 100,
        "container_code": f"BOX-{suffix}", "idempotency_key": f"place-{suffix}-0001", "actor": "保管员",
    })
    assert placed.status_code == 201, placed.text
    return accepted.json(), specimen.json(), court.json()


def _login(client, username, password):
    resp = client.post("/api/auth/login", json={"username": username, "password": password, "client_label": "test"})
    assert resp.status_code == 200, resp.text
    token = resp.json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_handover_api_end_to_end(client, admin):
    admin_h = admin["headers"]
    case, specimen, court = _bootstrap_case(client, admin_h)
    client.post("/api/users", headers=admin_h, json={
        "username": "keeper01", "password": "Keeper!23456", "display_name": "保管员甲",
        "role_codes": ["registrar"],
    })
    client.post("/api/users", headers=admin_h, json={
        "username": "receiver01", "password": "Receive!23456", "display_name": "法院接收人乙",
        "role_codes": ["registrar"],
    })
    keeper_h = _login(client, "keeper01", "Keeper!23456")
    receiver_h = _login(client, "receiver01", "Receive!23456")
    keeper_id = client.get("/api/users?status=active", headers=admin_h).json()
    users = {item["username"]: item["id"] for item in keeper_id["data"]}

    created = client.post("/api/forensics/handovers", headers=admin_h, json={
        "case_id": case["id"], "purpose": "调取", "legal_basis": f"法院调取函 调字-{case['case_no']}",
        "specimen_ids": [specimen["id"]], "target_location_id": court["id"],
        "handover_user_id": users["keeper01"], "receiver_user_id": users["receiver01"],
        "expires_in_minutes": 30,
    })
    assert created.status_code == 201, created.text
    session_id = created.json()["id"]
    assert created.json()["session_no"].startswith("HO-")

    for index, headers in enumerate((keeper_h, receiver_h), start=1):
        scanned = client.post(f"/api/forensics/handovers/{session_id}/scans", headers=headers, json={
            "party": "handover" if headers is keeper_h else "receiver",
            "specimen_code": specimen["specimen_no"], "seal_code": "SEAL-APIH",
            "scan_key": f"api-scan-{index:04d}",
        })
        assert scanned.status_code == 201, scanned.text

    detail = client.get(f"/api/forensics/handovers/{session_id}", headers=admin_h)
    assert detail.json()["discrepancies"]["consensus"] is True

    first = client.post(f"/api/forensics/handovers/{session_id}/confirm", headers=keeper_h, json={
        "party": "handover", "password": "Keeper!23456",
    })
    assert first.status_code == 200, first.text
    # 只确认一方不转移责任
    assert first.json()["status"] == "open"
    assert first.json()["responsibility_chain"] == []

    second = client.post(f"/api/forensics/handovers/{session_id}/confirm", headers=receiver_h, json={
        "party": "receiver", "password": "Receive!23456",
    })
    assert second.status_code == 200, second.text
    body = second.json()
    assert body["status"] == "completed"
    assert len(body["responsibility_chain"]) == 1
    assert body["responsibility_chain"][0]["transfer_event"]["to_location_id"] == court["id"]

    specimen_after = client.get(f"/api/forensics/specimens/{specimen['id']}", headers=admin_h).json()
    assert specimen_after["placements"][-1]["location_id"] == court["id"]

    listing = client.get(f"/api/forensics/handovers?case_id={case['id']}", headers=admin_h)
    assert listing.json()["total"] == 1
    stages = [event["stage"] for event in body["stage_events"]]
    assert stages == ["created", "scanned", "scanned", "handover_confirmed", "receiver_confirmed", "completed"]


def test_handover_api_seal_mismatch_blocks_confirmation(client, admin):
    admin_h = admin["headers"]
    case, specimen, court = _bootstrap_case(client, admin_h, suffix="APIHB")
    client.post("/api/users", headers=admin_h, json={
        "username": "keeper02", "password": "Keeper!23456", "display_name": "保管员甲", "role_codes": ["registrar"],
    })
    client.post("/api/users", headers=admin_h, json={
        "username": "receiver02", "password": "Receive!23456", "display_name": "法院接收人乙", "role_codes": ["registrar"],
    })
    keeper_h = _login(client, "keeper02", "Keeper!23456")
    receiver_h = _login(client, "receiver02", "Receive!23456")
    users = {
        item["username"]: item["id"]
        for item in client.get("/api/users?status=active", headers=admin_h).json()["data"]
    }
    created = client.post("/api/forensics/handovers", headers=admin_h, json={
        "case_id": case["id"], "purpose": "调取", "legal_basis": "调取函-BAD",
        "specimen_ids": [specimen["id"]], "target_location_id": court["id"],
        "handover_user_id": users["keeper02"], "receiver_user_id": users["receiver02"],
        "expires_in_minutes": 30,
    })
    session_id = created.json()["id"]
    client.post(f"/api/forensics/handovers/{session_id}/scans", headers=keeper_h, json={
        "party": "handover", "specimen_code": specimen["specimen_no"], "seal_code": "SEAL-APIHB",
        "scan_key": "bad-scan-0001",
    })
    client.post(f"/api/forensics/handovers/{session_id}/scans", headers=receiver_h, json={
        "party": "receiver", "specimen_code": specimen["specimen_no"], "seal_code": "SEAL-TAMPERED",
        "scan_key": "bad-scan-0002",
    })
    denied = client.post(f"/api/forensics/handovers/{session_id}/confirm", headers=keeper_h, json={
        "party": "handover", "password": "Keeper!23456",
    })
    assert denied.status_code == 409
    assert denied.json()["error"]["context"]["discrepancies"]["seal_mismatches"]
