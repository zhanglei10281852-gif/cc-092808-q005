from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.forensics.repository import ForensicRepository, record

ACTIVE_STATUSES = ("open", "handover_confirmed", "receiver_confirmed")
PARTIES = ("交出方", "接收方")


class HandoverService:
    """有期限的检材交接会话。

    会话在双方各自完成扫描、差异全部清零并分别以各自身份确认后才一次性转移
    全部检材的保管责任与位置；超时、撤销或确认前检材被他人移动都会令整次会话
    失效，不写入任何部分流转。扫描事件带幂等键，重放不增加扫描次数。
    """

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.repository = ForensicRepository(connection)

    # ------------------------------------------------------------------ 创建
    def create_session(self, data: dict[str, Any]) -> dict[str, Any]:
        direction = data["direction"]
        if direction not in {"调取", "归还"}:
            raise ValidationError("交接方向必须为调取或归还")
        forensic_case = self.repository.require_forensic_case(int(data["case_id"]))
        if forensic_case["status"] not in {"accepted", "restricted", "quarantine"}:
            raise ConflictError("案件未受理，不能发起检材交接")
        if self.repository.handover_session_by_no(data["session_no"]):
            raise ConflictError("交接会话编号已经存在")

        origin: dict[str, Any] | None = None
        target_location_id = data.get("target_location_id")
        if not target_location_id:
            raise ValidationError("交接必须指定接收库位，以便一次性转移检材位置")
        target_location = self.repository.require_location(int(target_location_id))
        if target_location["status"] != "active":
            raise ConflictError("交接目标库位当前不可用")
        if direction == "归还":
            origin_id = data.get("origin_session_id")
            if not origin_id:
                raise ValidationError("归还会话必须关联原调取交接会话")
            origin = self.repository.require_handover_session(int(origin_id))
            if origin["direction"] != "调取" or origin["status"] != "completed":
                raise ConflictError("只能针对已完成的调取会话发起归还")
            if int(origin["forensic_case_id"]) != int(forensic_case["id"]):
                raise ValidationError("归还会话与原调取会话的案件不一致")

        handover_party = str(data["handover_party"]).strip()
        receiver_party = str(data["receiver_party"]).strip()
        if not handover_party or not receiver_party:
            raise ValidationError("必须明确交出方与接收方")
        if handover_party == receiver_party:
            raise ValidationError("交出方与接收方不能是同一方")
        if data.get("initiating_party", "接收方") not in PARTIES:
            raise ValidationError("发起方身份必须是交出方或接收方")

        now = self.clock.now()
        timestamp = to_storage(now)
        ttl_minutes = int(data.get("ttl_minutes", 120))
        if not 5 <= ttl_minutes <= 1440:
            raise ValidationError("交接有效期必须在 5 到 1440 分钟之间")
        expires_at = to_storage(now.replace(microsecond=0) + _minutes(ttl_minutes))

        try:
            cursor = self.connection.execute(
                "INSERT INTO handover_sessions(session_no,forensic_case_id,direction,legal_basis,basis_document_no,"
                "origin_session_id,status,initiating_party,initiated_by,handover_party,receiver_party,"
                "target_location_id,expires_at,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,'open',?,?,?,?,?,?,?,?)",
                (
                    data["session_no"], forensic_case["id"], direction, data["legal_basis"],
                    data.get("basis_document_no", ""), origin["id"] if origin else None,
                    data.get("initiating_party", receiver_party), data["initiated_by"],
                    handover_party, receiver_party, target_location_id, expires_at, timestamp, timestamp,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("交接会话编号已经存在") from exc
        session_id = int(cursor.lastrowid)

        if direction == "归还":
            self._populate_return_items(session_id, origin)
        else:
            self._populate_request_items(session_id, forensic_case["id"], data.get("items", []))

        self._stage(session_id, "created", data["initiated_by"], {
            "direction": direction,
            "legal_basis": data["legal_basis"],
            "basis_document_no": data.get("basis_document_no", ""),
            "item_count": len(self.repository.handover_expected_items(session_id)),
            "expires_at": expires_at,
        })
        return self.detail(session_id)

    def _populate_request_items(self, session_id: int, case_id: int, raw_items: list[dict[str, Any]]) -> None:
        if not raw_items:
            raise ValidationError("调取交接必须依据调取函列明预期检材清单")
        seen: set[int] = set()
        for ordinal, raw in enumerate(raw_items, start=1):
            specimen = self._resolve_specimen(raw, case_id)
            if specimen["id"] in seen:
                raise ValidationError(f"检材 {specimen['specimen_no']} 在预期清单中重复出现")
            if int(specimen["case_id"]) != case_id:
                raise ValidationError(f"检材 {specimen['specimen_no']} 不属于本次交接案件")
            if specimen["status"] in {"depleted", "disposed"}:
                raise ConflictError(f"检材 {specimen['specimen_no']} 已耗尽或销毁，不能交接")
            seal_code = (raw.get("expected_seal_code") or "").strip()
            if not seal_code:
                raise ValidationError(f"检材 {specimen['specimen_no']} 缺少调取函登记的封识编号")
            placement = self._active_placement(specimen["id"])
            if placement is None:
                raise ConflictError(f"检材 {specimen['specimen_no']} 当前不在库，无法调取交接")
            seen.add(specimen["id"])
            last_event_id = self._last_custody_event_id(specimen["id"])
            self.connection.execute(
                "INSERT INTO handover_expected_items(session_id,specimen_id,ordinal,expected_seal_code,"
                "expected_packaging,expected_location_id,baseline_seal_code,baseline_packaging,"
                "baseline_location_id,baseline_placement_id,baseline_last_event_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    session_id, specimen["id"], ordinal, seal_code, specimen.get("packaging", ""),
                    placement["location_id"], seal_code, specimen.get("packaging", ""),
                    placement["location_id"], placement["id"], last_event_id,
                ),
            )

    def _populate_return_items(self, session_id: int, origin: dict[str, Any]) -> None:
        transfers = self.repository.handover_liability_transfers(int(origin["id"]))
        if not transfers:
            raise ConflictError("原调取会话没有责任转移记录，不能据此归还")
        for ordinal, transfer in enumerate(transfers, start=1):
            specimen = self.repository.require_specimen(int(transfer["specimen_id"]))
            last_event_id = self._last_custody_event_id(specimen["id"])
            self.connection.execute(
                "INSERT INTO handover_expected_items(session_id,specimen_id,ordinal,expected_seal_code,"
                "expected_packaging,expected_location_id,baseline_seal_code,baseline_packaging,"
                "baseline_location_id,baseline_placement_id,baseline_last_event_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    session_id, specimen["id"], ordinal, transfer["seal_after"],
                    specimen.get("packaging", ""), transfer["to_location_id"],
                    transfer["seal_before"], specimen.get("packaging", ""),
                    transfer["from_location_id"], None, last_event_id,
                ),
            )
    # ------------------------------------------------------------------ 扫描
    def scan(self, session_id: int, data: dict[str, Any]) -> dict[str, Any]:
        session = self._require_active(session_id)
        if session["status"] != "open":
            raise ConflictError("已有一方完成确认，扫描与差异处置已锁定")
        party = data["party"]
        if party not in PARTIES:
            raise ValidationError("扫描方必须是交出方或接收方")
        items = self.repository.handover_expected_items(session_id)
        item_by_specimen = {int(item["specimen_id"]): item for item in items}

        previous = self.connection.execute(
            "SELECT * FROM handover_scans WHERE session_id=? AND idempotency_key=?",
            (session_id, data["idempotency_key"]),
        ).fetchone()
        if previous is not None:
            scan = record(previous)
            return {"scan": scan, "replayed": True, "differences": self.evaluate(session_id),
                    "session_status": session["status"]}

        kind = data["scan_kind"]
        if kind not in {"specimen", "seal"}:
            raise ValidationError("扫描类型必须是检材 specimen 或封识 seal")
        code = str(data["code"]).strip()
        if not code:
            raise ValidationError("扫描编码不能为空")

        specimen_id: int | None = None
        item: dict[str, Any] | None = None
        if kind == "specimen":
            specimen = self.connection.execute("SELECT * FROM specimens WHERE specimen_no=?", (code,)).fetchone()
            if specimen is not None:
                specimen_id = int(specimen["id"])
                item = item_by_specimen.get(specimen_id)
            # 扫到系统或清单之外的封袋：记为多件，而不是拒收
        else:
            specimen_ref = str(data.get("specimen_code") or "").strip()
            if specimen_ref:
                specimen = self.connection.execute("SELECT * FROM specimens WHERE specimen_no=?", (specimen_ref,)).fetchone()
                if specimen is not None:
                    specimen_id = int(specimen["id"])
                    item = item_by_specimen.get(specimen_id)

        result = self._classify_scan(session_id, party, kind, code, item)
        timestamp = to_storage(self.clock.now())
        scan_seq = int(self.connection.execute(
            "SELECT COALESCE(MAX(scan_seq),0)+1 FROM handover_scans WHERE session_id=? AND party=?",
            (session_id, party),
        ).fetchone()[0])
        cursor = self.connection.execute(
            "INSERT INTO handover_scans(session_id,expected_item_id,specimen_id,party,scan_kind,scanned_code,"
            "seal_code,scan_result,scan_seq,idempotency_key,scanned_by,note,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                session_id, item["id"] if item else None, specimen_id, party, kind, code,
                code if kind == "seal" else None, result, scan_seq, data["idempotency_key"],
                data["scanned_by"], data.get("note", ""), timestamp,
            ),
        )
        scan = record(self.connection.execute("SELECT * FROM handover_scans WHERE id=?", (cursor.lastrowid,)).fetchone())
        self._touch(session_id, timestamp)
        differences = self.evaluate(session_id)
        self._stage(session_id, "scanned", data["scanned_by"], {
            "party": party, "scan_kind": kind, "specimen_id": specimen_id, "result": result,
        })
        return {"scan": scan, "replayed": False, "differences": differences, "session_status": "open"}

    def _classify_scan(
        self, session_id: int, party: str, kind: str, code: str, item: dict[str, Any] | None
    ) -> str:
        if item is None:
            return "unexpected"
        if kind == "specimen":
            count = int(self.connection.execute(
                "SELECT COUNT(*) FROM handover_scans WHERE session_id=? AND party=? AND specimen_id=? "
                "AND scan_kind='specimen' AND voided_at IS NULL",
                (session_id, party, item["specimen_id"]),
            ).fetchone()[0])
            return "duplicate" if count >= 1 else "matched"
        count = int(self.connection.execute(
            "SELECT COUNT(*) FROM handover_scans WHERE session_id=? AND party=? AND specimen_id=? "
            "AND scan_kind='seal' AND voided_at IS NULL",
            (session_id, party, item["specimen_id"]),
        ).fetchone()[0])
        if count >= 1:
            return "duplicate"
        return "matched" if code == str(item["expected_seal_code"]) else "seal_mismatch"

    def void_scan(self, session_id: int, scan_id: int, data: dict[str, Any]) -> dict[str, Any]:
        session = self._require_active(session_id)
        if session["status"] != "open":
            raise ConflictError("已有一方完成确认，不能再处置扫描差异")
        scan = record(self.connection.execute(
            "SELECT * FROM handover_scans WHERE id=? AND session_id=?", (scan_id, session_id)
        ).fetchone())
        if scan is None:
            raise NotFoundError("扫描记录不存在")
        if scan["voided_at"]:
            return {"scan": scan, "replayed": True, "differences": self.evaluate(session_id)}
        timestamp = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE handover_scans SET voided_at=?,voided_by=?,void_reason=? WHERE id=? AND voided_at IS NULL",
            (timestamp, data["actor"], data["reason"], scan_id),
        )
        scan = record(self.connection.execute("SELECT * FROM handover_scans WHERE id=?", (scan_id,)).fetchone())
        self._stage(session_id, "disposition_recorded", data["actor"], {
            "party": scan["party"], "scan_id": scan_id, "voided_result": scan["scan_result"],
            "specimen_id": scan["specimen_id"], "reason": data["reason"],
        })
        return {"scan": scan, "replayed": False, "differences": self.evaluate(session_id),
                "session_status": session["status"]}

    # ------------------------------------------------------------------ 差异
    def evaluate(self, session_id: int) -> dict[str, Any]:
        session = self.repository.require_handover_session(session_id)
        items = self.repository.handover_expected_items(session_id)
        scans = [row for row in self.repository.handover_scans(session_id) if not row["voided_at"]]

        missing: list[dict[str, Any]] = []
        duplicates: list[dict[str, Any]] = []
        seal_mismatches: list[dict[str, Any]] = []
        unexpected: list[dict[str, Any]] = []
        matched: list[dict[str, Any]] = []

        specimen_numbers: dict[int, str] = {}
        if items:
            placeholders = ",".join("?" * len(items))
            specimen_numbers = {
                int(row["id"]): row["specimen_no"]
                for row in self.connection.execute(
                    f"SELECT id,specimen_no FROM specimens WHERE id IN ({placeholders})",
                    [int(item["specimen_id"]) for item in items],
                ).fetchall()
            }

        for scan in scans:
            if scan["expected_item_id"] is None:
                unexpected.append(_scan_ref(scan))

        for item in items:
            specimen_no = specimen_numbers.get(int(item["specimen_id"]), str(item["specimen_id"]))
            for party in PARTIES:
                spec_scans = [s for s in scans if s["party"] == party and s["specimen_id"] == item["specimen_id"]
                              and s["scan_kind"] == "specimen"]
                seal_scans = [s for s in scans if s["party"] == party and s["specimen_id"] == item["specimen_id"]
                              and s["scan_kind"] == "seal"]
                if len(spec_scans) == 0:
                    missing.append({"party": party, "specimen_id": item["specimen_id"], "specimen_no": specimen_no})
                if len(spec_scans) > 1:
                    duplicates.append({"party": party, "specimen_id": item["specimen_id"], "specimen_no": specimen_no,
                                       "scan_kind": "specimen", "count": len(spec_scans)})
                if len(seal_scans) > 1:
                    duplicates.append({"party": party, "specimen_id": item["specimen_id"], "specimen_no": specimen_no,
                                       "scan_kind": "seal", "count": len(seal_scans)})
                for seal_scan in seal_scans:
                    if seal_scan["seal_code"] != str(item["expected_seal_code"]):
                        seal_mismatches.append({
                            "party": party, "specimen_id": item["specimen_id"], "specimen_no": specimen_no,
                            "expected_seal_code": item["expected_seal_code"],
                            "scanned_seal_code": seal_scan["seal_code"], "scan_id": seal_scan["id"],
                        })
                if (len(spec_scans) == 1 and len(seal_scans) == 1
                        and seal_scans[0]["seal_code"] == str(item["expected_seal_code"])):
                    matched.append({"party": party, "specimen_id": item["specimen_id"], "specimen_no": specimen_no})

        no_count_diff = not (missing or unexpected or duplicates)
        consistent = no_count_diff and not seal_mismatches and len(matched) == len(items) * 2
        return_consistent = no_count_diff
        if session["direction"] == "归还":
            can_confirm = return_consistent
        else:
            can_confirm = consistent
        return {
            "ready": can_confirm and session["status"] == "open",
            "consistent": consistent,
            "return_consistent": return_consistent,
            "matched": matched,
            "missing": missing,
            "unexpected": unexpected,
            "duplicates": duplicates,
            "seal_mismatches": seal_mismatches,
            "seal_changes": seal_mismatches if session["direction"] == "归还" else [],
            "matched_count": len(matched),
            "expected_party_count": len(items) * 2,
        }

    # ------------------------------------------------------------------ 确认
    def confirm(self, session_id: int, data: dict[str, Any], confirmer_id: int) -> dict[str, Any]:
        session = self._require_active(session_id)
        party = data["party"]
        if party not in PARTIES:
            raise ValidationError("确认方必须是交出方或接收方")
        already_confirmer = session["handover_confirmer_id"] if party == "交出方" else session["receiver_confirmer_id"]
        if already_confirmer is not None:
            raise ConflictError(f"{party}已经完成确认，不能重复确认")
        other_confirmer = session["receiver_confirmer_id"] if party == "交出方" else session["handover_confirmer_id"]
        if other_confirmer is not None and int(other_confirmer) == int(confirmer_id):
            raise ConflictError("双方必须使用各自身份确认，不能由同一人代表双方")

        differences = self.evaluate(session_id)
        if session["direction"] == "调取":
            can_confirm = differences["consistent"]
        else:
            can_confirm = differences["return_consistent"]
        if not can_confirm:
            raise ConflictError("清单尚未一致或存在未处置差异，不能确认交接", context={
                "missing": len(differences["missing"]),
                "unexpected": len(differences["unexpected"]),
                "duplicates": len(differences["duplicates"]),
                "seal_mismatches": len(differences["seal_mismatches"]),
            })

        self._guard_unchanged(session)
        timestamp = to_storage(self.clock.now())
        if party == "交出方":
            self.connection.execute(
                "UPDATE handover_sessions SET handover_confirmer=?,handover_confirmer_id=?,"
                "handover_confirmed_at=?,version=version+1,updated_at=? WHERE id=?",
                (data["confirmer"], confirmer_id, timestamp, timestamp, session_id),
            )
        else:
            self.connection.execute(
                "UPDATE handover_sessions SET receiver_confirmer=?,receiver_confirmer_id=?,"
                "receiver_confirmed_at=?,version=version+1,updated_at=? WHERE id=?",
                (data["confirmer"], confirmer_id, timestamp, timestamp, session_id),
            )
        self._stage(session_id, "party_confirmed", data["confirmer"], {"party": party})

        session = self.repository.require_handover_session(session_id)
        if session["handover_confirmed_at"] and session["receiver_confirmed_at"]:
            return self._complete(session, timestamp)
        status = "handover_confirmed" if party == "交出方" else "receiver_confirmed"
        self.connection.execute("UPDATE handover_sessions SET status=? WHERE id=?", (status, session_id))
        return self.detail(session_id)

    def _complete(self, session: dict[str, Any], timestamp: str) -> dict[str, Any]:
        session_id = int(session["id"])
        self._guard_unchanged(session)
        items = self.repository.handover_expected_items(session_id)
        self._validate_target_capacity(session, items)
        scans = [row for row in self.repository.handover_scans(session_id) if not row["voided_at"]]
        frozen: list[dict[str, Any]] = []

        for ordinal, item in enumerate(items, start=1):
            specimen_id = int(item["specimen_id"])
            receiver_seals = [s for s in scans if s["party"] == "接收方" and s["specimen_id"] == specimen_id
                              and s["scan_kind"] == "seal"]
            seal_after = receiver_seals[0]["seal_code"] if receiver_seals else item["expected_seal_code"]
            if session["direction"] == "调取":
                event_id, from_location, to_location = self._transfer_request(session, item, timestamp)
                from_party, to_party = session["handover_party"], session["receiver_party"]
            else:
                event_id, from_location, to_location = self._transfer_return(session, item, timestamp)
                from_party, to_party = session["handover_party"], session["receiver_party"]
                if str(seal_after) != str(item["expected_seal_code"]):
                    self._freeze_specimen(session, item, seal_after, timestamp)
                    frozen.append({"specimen_id": specimen_id, "expected": item["expected_seal_code"],
                                   "actual": seal_after})
            self.connection.execute(
                "INSERT INTO handover_liability_transfers(session_id,specimen_id,sequence_no,from_party,to_party,"
                "from_location_id,to_location_id,seal_before,seal_after,custody_event_id,transferred_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    session_id, specimen_id, ordinal, from_party, to_party, from_location, to_location,
                    item["expected_seal_code"], seal_after, event_id, timestamp,
                ),
            )

        self.connection.execute(
            "UPDATE handover_sessions SET status='completed',completed_at=?,closed_at=?,closure_reason='',"
            "version=version+1,updated_at=? WHERE id=?",
            (timestamp, timestamp, timestamp, session_id),
        )
        self._stage(session_id, "completed", "system", {
            "transferred": len(items), "frozen": frozen,
            "handover_confirmer": session["handover_confirmer"], "receiver_confirmer": session["receiver_confirmer"],
        })
        return self.detail(session_id)

    def _validate_target_capacity(self, session: dict[str, Any], items: list[dict[str, Any]]) -> None:
        target_id = int(session["target_location_id"])
        target = self.repository.require_location(target_id)
        if target["status"] != "active":
            self._abort(int(session["id"]), "接收库位当前不可用，整次交接失效")
        incoming = 0.0
        for item in items:
            placement = self._active_placement(int(item["specimen_id"]))
            if placement is None:
                incoming += 1.0
            elif int(placement["location_id"]) != target_id:
                incoming += float(placement["quantity"])
        used = self.repository.location_usage(target_id)
        if used + incoming > float(target["capacity_units"]) + 1e-9:
            self._abort(int(session["id"]), "接收库位容量不足，整次交接失效")

    def _transfer_request(self, session: dict[str, Any], item: dict[str, Any], timestamp: str) -> tuple[int, Any, Any]:
        specimen_id = int(item["specimen_id"])
        placement = self._active_placement(specimen_id)
        if placement is None or int(placement["id"]) != int(item["baseline_placement_id"]):
            self._close(int(session["id"]), "invalidated", "检材在确认前已被移动，交接失效", "system", timestamp)
            raise ConflictError("检材在确认前已被移动，整次交接失效")
        target_location_id = session["target_location_id"]
        from_location_id = placement["location_id"]
        new_placement_id: int | None = None
        if target_location_id:
            handover_container = f"{placement['container_code']}-H{session['id']}"
            cursor = self.connection.execute(
                "INSERT INTO specimen_placements(specimen_id,location_id,quantity,container_code,placed_at) "
                "VALUES(?,?,?,?,?)",
                (specimen_id, target_location_id, placement["quantity"], handover_container, timestamp),
            )
            new_placement_id = int(cursor.lastrowid)
        self.connection.execute(
            "UPDATE specimen_placements SET removed_at=?,version=version+1 WHERE id=? AND removed_at IS NULL",
            (timestamp, placement["id"]),
        )
        event_key = f"handover-{session['id']}-{specimen_id}"
        cursor = self.connection.execute(
            "INSERT INTO custody_events(specimen_id,placement_id,movement_type,quantity,from_location_id,"
            "to_location_id,idempotency_key,actor,reason,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                specimen_id, new_placement_id, "交接", placement["quantity"], from_location_id,
                target_location_id, event_key, session["receiver_confirmer"] or session["initiated_by"],
                f"交接会话 {session['session_no']} 当庭调取", timestamp,
            ),
        )
        return int(cursor.lastrowid), from_location_id, target_location_id

    def _transfer_return(self, session: dict[str, Any], item: dict[str, Any], timestamp: str) -> tuple[int, Any, Any]:
        specimen_id = int(item["specimen_id"])
        target_location_id = int(session["target_location_id"])
        placement = self._active_placement(specimen_id)
        container_code = f"RET-{session['session_no']}-{item['ordinal']}"
        quantity = 1.0
        from_location_id = item["expected_location_id"]
        if placement is not None:
            quantity = float(placement["quantity"])
            from_location_id = placement["location_id"]
            self.connection.execute(
                "UPDATE specimen_placements SET removed_at=?,version=version+1 WHERE id=? AND removed_at IS NULL",
                (timestamp, placement["id"]),
            )
        cursor = self.connection.execute(
            "INSERT INTO specimen_placements(specimen_id,location_id,quantity,container_code,placed_at) "
            "VALUES(?,?,?,?,?)",
            (specimen_id, target_location_id, quantity, container_code, timestamp),
        )
        new_placement_id = int(cursor.lastrowid)
        event_key = f"handover-{session['id']}-{specimen_id}"
        cursor = self.connection.execute(
            "INSERT INTO custody_events(specimen_id,placement_id,movement_type,quantity,from_location_id,"
            "to_location_id,idempotency_key,actor,reason,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                specimen_id, new_placement_id, "交接", quantity, from_location_id,
                target_location_id, event_key, session["receiver_confirmer"] or session["initiated_by"],
                f"交接会话 {session['session_no']} 庭后归还", timestamp,
            ),
        )
        self.connection.execute(
            "UPDATE specimens SET status='stored',version=version+1,updated_at=? WHERE id=? "
            "AND status NOT IN ('depleted','disposed')",
            (timestamp, specimen_id),
        )
        return int(cursor.lastrowid), from_location_id, target_location_id

    def _freeze_specimen(self, session: dict[str, Any], item: dict[str, Any], actual_seal: str, timestamp: str) -> None:
        specimen_id = int(item["specimen_id"])
        existing = self.connection.execute(
            "SELECT 1 FROM specimen_holds WHERE specimen_id=? AND hold_type='争议' AND released_at IS NULL",
            (specimen_id,),
        ).fetchone()
        if existing:
            return
        self.connection.execute(
            "INSERT INTO specimen_holds(specimen_id,hold_type,reason,imposed_by,imposed_at) VALUES(?,?,?,?,?)",
            (
                specimen_id, "争议",
                f"归还会话 {session['session_no']} 封识变化：应为 {item['expected_seal_code']}，实际 {actual_seal}",
                "system", timestamp,
            ),
        )
        self.connection.execute(
            "UPDATE specimens SET status='held',version=version+1,updated_at=? WHERE id=? "
            "AND status NOT IN ('depleted','disposed')",
            (timestamp, specimen_id),
        )
        self._stage(int(session["id"]), "frozen", "system", {
            "specimen_id": specimen_id, "expected_seal_code": item["expected_seal_code"],
            "actual_seal_code": actual_seal,
        })

    # ------------------------------------------------------------------ 失效
    def revoke(self, session_id: int, data: dict[str, Any]) -> dict[str, Any]:
        self._require_active(session_id)
        timestamp = to_storage(self.clock.now())
        self._close(session_id, "revoked", data.get("reason") or "发起方撤销交接", data["actor"], timestamp)
        return self.detail(session_id)

    def expire_due_sessions(self) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        rows = self.connection.execute(
            "SELECT id FROM handover_sessions WHERE status IN ('open','handover_confirmed','receiver_confirmed') "
            "AND expires_at<=?",
            (now,),
        ).fetchall()
        expired: list[int] = []
        for row in rows:
            timestamp = to_storage(self.clock.now())
            self._close(int(row["id"]), "expired", "超过交接会话有效期", "system", timestamp)
            expired.append(int(row["id"]))
        return {"expired_session_ids": expired, "count": len(expired)}

    def invalidate_for_external_move(self, specimen_id: int, reason: str) -> list[int]:
        """供普通移库/领用路径调用：让涉及该检材的活动会话立即失效。"""
        timestamp = to_storage(self.clock.now())
        rows = self.connection.execute(
            "SELECT id FROM handover_sessions WHERE status IN ('open','handover_confirmed','receiver_confirmed') "
            "AND id IN (SELECT session_id FROM handover_expected_items WHERE specimen_id=?)",
            (specimen_id,),
        ).fetchall()
        invalidated = []
        for row in rows:
            self._close(int(row["id"]), "invalidated", reason, "system", timestamp)
            invalidated.append(int(row["id"]))
        return invalidated

    def _guard_unchanged(self, session: dict[str, Any]) -> None:
        """确认前最后一道防线：会话建立后检材被本会话之外的流转改动即失效。"""
        session_id = int(session["id"])
        if session["status"] not in ACTIVE_STATUSES:
            raise ConflictError("交接会话已经结束")
        items = self.repository.handover_expected_items(session_id)
        for item in items:
            specimen_id = int(item["specimen_id"])
            if session["direction"] == "调取":
                placement = self._active_placement(specimen_id)
                if placement is None or int(placement["id"]) != int(item["baseline_placement_id"]):
                    self._abort(session_id, "检材在双方确认前被移动，整次交接失效")
            baseline_last = item["baseline_last_event_id"] or 0
            moved = self.connection.execute(
                "SELECT 1 FROM custody_events WHERE specimen_id=? AND id>? "
                "AND idempotency_key NOT LIKE ? LIMIT 1",
                (specimen_id, baseline_last, f"handover-{session_id}-%"),
            ).fetchone()
            if moved is not None:
                self._abort(session_id, "检材在双方确认前出现会话外流转，整次交接失效")

    def _abort(self, session_id: int, reason: str) -> None:
        self._close(session_id, "invalidated", reason, "system", to_storage(self.clock.now()))
        raise ConflictError(reason)

    # ------------------------------------------------------------------ 查询
    def detail(self, session_id: int) -> dict[str, Any]:
        detail = self.repository.handover_session_detail(session_id)
        detail["differences"] = self.evaluate(session_id) if detail["status"] in ACTIVE_STATUSES else None
        detail["is_expired"] = (
            detail["status"] in ACTIVE_STATUSES and to_storage(self.clock.now()) >= detail["expires_at"]
        )
        return detail

    def list_sessions(
        self, *, case_id: int | None = None, status: str | None = None, limit: int = 50, offset: int = 0
    ) -> dict[str, Any]:
        items, total = self.repository.list_handover_sessions(
            case_id=case_id, status=status, limit=limit, offset=offset
        )
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    # ------------------------------------------------------------------ 辅助
    def _require_active(self, session_id: int) -> dict[str, Any]:
        session = self.repository.require_handover_session(session_id)
        # 只做只读拦截；超时状态由读路径与 expire-due 维护任务惰性持久化，
        # 避免在随后抛错回滚的写事务里留下未落库的状态变更。
        if to_storage(self.clock.now()) >= session["expires_at"] and session["status"] in ACTIVE_STATUSES:
            raise ConflictError("交接会话已超时失效", context={"status": "expired"})
        if session["status"] not in ACTIVE_STATUSES:
            raise ConflictError("交接会话已经结束", context={"status": session["status"]})
        return session

    def _close(self, session_id: int, status: str, reason: str, actor: str, timestamp: str) -> None:
        session = self.repository.require_handover_session(session_id)
        if session["status"] not in ACTIVE_STATUSES:
            return
        self.connection.execute(
            "UPDATE handover_sessions SET status=?,closed_at=?,closure_reason=?,version=version+1,updated_at=? WHERE id=?",
            (status, timestamp, reason, timestamp, session_id),
        )
        self._stage(session_id, status, actor, {"reason": reason})

    def _stage(self, session_id: int, stage: str, actor: str, detail: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO handover_stage_events(session_id,stage,actor,detail_json,created_at) VALUES(?,?,?,?,?)",
            (session_id, stage, actor, json.dumps(detail, ensure_ascii=False, sort_keys=True), to_storage(self.clock.now())),
        )

    def _touch(self, session_id: int, timestamp: str) -> None:
        self.connection.execute("UPDATE handover_sessions SET updated_at=? WHERE id=?", (timestamp, session_id))

    def _resolve_specimen(self, raw: dict[str, Any], case_id: int) -> dict[str, Any]:
        specimen_id = raw.get("specimen_id")
        if specimen_id:
            specimen = self.repository.require_specimen(int(specimen_id))
        else:
            specimen_no = str(raw.get("specimen_no") or "").strip().upper()
            if not specimen_no:
                raise ValidationError("预期清单每项必须包含检材编号或检材ID")
            row = self.connection.execute("SELECT * FROM specimens WHERE specimen_no=?", (specimen_no,)).fetchone()
            if row is None:
                raise NotFoundError(f"检材 {specimen_no} 不存在")
            specimen = record(row)
        return specimen  # type: ignore[return-value]

    def _active_placement(self, specimen_id: int) -> dict[str, Any] | None:
        return record(self.connection.execute(
            "SELECT * FROM specimen_placements WHERE specimen_id=? AND removed_at IS NULL ORDER BY id DESC LIMIT 1",
            (specimen_id,),
        ).fetchone())

    def _last_custody_event_id(self, specimen_id: int) -> int:
        row = self.connection.execute(
            "SELECT MAX(id) AS last_id FROM custody_events WHERE specimen_id=?", (specimen_id,)
        ).fetchone()
        return int(row["last_id"] or 0)


def _minutes(value: int):
    from datetime import timedelta

    return timedelta(minutes=value)


def _scan_ref(scan: dict[str, Any]) -> dict[str, Any]:
    return {
        "scan_id": scan["id"], "party": scan["party"], "scan_kind": scan["scan_kind"],
        "specimen_id": scan["specimen_id"], "scanned_code": scan["scanned_code"],
        "result": scan["scan_result"], "scanned_by": scan["scanned_by"],
    }
