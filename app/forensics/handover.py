from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, to_microseconds, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.security import verify_password
from app.forensics.repository import ForensicRepository, record, records


def void_open_handovers(connection: sqlite3.Connection, specimen_id: int, reason: str, timestamp: str) -> list[int]:
    """检材在交接确认前被其他流程移动时，作废所有涉及它的未完成会话（不写入任何部分流转）。"""
    rows = connection.execute(
        "SELECT hs.id FROM handover_sessions hs "
        "JOIN handover_items hi ON hi.session_id=hs.id "
        "WHERE hi.specimen_id=? AND hs.status='open' ORDER BY hs.id",
        (specimen_id,),
    ).fetchall()
    voided = [int(row["id"]) for row in rows]
    for session_id in voided:
        connection.execute(
            "UPDATE handover_sessions SET status='voided',closure_reason=?,version=version+1,updated_at=? WHERE id=?",
            (reason, timestamp, session_id),
        )
        connection.execute(
            "INSERT INTO handover_stage_events(session_id,stage,actor,detail_json,created_at) VALUES(?,?,?,?,?)",
            (session_id, "voided", "system", json.dumps({"reason": reason}, ensure_ascii=False), timestamp),
        )
    return voided


class HandoverService:
    """有期限的双人交接会话：清单一致且双方身份确认后一次性转移保管责任。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.repository = ForensicRepository(connection)

    # ------------------------------------------------------------------ 创建
    def create_session(self, data: dict[str, Any]) -> dict[str, Any]:
        timestamp = to_storage(self.clock.now())
        purpose = data.get("purpose", "调取")
        handover_user = self._require_user(int(data["handover_user_id"]))
        receiver_user = self._require_user(int(data["receiver_user_id"]))
        if handover_user["id"] == receiver_user["id"]:
            raise ValidationError("交出方与接收方不能是同一身份")
        if purpose == "归还":
            session = self._create_return_session(data, handover_user, receiver_user, timestamp)
        else:
            session = self._create_dispatch_session(data, handover_user, receiver_user, timestamp)
        self._stage(session["id"], "created", data["created_by"], {"purpose": purpose}, timestamp)
        return self.session_detail(session["id"])

    def _create_dispatch_session(
        self, data: dict[str, Any], handover_user: dict, receiver_user: dict, timestamp: str
    ) -> dict:
        forensic_case = self.repository.require_forensic_case(int(data["case_id"]))
        if forensic_case["status"] not in {"accepted", "restricted"}:
            raise ConflictError("案件尚未正式受理，不能发起调取交接")
        if not data.get("target_location_id"):
            raise ValidationError("调取交接必须指定接收库位")
        target = self.repository.require_location(int(data["target_location_id"]))
        if target["status"] != "active":
            raise ConflictError("接收库位当前不可用")
        specimen_ids = list(dict.fromkeys(int(value) for value in data["specimen_ids"]))
        if len(specimen_ids) != len(data["specimen_ids"]):
            raise ValidationError("预期清单中存在重复检材")
        snapshots = [self._snapshot_item(forensic_case["id"], specimen_id) for specimen_id in specimen_ids]
        total_quantity = sum(float(item["quantity"]) for item in snapshots)
        if self.repository.location_usage(target["id"]) + total_quantity > float(target["capacity_units"]) + 1e-9:
            raise ConflictError("接收库位容量不足", context={"available_grams": target["capacity_units"]})
        session_id = self._insert_session(
            case_id=forensic_case["id"], purpose="调取", legal_basis=data["legal_basis"],
            parent_session_id=None, target_location_id=target["id"],
            handover_user=handover_user, receiver_user=receiver_user,
            items=snapshots, created_by=data["created_by"],
            created_by_user_id=data.get("created_by_user_id"),
            ttl_minutes=int(data["expires_in_minutes"]), timestamp=timestamp,
        )
        return record(self.connection.execute("SELECT * FROM handover_sessions WHERE id=?", (session_id,)).fetchone()) or {}

    def _create_return_session(
        self, data: dict[str, Any], handover_user: dict, receiver_user: dict, timestamp: str
    ) -> dict:
        parent_id = data.get("parent_session_id")
        if not parent_id:
            raise ValidationError("归还交接必须关联原调取会话")
        parent = record(self.connection.execute(
            "SELECT * FROM handover_sessions WHERE id=?", (int(parent_id),)
        ).fetchone())
        if parent is None:
            raise NotFoundError("原调取会话不存在")
        if parent["purpose"] != "调取" or parent["status"] != "completed":
            raise ConflictError("只能沿用已完成的调取会话发起归还")
        existing = self.connection.execute(
            "SELECT id FROM handover_sessions WHERE parent_session_id=? AND status IN ('open','completed')",
            (parent["id"],),
        ).fetchone()
        if existing:
            raise ConflictError("该调取会话已有进行中的归还交接", context={"session_id": existing["id"]})
        parent_items = records(self.connection.execute(
            "SELECT * FROM handover_items WHERE session_id=? ORDER BY id", (parent["id"],)
        ).fetchall())
        snapshots: list[dict] = []
        for parent_item in parent_items:
            specimen = self.repository.require_specimen(int(parent_item["specimen_id"]))
            transfer_event = record(self.connection.execute(
                "SELECT * FROM custody_events WHERE idempotency_key=?",
                (f"handover-{parent['id']}-{parent_item['id']}",),
            ).fetchone())
            if transfer_event is None:
                raise ConflictError("原调取会话缺少移交记录，不能发起归还", context={"specimen_id": specimen["id"]})
            placement = self._active_placement(specimen["id"])
            if placement is None:
                raise ConflictError(
                    "检材当前不在架，不能纳入归还会话", context={"specimen_id": specimen["id"]}
                )
            if int(placement["location_id"]) != int(parent["target_location_id"]):
                raise ConflictError(
                    "检材不在原调取接收库位，不能按原会话归还", context={"specimen_id": specimen["id"]}
                )
            if self.repository.active_holds(specimen["id"]):
                raise ConflictError("检材存在未解除冻结，不能纳入归还会话", context={"specimen_id": specimen["id"]})
            snapshots.append({
                "specimen_id": specimen["id"],
                "specimen_no": specimen["specimen_no"],
                "seal_code": parent_item["expected_seal_code"],
                "placement_id": int(placement["id"]),
                "placement_version": int(placement["version"]),
                "location_id": int(placement["location_id"]),
                "quantity": float(placement["quantity"]),
                "target_location_id": int(transfer_event["from_location_id"]),
            })
        session_id = self._insert_session(
            case_id=int(parent["case_id"]), purpose="归还", legal_basis=data["legal_basis"],
            parent_session_id=int(parent["id"]), target_location_id=None,
            handover_user=handover_user, receiver_user=receiver_user,
            items=snapshots, created_by=data["created_by"],
            created_by_user_id=data.get("created_by_user_id"),
            ttl_minutes=int(data["expires_in_minutes"]), timestamp=timestamp,
        )
        return record(self.connection.execute("SELECT * FROM handover_sessions WHERE id=?", (session_id,)).fetchone()) or {}

    def _insert_session(
        self, *, case_id: int, purpose: str, legal_basis: str, parent_session_id: int | None,
        target_location_id: int | None, handover_user: dict, receiver_user: dict,
        items: list[dict], created_by: str, created_by_user_id: int | None, ttl_minutes: int, timestamp: str,
    ) -> int:
        digest = hashlib.sha256(
            "|".join(f"{item['specimen_id']}:{item['seal_code']}" for item in items).encode()
        ).hexdigest()
        expires_at = to_storage(self.clock.now() + timedelta(minutes=ttl_minutes))
        cursor = self.connection.execute(
            "INSERT INTO handover_sessions(case_id,purpose,legal_basis,parent_session_id,status,expected_seal_digest,"
            "target_location_id,handover_party_user_id,handover_party_name,receiver_party_user_id,receiver_party_name,"
            "expires_at,created_by_user_id,created_by,created_at,updated_at) VALUES(?,?,?,?, 'open', ?,?,?,?,?,?,?,?,?,?,?)",
            (
                case_id, purpose, legal_basis, parent_session_id, digest, target_location_id,
                handover_user["id"], handover_user["display_name"], receiver_user["id"], receiver_user["display_name"],
                expires_at, created_by_user_id, created_by, timestamp, timestamp,
            ),
        )
        session_id = int(cursor.lastrowid)
        session_no = f"HO-{session_id:08d}"
        self.connection.execute("UPDATE handover_sessions SET session_no=? WHERE id=?", (session_no, session_id))
        for item in items:
            self.connection.execute(
                "INSERT INTO handover_items(session_id,specimen_id,expected_seal_code,expected_placement_id,"
                "expected_placement_version,expected_location_id) VALUES(?,?,?,?,?,?)",
                (
                    session_id, item["specimen_id"], item["seal_code"], item["placement_id"],
                    item["placement_version"], item["target_location_id" if purpose == "归还" else "location_id"],
                ),
            )
        return session_id

    def _snapshot_item(self, case_id: int, specimen_id: int) -> dict:
        specimen = self.repository.require_specimen(specimen_id)
        if int(specimen["case_id"]) != case_id:
            raise ValidationError(f"检材 {specimen['specimen_no']} 不属于该案件")
        if not specimen["seal_code"]:
            raise ValidationError(f"检材 {specimen['specimen_no']} 未登记封识编号，不能发起交接")
        placement = self._active_placement(specimen_id)
        if placement is None:
            raise ConflictError("检材当前不在架，不能纳入交接清单", context={"specimen_id": specimen_id})
        if self.repository.active_holds(specimen_id):
            raise ConflictError("检材存在未解除冻结，不能纳入交接清单", context={"specimen_id": specimen_id})
        return {
            "specimen_id": specimen_id,
            "specimen_no": specimen["specimen_no"],
            "seal_code": specimen["seal_code"],
            "placement_id": int(placement["id"]),
            "placement_version": int(placement["version"]),
            "location_id": int(placement["location_id"]),
            "quantity": float(placement["quantity"]),
        }

    # ------------------------------------------------------------------ 扫描
    def scan(self, session_id: int, data: dict[str, Any]) -> dict[str, Any]:
        timestamp = to_storage(self.clock.now())
        self._expire_if_due(session_id, timestamp)
        session = self._require_open_session(session_id)
        if session["handover_confirmed_at"] or session["receiver_confirmed_at"]:
            raise ConflictError("已有一方完成确认，扫描清单已锁定；如有差异请撤销后重新发起会话")
        party = data["party"]
        self._require_party_principal(session, party, int(data["user_id"]))
        specimen_code = str(data["specimen_code"]).strip().upper()
        seal_code = str(data["seal_code"]).strip().upper()
        scan_key = str(data["scan_key"]).strip()
        specimen = record(self.connection.execute(
            "SELECT * FROM specimens WHERE specimen_no=?", (specimen_code,)
        ).fetchone())
        item = None
        if specimen is not None:
            item = record(self.connection.execute(
                "SELECT * FROM handover_items WHERE session_id=? AND specimen_id=?",
                (session_id, specimen["id"]),
            ).fetchone())
        previous = record(self.connection.execute(
            "SELECT * FROM handover_scans WHERE session_id=? AND party=? AND specimen_code=? "
            "AND disposition='' ORDER BY id DESC LIMIT 1",
            (session_id, party, specimen_code),
        ).fetchone())
        result: str
        supersede_scan_id: int | None = None
        if item is None:
            result = "surplus"
        elif previous is not None and previous["seal_code"] == seal_code:
            result = "duplicate"
        else:
            result = "matched" if seal_code == item["expected_seal_code"] else "seal_mismatch"
            if previous is not None:
                supersede_scan_id = int(previous["id"])
        try:
            cursor = self.connection.execute(
                "INSERT INTO handover_scans(session_id,item_id,specimen_id,party,specimen_code,seal_code,"
                "scan_result,scan_key,scanner,scanned_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    session_id, item["id"] if item else None, specimen["id"] if specimen else None,
                    party, specimen_code, seal_code, result, scan_key, data["scanner"], timestamp,
                ),
            )
        except sqlite3.IntegrityError as exc:
            existing = record(self.connection.execute(
                "SELECT * FROM handover_scans WHERE session_id=? AND scan_key=?", (session_id, scan_key)
            ).fetchone())
            if existing is not None:
                if (
                    existing["party"] != party
                    or existing["specimen_code"] != specimen_code
                    or existing["seal_code"] != seal_code
                ):
                    raise ConflictError("同一扫描事件键对应了不同的扫描数据")
                return {"scan": existing, "replayed": True, "session": self.session_detail(session_id)}
            raise ConflictError("扫描事件键冲突") from exc
        scan_id = int(cursor.lastrowid)
        frozen = False
        if supersede_scan_id is not None:
            self.connection.execute(
                "UPDATE handover_scans SET disposition='excluded',disposition_reason='被更正扫描取代',"
                "disposed_by='system',disposed_at=? WHERE id=?",
                (timestamp, supersede_scan_id),
            )
            self._stage(
                session_id, "scan_corrected", data["scanner"],
                {"superseded_scan_id": supersede_scan_id, "scan_id": scan_id, "party": party}, timestamp,
            )
        if result == "seal_mismatch" and session["purpose"] == "归还":
            frozen = self._freeze_for_seal_change(
                int(item["specimen_id"]), item["expected_seal_code"], seal_code, data["scanner"], timestamp
            )
        self._stage(
            session_id, "scanned", data["scanner"],
            {"scan_id": scan_id, "party": party, "result": result, "specimen_code": specimen_code,
             "seal_code": seal_code, "auto_frozen": frozen},
            timestamp,
        )
        return {"scan": self._scan_row(scan_id), "replayed": False, "session": self.session_detail(session_id)}

    def resolve_discrepancy(self, session_id: int, data: dict[str, Any]) -> dict[str, Any]:
        timestamp = to_storage(self.clock.now())
        self._expire_if_due(session_id, timestamp)
        session = self._require_open_session(session_id)
        if session["handover_confirmed_at"] or session["receiver_confirmed_at"]:
            raise ConflictError("已有一方完成确认，差异处置已锁定；如需中止请撤销会话")
        scan = self._scan_row(int(data["scan_id"]))
        if int(scan["session_id"]) != session_id:
            raise NotFoundError("扫描记录不属于该会话")
        expected_user = (
            int(session["handover_party_user_id"]) if scan["party"] == "handover"
            else int(session["receiver_party_user_id"])
        )
        if int(data["user_id"]) != expected_user:
            raise ConflictError("只有产生该扫描的一方可以剔除多件")
        if scan["disposition"] == "excluded":
            raise ConflictError("该扫描已经处置")
        if scan["scan_result"] != "surplus":
            raise ValidationError("仅多件扫描可以作为差异剔除")
        self.connection.execute(
            "UPDATE handover_scans SET disposition='excluded',disposition_reason=?,disposed_by=?,disposed_at=? WHERE id=?",
            (data["reason"], data["actor"], timestamp, scan["id"]),
        )
        self._stage(
            session_id, "discrepancy_resolved", data["actor"],
            {"scan_id": scan["id"], "specimen_code": scan["specimen_code"], "reason": data["reason"]}, timestamp,
        )
        return self.session_detail(session_id)

    # ------------------------------------------------------------------ 确认
    def confirm(self, session_id: int, data: dict[str, Any]) -> dict[str, Any]:
        timestamp = to_storage(self.clock.now())
        self._expire_if_due(session_id, timestamp)
        session = self._require_open_session(session_id)
        party = data["party"]
        user_id = int(session["handover_party_user_id"] if party == "handover" else session["receiver_party_user_id"])
        if int(data["user_id"]) != user_id:
            raise ConflictError("当前登录身份不是该方指定的交接人，不能代为确认")
        user = self._require_user(user_id)
        if not verify_password(str(data["password"]), str(user["password_hash"])):
            self._stage(
                session_id, "confirm_rejected", user["display_name"],
                {"party": party, "reason": "口令核验失败"}, timestamp,
            )
            self.connection.commit()
            raise ConflictError("身份口令核验失败，不能代表该方确认")
        if (party == "handover" and session["handover_confirmed_at"]) or (
            party == "receiver" and session["receiver_confirmed_at"]
        ):
            raise ConflictError("该方已经完成确认")
        discrepancies = self._discrepancies(session)
        if discrepancies["interfered"]:
            reason = "检材在确认前被移动，交接会话失效"
            self._void(session, reason, timestamp)
            self.connection.commit()
            raise ConflictError(reason, context={"interfered": discrepancies["interfered"]})
        if not discrepancies["consensus"]:
            raise ConflictError("清单尚未一致，不能确认", context={"discrepancies": discrepancies})
        self._validate_transfer(session, timestamp)
        if party == "handover":
            self.connection.execute(
                "UPDATE handover_sessions SET handover_confirmed_at=?,version=version+1,updated_at=? WHERE id=?",
                (timestamp, timestamp, session_id),
            )
        else:
            self.connection.execute(
                "UPDATE handover_sessions SET receiver_confirmed_at=?,version=version+1,updated_at=? WHERE id=?",
                (timestamp, timestamp, session_id),
            )
        self._stage(session_id, f"{party}_confirmed", user["display_name"], {"user_id": user_id}, timestamp)
        if party == "receiver" or (
            party == "handover" and session["receiver_confirmed_at"]
        ):
            refreshed = record(self.connection.execute(
                "SELECT * FROM handover_sessions WHERE id=?", (session_id,)
            ).fetchone()) or {}
            if refreshed["handover_confirmed_at"] and refreshed["receiver_confirmed_at"]:
                self._complete_transfer(refreshed, timestamp)
        return self.session_detail(session_id)

    def cancel(self, session_id: int, user_id: int, data: dict[str, Any]) -> dict:
        timestamp = to_storage(self.clock.now())
        self._expire_if_due(session_id, timestamp)
        session = self._require_open_session(session_id)
        allowed = {
            int(session["handover_party_user_id"]),
            int(session["receiver_party_user_id"]),
        }
        creator_id = session["created_by_user_id"]
        if creator_id is not None:
            allowed.add(int(creator_id))
        if user_id not in allowed:
            raise ConflictError("只有发起人或交接双方可以撤销会话")
        self.connection.execute(
            "UPDATE handover_sessions SET status='cancelled',closure_reason=?,version=version+1,updated_at=? WHERE id=?",
            (data["reason"], timestamp, session_id),
        )
        self._stage(session_id, "cancelled", data["actor"], {"reason": data["reason"]}, timestamp)
        return self.session_detail(session_id)

    def sweep_expired(self) -> dict[str, Any]:
        timestamp = to_storage(self.clock.now())
        rows = self.connection.execute(
            "SELECT id FROM handover_sessions WHERE status='open' AND expires_at<=? ORDER BY id", (timestamp,)
        ).fetchall()
        expired_ids = [int(row["id"]) for row in rows]
        for session_id in expired_ids:
            session = record(self.connection.execute(
                "SELECT * FROM handover_sessions WHERE id=?", (session_id,)
            ).fetchone()) or {}
            self._expire(session, timestamp)
        if expired_ids:
            self.connection.commit()
        return {"expired_session_ids": expired_ids, "count": len(expired_ids)}

    # ------------------------------------------------------------------ 转移
    def _validate_transfer(self, session: dict, timestamp: str) -> None:
        """双方确认前的统一预检：任一检材被移动或目标库位不可用即作废整次会话。"""
        items = records(self.connection.execute(
            "SELECT * FROM handover_items WHERE session_id=? ORDER BY id", (session["id"],)
        ).fetchall())
        planned: list[tuple[int, int, float]] = []
        for item in items:
            placement = record(self.connection.execute(
                "SELECT * FROM specimen_placements WHERE id=? AND removed_at IS NULL",
                (item["expected_placement_id"],),
            ).fetchone())
            if placement is None or int(placement["version"]) != int(item["expected_placement_version"]):
                reason = "检材在确认前被移动，交接会话失效"
                self._void(session, reason, timestamp)
                self.connection.commit()
                raise ConflictError(reason, context={"specimen_id": item["specimen_id"]})
            holds = self.repository.active_holds(int(item["specimen_id"]))
            if holds:
                reason = "检材存在未解除冻结，交接失效"
                self._void(session, reason, timestamp)
                self.connection.commit()
                raise ConflictError(reason, context={"specimen_id": item["specimen_id"], "holds": [h["id"] for h in holds]})
            target_location_id = (
                int(session["target_location_id"])
                if session["purpose"] == "调取"
                else int(item["expected_location_id"])
            )
            planned.append((int(item["specimen_id"]), target_location_id, float(placement["quantity"])))
        loads: dict[int, float] = {}
        for _, target_location_id, quantity in planned:
            loads[target_location_id] = loads.get(target_location_id, 0.0) + quantity
        for target_location_id, incoming in loads.items():
            target = self.repository.require_location(target_location_id)
            if target["status"] != "active":
                reason = f"目标库位 {target['location_code']} 不可用，交接失效"
                self._void(session, reason, timestamp)
                self.connection.commit()
                raise ConflictError("目标库位当前不可用，整次交接失效")
            if self.repository.location_usage(target_location_id) + incoming > float(target["capacity_units"]) + 1e-9:
                reason = f"目标库位 {target['location_code']} 容量不足，交接失效"
                self._void(session, reason, timestamp)
                self.connection.commit()
                raise ConflictError("目标库位容量不足，整次交接失效")

    def _complete_transfer(self, session: dict, timestamp: str) -> None:
        items = records(self.connection.execute(
            "SELECT * FROM handover_items WHERE session_id=? ORDER BY id", (session["id"],)
        ).fetchall())
        purpose_label = "调取移交" if session["purpose"] == "调取" else "归还入库"
        for item in items:
            placement = record(self.connection.execute(
                "SELECT * FROM specimen_placements WHERE id=? AND removed_at IS NULL",
                (item["expected_placement_id"],),
            ).fetchone())
            if placement is None or int(placement["version"]) != int(item["expected_placement_version"]):
                raise ConflictError("检材在确认前已被移动，整次交接失效", context={"specimen_id": item["specimen_id"]})
            target_location_id = (
                int(session["target_location_id"])
                if session["purpose"] == "调取"
                else int(item["expected_location_id"])
            )
            cursor = self.connection.execute(
                "INSERT INTO specimen_placements(specimen_id,location_id,quantity,container_code,placed_at) "
                "VALUES(?,?,?,?,?)",
                (placement["specimen_id"], target_location_id, placement["quantity"],
                 placement["container_code"], to_microseconds(self.clock.now())),
            )
            new_placement_id = int(cursor.lastrowid)
            updated = self.connection.execute(
                "UPDATE specimen_placements SET removed_at=?,version=version+1 "
                "WHERE id=? AND version=? AND removed_at IS NULL",
                (timestamp, placement["id"], item["expected_placement_version"]),
            )
            if updated.rowcount != 1:
                raise ConflictError("容器摆放版本冲突，整次交接失效")
            self.connection.execute(
                "INSERT INTO custody_events(specimen_id,placement_id,movement_type,quantity,from_location_id,"
                "to_location_id,idempotency_key,actor,reason,created_at) VALUES(?,?,'移交',?,?,?,?,?,?,?)",
                (
                    placement["specimen_id"], new_placement_id, placement["quantity"],
                    placement["location_id"], target_location_id,
                    f"handover-{session['id']}-{item['id']}",
                    f"{session['handover_party_name']}→{session['receiver_party_name']}",
                    f"交接会话 {session['session_no']}：{purpose_label}", timestamp,
                ),
            )
            self.connection.execute(
                "UPDATE specimens SET status='stored',version=version+1,updated_at=? WHERE id=? "
                "AND status NOT IN ('depleted','disposed')",
                (timestamp, placement["specimen_id"]),
            )
        self.connection.execute(
            "UPDATE handover_sessions SET status='completed',completed_at=?,version=version+1,updated_at=? WHERE id=?",
            (timestamp, timestamp, session["id"]),
        )
        self._stage(
            session["id"], "completed", "system",
            {"custody_transferred": True, "purpose": session["purpose"], "item_count": len(items)}, timestamp,
        )
        # 本会话完成即意味着这些检材被移动：其他仍打开的并发会话立即失效（本会话已是 completed，不会被波及）
        for item in items:
            void_open_handovers(
                self.connection, int(item["specimen_id"]),
                f"检材已由交接会话 {session['session_no']} 移动，其他会话失效", timestamp,
            )

    # ------------------------------------------------------------------ 查询
    def list_sessions(self, *, case_id: int | None, status: str | None, limit: int, offset: int) -> dict:
        where: list[str] = []
        params: list[Any] = []
        if case_id is not None:
            where.append("case_id=?")
            params.append(case_id)
        if status:
            where.append("status=?")
            params.append(status)
        clause = " WHERE " + " AND ".join(where) if where else ""
        total = int(self.connection.execute(f"SELECT COUNT(*) FROM handover_sessions{clause}", params).fetchone()[0])
        params.extend([limit, offset])
        rows = self.connection.execute(
            f"SELECT * FROM handover_sessions{clause} ORDER BY id DESC LIMIT ? OFFSET ?", params
        ).fetchall()
        return {"items": records(rows), "total": total, "limit": limit, "offset": offset}

    def session_detail(self, session_id: int) -> dict[str, Any]:
        self._expire_if_due(session_id, to_storage(self.clock.now()))
        session = record(self.connection.execute(
            "SELECT * FROM handover_sessions WHERE id=?", (session_id,)
        ).fetchone())
        if session is None:
            raise NotFoundError("交接会话不存在")
        items = records(self.connection.execute(
            "SELECT hi.*,s.specimen_no,s.seal_code AS current_seal_code,l.location_code AS expected_location_code "
            "FROM handover_items hi JOIN specimens s ON s.id=hi.specimen_id "
            "JOIN storage_locations l ON l.id=hi.expected_location_id "
            "WHERE hi.session_id=? ORDER BY hi.id", (session_id,),
        ).fetchall())
        scans = records(self.connection.execute(
            "SELECT * FROM handover_scans WHERE session_id=? ORDER BY id", (session_id,)
        ).fetchall())
        stages = records(self.connection.execute(
            "SELECT * FROM handover_stage_events WHERE session_id=? ORDER BY id", (session_id,)
        ).fetchall())
        session["items"] = items
        session["scans"] = scans
        session["stage_events"] = stages
        session["discrepancies"] = self._discrepancies(session, items=items, scans=scans)
        session["responsibility_chain"] = self._responsibility_chain(session, items)
        return session

    def _responsibility_chain(self, session: dict, items: list[dict]) -> list[dict]:
        if session["status"] != "completed":
            return []
        chain: list[dict] = []
        for item in items:
            event = record(self.connection.execute(
                "SELECT * FROM custody_events WHERE idempotency_key=?",
                (f"handover-{session['id']}-{item['id']}",),
            ).fetchone())
            chain.append({
                "specimen_id": item["specimen_id"],
                "specimen_no": item["specimen_no"],
                "transfer_event": event,
                "handover_party": session["handover_party_name"],
                "receiver_party": session["receiver_party_name"],
            })
        return chain

    # ------------------------------------------------------------------ 差异
    def _discrepancies(self, session: dict, *, items: list[dict] | None = None, scans: list[dict] | None = None) -> dict:
        if items is None:
            items = records(self.connection.execute(
                "SELECT * FROM handover_items WHERE session_id=? ORDER BY id", (session["id"],)
            ).fetchall())
        if scans is None:
            scans = records(self.connection.execute(
                "SELECT * FROM handover_scans WHERE session_id=? ORDER BY id", (session["id"],)
            ).fetchall())
        specimen_numbers = {
            int(item["specimen_id"]): self.repository.require_specimen(int(item["specimen_id"]))["specimen_no"]
            for item in items
        }
        effective = [scan for scan in scans if scan["disposition"] == ""]
        missing: list[dict] = []
        mismatches: list[dict] = []
        interfered: list[dict] = []
        for item in items:
            specimen_id = int(item["specimen_id"])
            for party in ("handover", "receiver"):
                party_scans = [scan for scan in effective if scan["party"] == party]
                matched = [scan for scan in party_scans if scan["specimen_id"] == specimen_id]
                if not matched:
                    missing.append({"specimen_id": specimen_id, "specimen_no": specimen_numbers[specimen_id], "party": party})
                else:
                    latest = matched[-1]
                    if latest["scan_result"] == "seal_mismatch" or latest["seal_code"] != item["expected_seal_code"]:
                        mismatches.append({
                            "specimen_id": specimen_id, "specimen_no": specimen_numbers[specimen_id], "party": party,
                            "expected_seal_code": item["expected_seal_code"],
                            "scanned_seal_code": latest["seal_code"],
                        })
            placement = self._active_placement(specimen_id)
            if placement is None or int(placement["id"]) != int(item["expected_placement_id"]) or int(
                placement["version"]
            ) != int(item["expected_placement_version"]):
                interfered.append({"specimen_id": specimen_id, "specimen_no": specimen_numbers[specimen_id]})
        surplus = [
            {
                "scan_id": scan["id"], "party": scan["party"], "specimen_code": scan["specimen_code"],
                "specimen_id": scan["specimen_id"], "seal_code": scan["seal_code"],
            }
            for scan in effective
            if scan["scan_result"] == "surplus"
        ]
        duplicates = [
            {
                "scan_id": scan["id"], "party": scan["party"], "specimen_code": scan["specimen_code"],
                "seal_code": scan["seal_code"],
            }
            for scan in scans
            if scan["scan_result"] == "duplicate"
        ]
        consensus = session["status"] == "open" and not missing and not mismatches and not surplus and not interfered
        return {
            "consensus": consensus,
            "missing": missing,
            "surplus": surplus,
            "duplicates": duplicates,
            "seal_mismatches": mismatches,
            "interfered": interfered,
        }

    # ------------------------------------------------------------------ 辅助
    def _freeze_for_seal_change(
        self, specimen_id: int, expected_seal: str, scanned_seal: str, actor: str, timestamp: str
    ) -> bool:
        existing = self.connection.execute(
            "SELECT id FROM specimen_holds WHERE specimen_id=? AND hold_type='争议' AND released_at IS NULL",
            (specimen_id,),
        ).fetchone()
        if existing:
            return False
        reason = f"归还会话封识变化：登记封识 {expected_seal}，扫描封识 {scanned_seal}"
        self.connection.execute(
            "INSERT INTO specimen_holds(specimen_id,hold_type,reason,imposed_by,imposed_at) VALUES(?,?,?,?,?)",
            (specimen_id, "争议", reason, actor, timestamp),
        )
        self.connection.execute(
            "UPDATE specimens SET status='held',version=version+1,updated_at=? WHERE id=? "
            "AND status NOT IN ('depleted','disposed')",
            (timestamp, specimen_id),
        )
        return True

    def _active_placement(self, specimen_id: int) -> dict[str, Any] | None:
        return record(self.connection.execute(
            "SELECT * FROM specimen_placements WHERE specimen_id=? AND removed_at IS NULL ORDER BY id DESC LIMIT 1",
            (specimen_id,),
        ).fetchone())

    def _scan_row(self, scan_id: int) -> dict[str, Any]:
        scan = record(self.connection.execute(
            "SELECT * FROM handover_scans WHERE id=?", (scan_id,)
        ).fetchone())
        if scan is None:
            raise NotFoundError("扫描记录不存在")
        return scan

    def _require_user(self, user_id: int) -> dict[str, Any]:
        user = record(self.connection.execute(
            "SELECT id,username,display_name,status,password_hash FROM users WHERE id=?", (user_id,)
        ).fetchone())
        if user is None:
            raise NotFoundError("交接身份对应用户不存在")
        if user["status"] != "active":
            raise ConflictError("交接身份对应账号当前不可用")
        return user

    def _require_open_session(self, session_id: int) -> dict[str, Any]:
        session = record(self.connection.execute(
            "SELECT * FROM handover_sessions WHERE id=?", (session_id,)
        ).fetchone())
        if session is None:
            raise NotFoundError("交接会话不存在")
        if session["status"] != "open":
            raise ConflictError(f"交接会话已结束（{session['status']}），不能继续操作")
        return session

    def _expire_if_due(self, session_id: int, timestamp: str) -> bool:
        session = record(self.connection.execute(
            "SELECT * FROM handover_sessions WHERE id=?", (session_id,)
        ).fetchone())
        if session is None:
            return False
        if session["status"] == "open" and session["expires_at"] <= timestamp:
            self._expire(session, timestamp)
            self.connection.commit()
            return True
        return False

    def _expire(self, session: dict, timestamp: str) -> None:
        updated = self.connection.execute(
            "UPDATE handover_sessions SET status='expired',closure_reason='超过交接期限未完成双方确认',"
            "version=version+1,updated_at=? WHERE id=? AND status='open'",
            (timestamp, session["id"]),
        )
        if updated.rowcount:
            self._stage(session["id"], "expired", "system", {"expires_at": session["expires_at"]}, timestamp)

    def _void(self, session: dict, reason: str, timestamp: str) -> None:
        self.connection.execute(
            "UPDATE handover_sessions SET status='voided',closure_reason=?,version=version+1,updated_at=? "
            "WHERE id=? AND status='open'",
            (reason, timestamp, session["id"]),
        )
        self._stage(session["id"], "voided", "system", {"reason": reason}, timestamp)

    def _stage(self, session_id: int, stage: str, actor: str, detail: dict, timestamp: str) -> None:
        self.connection.execute(
            "INSERT INTO handover_stage_events(session_id,stage,actor,detail_json,created_at) VALUES(?,?,?,?,?)",
            (session_id, stage, actor, json.dumps(detail, ensure_ascii=False, sort_keys=True), timestamp),
        )

    def _require_party_principal(self, session: dict, party: str, user_id: int) -> None:
        expected = int(session["handover_party_user_id"] if party == "handover" else session["receiver_party_user_id"])
        if user_id != expected:
            raise ConflictError("当前登录身份不是该方指定的交接人，不能代为扫描")
