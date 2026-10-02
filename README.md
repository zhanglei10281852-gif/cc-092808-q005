# 司法鉴定检材流转与复核服务

本项目是面向司法鉴定机构的 Python 后端服务，用于登记委托或移送案件、接收带封识的检材、记录保管位置与流转、执行专业检验、安排复核并处理环境和质量告警。案件、检材、检验记录和领用审批都保存在本地 SQLite 中，关键写入带版本或幂等键，适合在单个 Linux 应用容器内运行。

## 运行环境

- Python 3.11
- FastAPI 与 Uvicorn
- SQLite 3，由 Python 标准库提供

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

默认数据库位于 `data/forensics.db`，也可以通过 `FORENSICS_DATABASE_PATH` 指向其他 `.db`、`.sqlite` 或 `.sqlite3` 文件。

## 初始化与启动

```bash
python -m app.cli init-db
python -m app.cli check-db
uvicorn app.main:app --host 0.0.0.0 --port 8432
```

健康检查为 `GET /api/system/health`。首次使用可调用 `POST /api/auth/bootstrap` 创建管理员，再通过 `POST /api/auth/login` 取得 Bearer 会话令牌。鉴定业务接口统一位于 `/api/forensics`。

## 测试与构建检查

```bash
python -m pytest
python -m compileall -q app tests
```

下面两条命令分别检查 HTTP 入口和完整的入库演示链路：

```bash
python -m app.cli smoke
python -m app.cli demo
```

## 业务边界

- `app/forensics/cases.py` 管理委托机构、案件档案、委托资料与受理状态。
- `app/forensics/custody.py` 管理检材、库位容量、容器摆放、流转、领用和冻结。
- `app/forensics/handover.py` 管理有期限的当庭调取/归还交接会话、双方扫描、差异处置与责任链。
- `app/forensics/examinations.py` 管理检验规程、取样、观察记录、检验结果与复核日程。
- `app/forensics/quality.py` 管理温湿度读数、偏离告警和检材领用审批。
- `app/api`、`app/services` 和 `app/repositories` 提供身份、权限、审计、后台作业及维护能力。

## 有期限的检材交接会话

开庭前临时调取多件检材时，普通移库备注既无法阻止遗漏，也不能证明双方确认的是同一批封识。交接会话把“清单核对—双方各自确认—责任与位置一次性转移”做成一个有期限的原子过程：

1. 发起人指定案件、调取依据（调取函等法律文书）、交出方/接收方、接收库位和有效期（5–1440 分钟），系统按依据生成预期清单，逐件锁定调取函登记的封识编号，并记录当时的库位、摆放与最后流转事件作为核对基线。
2. 交出方与接收方分别扫描检材编号与封识。扫描接口实时返回差异：缺件 `missing`、多件 `unexpected`（含不在调取函上的封袋）、重复扫描 `duplicates`、封识不符 `seal_mismatches`。误扫可作废旧扫描后重扫；扫描带幂等键，相同扫描事件重放不会增加次数。
3. 只有清单逐件逐方一致（`consistent`）后，双方才能各自确认；系统拒绝同一登录身份代表双方确认。
4. 双方确认齐备的同一事务内，全部检材的保管责任（交出方→接收方）和位置（原库位→接收库位）一次性转移，逐件写入责任链 `handover_liability_transfers` 和“交接”类型的流转事件；任何一件不满足条件都不写部分流转。
5. 超过有效期、被撤销，或确认前任一检材被普通移库/领用/取样等会话外路径移动，整次会话置为 `expired`/`revoked`/`invalidated`，不产生任何交接流转；确认前还会用基线摆放与基线流转事件做最后校验。
6. 归还时基于原调取会话生成清单沿用核对。封识与原会话不同属于“封识变化”，不阻断归还，但完成时自动对相关检材加“争议”冻结并记录阶段事件。

交接接口（权限 `custody.handover` 写入、`custody.read` 只读）：

- `POST /api/forensics/handovers` 创建会话（调取给 `items`，归还给 `origin_session_id`）。
- `POST /api/forensics/handovers/{id}/scans` 扫描检材/封识并实时返回差异。
- `POST /api/forensics/handovers/{id}/scans/{scan_id}/void` 作废误扫（差异处置）。
- `POST /api/forensics/handovers/{id}/confirm` 交出方/接收方分别确认。
- `POST /api/forensics/handovers/{id}/revoke` 撤销会话。
- `GET /api/forensics/handovers`、`GET /api/forensics/handovers/{id}` 查看会话阶段、双方确认、差异处置和最终责任链；读路径会自动落定已超时会话。

## 一致性约定

SQLite 连接启用外键、WAL、忙等待和即时写事务。案件档案、库位、容器摆放、检验任务和领用申请采用版本号防止旧请求覆盖新状态；入库、移库、取样和传感读数使用业务键去重。专业检验保留采用的规程版本和每个检查点的观察记录，完成后可依据鉴定专业及风险策略生成下一次复核日期。会话令牌只保存摘要，审计记录不保存明文密码或令牌。
