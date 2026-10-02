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
- `app/forensics/handover.py` 管理有期限的双人交接会话（调取与归还）。
- `app/forensics/examinations.py` 管理检验规程、取样、观察记录、检验结果与复核日程。
- `app/forensics/quality.py` 管理温湿度读数、偏离告警和检材领用审批。
- `app/api`、`app/services` 和 `app/repositories` 提供身份、权限、审计、后台作业及维护能力。

## 检材交接会话

开庭前临时调取等场景使用有时效的交接会话，避免“封袋编号不在调取函上只能写在普通移库备注里”的问题：

1. 发起人从案件、调取依据（调取函）和指定的交出方/接收方用户生成**预期清单**，系统快照每件检材的封识编号、当前容器摆放与版本，并设定到期时间（5–1440 分钟）。
2. 交出方与接收方分别扫描检材编号和封识编号，接口实时返回 `matched`（一致）、`surplus`（多件）、`duplicate`（重复扫描）、`seal_mismatch`（封识不符）。同一 `scan_key` 重放返回 `replayed=true`，不会增加扫描次数；重复扫描只作提示，不占有效计数；更正封识会作废旧扫描。多件可由扫描方登记剔除原因后排除。
3. 只有双方清单实时一致（无缺件、多件、封识不符，且检材未被别人移动），并且双方分别以**各自身份口令**确认后，全部检材的库位、保管责任才在同一事务内一次性转移（`custody_events` 记录“移交”）；单方确认不产生任何流转。
4. 超时、发起人或双方撤销、或任一检材在确认前被普通移库/领用移动时，整次会话失效（`expired`/`cancelled`/`voided`），不写部分流转；失效会话不可再扫描或确认。
5. 归还沿用原调取会话生成清单并以原封识为核对基线；扫描发现封识变化时自动对相关检材加“争议”冻结，归还不能完成。
6. `GET /api/forensics/handovers/{id}` 返回会话各阶段事件、双方确认时间、差异处置记录、实时差异状态和最终责任链；`POST /api/forensics/handovers/sweep-expired` 批量清理到期会话。

## 一致性约定

SQLite 连接启用外键、WAL、忙等待和即时写事务。案件档案、库位、容器摆放、检验任务和领用申请采用版本号防止旧请求覆盖新状态；入库、移库、取样和传感读数使用业务键去重。专业检验保留采用的规程版本和每个检查点的观察记录，完成后可依据鉴定专业及风险策略生成下一次复核日期。会话令牌只保存摘要，审计记录不保存明文密码或令牌。交接会话以扫描事件键保证重放幂等，以摆放版本快照保证确认前移动可被发现，责任转移只在双方确认后的单一事务中提交。
