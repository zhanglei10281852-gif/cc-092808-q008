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
- `app/forensics/examinations.py` 管理检验规程、取样、观察记录、检验结果与复核日程。
- `app/forensics/quality.py` 管理温湿度读数、偏离告警和检材领用审批。
- `app/forensics/impact.py` 管理质量事件、可版本化影响规则、命中候选、人工决定与原子处置。
- `app/api`、`app/services` 和 `app/repositories` 提供身份、权限、审计、后台作业及维护能力。

## 质量事件影响追踪

空白对照受污染等质量事件通过 `/api/forensics/quality-events` 登记污染时间窗、资源标识（试剂批次、设备、工作台）和证据，系统随即按当前生效规则生成检验候选，候选携带逐条命中路径（规则代码与版本、资源标识、时间区间交集）：

- 影响规则位于 `/api/forensics/impact-rules`，支持时间窗邻近、试剂批次、设备、工作台时段四类；同号规则递增版本，发布新版本自动停用旧版本，历史评估保留所用规则快照。
- 调查员可对候选填写理由排除误报，或确认影响。确认在同一事务内原子完成：以质量冻结冻结相关检材剩余量（立即阻断领用）、把检验结果标记待复核（阻断继续签发意见）、为已签发报告创建撤回审查；原报告记录永不改写，撤回结论只落在审查记录上。
- 迟到的设备日志或试剂批次记录通过 `/api/forensics/examinations/{id}/resource-uses` 补录，按业务来源键幂等，并确定性地重新评估所有引用同一资源的开放事件、扩展候选；评估输入（时间窗、资源、规则、资源使用与检验快照）生成指纹，输入不变的重复评估直接复用，不会产生第二份有效处置。
- 事件采用乐观版本号：补充资源、证据、候选决定都须携带 `expected_version`，并发调查的旧版本请求会被拒绝，所有变更进入事件版本链。
- `GET /api/forensics/quality-events/{id}` 可一次性追到规则、资源、证据、评估、检验候选、检材、待复核标志、报告撤回审查与每项人工决定。
- 服务启动时自动回收中断的评估行并重算（也可手动调用 `POST /api/forensics/quality-events/reconcile`），未完成的影响计算在重启后继续。

## 一致性约定

SQLite 连接启用外键、WAL、忙等待和即时写事务。案件档案、库位、容器摆放、检验任务和领用申请采用版本号防止旧请求覆盖新状态；入库、移库、取样和传感读数使用业务键去重。专业检验保留采用的规程版本和每个检查点的观察记录，完成后可依据鉴定专业及风险策略生成下一次复核日期。会话令牌只保存摘要，审计记录不保存明文密码或令牌。
