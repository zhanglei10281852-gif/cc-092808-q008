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
- `app/forensics/incidents.py` 管理质量事件（如空白对照污染）的影响追踪、候选评估、人工决定与原子处置。
- `app/api`、`app/services` 和 `app/repositories` 提供身份、权限、审计、后台作业及维护能力。

## 质量事件影响追踪

针对毒物实验室空白对照在报告签发后才被确认受污染的场景，系统提供端到端的影响追踪与处置闭环：

1. **登记事件**：登记污染时间窗（可带分钟级宽限）、资源标识（试剂批次 `reagent_batch`、设备 `equipment`、工作台 `workbench`）与证据，系统随即生成第 1 版**可版本化规则快照**。
2. **确定性评估**：评估按规则与时间窗重叠扫描检验资源使用台账，生成带**命中路径**（规则、资源、使用时段、污染窗、规则版本、是否迟到数据）的检验候选。评估分批执行并持久化游标，登记、规则更新、迟到设备/试剂信息、迟到台账都会触发新版本评估；相同输入重复评估只合并命中路径，不产生第二份候选或有效处置。
3. **人工决定**：调查员可把候选**排除为误报**（须填理由）或**确认影响**。被排除候选在同版本重放下不会翻案，但被新版本规则的迟到证据再次命中时会重新开放。
4. **原子处置**：确认影响在一个事务内冻结相关剩余检材（复用质量冻结，立即阻断领用）、为检验结果置“待复核”标志（立即阻断继续签发），并为已签发意见创建**撤回审查**而不改写原报告。处置靠唯一约束幂等，重复确认不会产生第二份处置。
5. **版本与并发**：事件与候选都带乐观版本号，并发调查持旧版本提交会被拒绝（409）。
6. **可追踪、可续跑**：`GET` 事件详情可从事件追到规则版本、资源、证据、检验候选、检材、案件、报告、冻结/待复核/撤回审查处置以及每项人工决定。未完成的影响评估在服务重启后由启动流程、`POST /api/forensics/incidents-evaluations/run` 或 `python -m app.cli resume-impact-evaluations` 按游标继续。

资源台账与报告接口：`POST /api/forensics/examinations/{id}/resources`（迟到数据用 `source=late`）、`POST /api/forensics/examinations/{id}/reports`。

## 一致性约定

SQLite 连接启用外键、WAL、忙等待和即时写事务。案件档案、库位、容器摆放、检验任务和领用申请采用版本号防止旧请求覆盖新状态；入库、移库、取样和传感读数使用业务键去重。专业检验保留采用的规程版本和每个检查点的观察记录，完成后可依据鉴定专业及风险策略生成下一次复核日期。质量事件与检验候选使用版本号实现乐观并发控制，规则按版本快照保存；影响评估以去重键和游标保证确定性、可重放与重启续跑；处置记录以 `(事件, 处置类型, 目标)` 唯一约束保证不重复。会话令牌只保存摘要，审计记录不保存明文密码或令牌。
