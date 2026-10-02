from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api import audit, auth, roles, system, users
from app.core.errors import DomainError
from app.database import close_connection, get_connection, init_db, transaction
from app.forensics.incident_router import router as incident_router
from app.forensics.router import router as forensics_router
from app.forensics.service import ForensicService


@asynccontextmanager
async def lifespan(app: FastAPI):
    del app
    init_db()
    # 服务重启后继续上次未完成的质量事件影响评估（按持久化游标确定性续跑）
    try:
        with transaction(immediate=True) as connection:
            ForensicService(connection).incidents.run_pending_evaluations(worker="startup")
    except Exception:  # noqa: BLE001 - 启动续跑失败不应阻止服务起来，仍可由 API/CLI 重试
        pass
    yield
    close_connection()


app = FastAPI(title="司法鉴定检材流转与复核服务", version="1.0.0", lifespan=lifespan)


@app.exception_handler(DomainError)
async def handle_domain_error(request: Request, exc: DomainError) -> JSONResponse:
    del request
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message, "context": exc.context}},
    )


app.include_router(auth.router)
app.include_router(users.router)
app.include_router(roles.router)
app.include_router(audit.router)
app.include_router(system.router)
app.include_router(forensics_router)
app.include_router(incident_router)


@app.get("/")
def root() -> dict:
    return {"service": "司法鉴定检材流转与复核服务", "version": "1.0.0"}
