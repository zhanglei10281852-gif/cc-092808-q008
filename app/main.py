from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api import audit, auth, roles, system, users
from app.core.errors import DomainError
from app.database import close_connection, init_db, transaction
from app.forensics.impact_router import router as impact_router
from app.forensics.router import router as forensics_router
from app.forensics.service import ForensicService


@asynccontextmanager
async def lifespan(app: FastAPI):
    del app
    init_db()
    # 服务重启后继续未完成的影响计算
    try:
        with transaction(immediate=True) as connection:
            ForensicService(connection).impact.reconcile_on_startup()
    except Exception as exc:  # pragma: no cover - 启动恢复不能阻断服务
        import logging

        logging.getLogger(__name__).warning("质量事件影响评估恢复失败：%s", exc)
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
app.include_router(impact_router)


@app.get("/")
def root() -> dict:
    return {"service": "司法鉴定检材流转与复核服务", "version": "1.0.0"}
