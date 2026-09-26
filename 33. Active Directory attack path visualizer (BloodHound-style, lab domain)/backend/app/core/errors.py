"""Standard error envelope (ISO 27001 A.8.9 / OWASP A05: no info leakage)."""
from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, hint: str | None = None):
        self.status = status
        self.code = code
        self.message = message
        self.hint = hint
        super().__init__(message)


async def api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
    body = {"error": {"code": exc.code, "message": exc.message}}
    if exc.hint:
        body["error"]["hint"] = exc.hint
    return JSONResponse(status_code=exc.status, content=body)


async def unhandled_error_handler(_: Request, exc: Exception) -> JSONResponse:
    # Never leak stack traces or internals to clients (ISO A.8.8, OWASP A05).
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred. Reference logged for audit.",
            }
        },
    )
