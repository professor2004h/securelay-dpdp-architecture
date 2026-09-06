"""
Securelay Ingestion Proxy ASGI Middleware
Author: Shanmukh Chitturi (https://www.linkedin.com/in/shanmukh-chitturi/)
"""

import json
from typing import Callable, Optional
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.requests import Request
from starlette.responses import Response
from .enclave import TokenizationEnclave


class SecurelayIngestionMiddleware:
    """
    ASGI middleware intercepting incoming request bodies and tokenizing
    all sensitive PII fields before the request reaches application route handlers.
    """

    def __init__(
        self,
        app: ASGIApp,
        enclave: TokenizationEnclave,
        subject_id_header: str = "X-Subject-ID",
        subject_id_field: str = "user_id"
    ):
        self.app = app
        self.enclave = enclave
        self.subject_id_header = subject_id_header
        self.subject_id_field = subject_id_field

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)

        # Only process POST / PUT / PATCH with JSON content
        content_type = request.headers.get("content-type", "")
        if request.method in {"POST", "PUT", "PATCH"} and "application/json" in content_type:
            body_bytes = await request.body()
            if body_bytes:
                try:
                    payload = json.loads(body_bytes.decode("utf-8"))
                    subject_id = (
                        request.headers.get(self.subject_id_header)
                        or payload.get(self.subject_id_field)
                        or "anonymous_subject"
                    )

                    tokenized_payload = self.enclave.tokenize_payload(subject_id, payload)
                    modified_body = json.dumps(tokenized_payload).encode("utf-8")

                    async def custom_receive():
                        return {
                            "type": "http.request",
                            "body": modified_body,
                            "more_body": False
                        }

                    await self.app(scope, custom_receive, send)
                    return
                except Exception:
                    # Fallback to standard request processing on parse error
                    pass

        await self.app(scope, receive, send)
