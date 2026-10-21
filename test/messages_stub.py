"""A local stand-in for the Anthropic Messages API, for driving the real Claude Code CLI (bundled
with the Claude Agent SDK) in tests without calling any model. It answers ``POST /v1/messages``,
streamed or not: when the request offers the planned tool and holds no tool result yet, it asks
for that tool call; otherwise it says it is done. Every request is recorded."""

from __future__ import annotations

import json
import uuid
from typing import Any

from starlette.applications import Starlette
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route


class MessagesStub:
    def __init__(self) -> None:
        self.plan: tuple[str, dict[str, Any]] | None = None
        self.requests: list[dict[str, Any]] = []
        self.app = Starlette(routes=[Route("/v1/messages", self._messages, methods=["POST"]),
                                     Route("/{path:path}", self._other, methods=["GET", "POST", "PUT", "DELETE"])])

    def _reply(self, body: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
        offered = {t.get("name") for t in body.get("tools") or []}
        answered = any(isinstance(m.get("content"), list) and any(isinstance(b, dict) and b.get("type") == "tool_result"
                                                                  for b in m["content"]) for m in body.get("messages") or [])
        if self.plan is not None and self.plan[0] in offered and not answered:
            return [{"type": "tool_use", "id": f"toolu_{uuid.uuid4().hex[:20]}", "name": self.plan[0], "input": self.plan[1]}], "tool_use"
        return [{"type": "text", "text": "done"}], "end_turn"

    async def _messages(self, request: Any) -> Any:
        body = await request.json()
        self.requests.append({"path": request.url.path, "model": body.get("model")})
        blocks, stop = self._reply(body)
        message = {"id": f"msg_{uuid.uuid4().hex[:20]}", "type": "message", "role": "assistant", "model": body.get("model"),
                   "content": blocks, "stop_reason": stop, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 5}}
        if not body.get("stream"):
            return JSONResponse(message)

        def events():
            def event(name: str, data: dict[str, Any]) -> str:
                return f"event: {name}\ndata: {json.dumps(data)}\n\n"

            yield event("message_start", {"type": "message_start", "message": {**message, "content": [], "stop_reason": None}})
            for i, block in enumerate(blocks):
                if block["type"] == "text":
                    yield event("content_block_start", {"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}})
                    delta = {"type": "text_delta", "text": block["text"]}
                else:
                    yield event("content_block_start", {"type": "content_block_start", "index": i, "content_block": {**block, "input": {}}})
                    delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
                yield event("content_block_delta", {"type": "content_block_delta", "index": i, "delta": delta})
                yield event("content_block_stop", {"type": "content_block_stop", "index": i})
            yield event("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                                          "usage": {"output_tokens": 5}})
            yield event("message_stop", {"type": "message_stop"})

        return StreamingResponse(events(), media_type="text/event-stream")

    async def _other(self, request: Any) -> Any:
        self.requests.append({"path": request.url.path, "method": request.method})
        return JSONResponse({"type": "error", "error": {"type": "not_found_error", "message": "stub"}}, status_code=404)
