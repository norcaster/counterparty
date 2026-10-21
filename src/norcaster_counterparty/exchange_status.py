"""What happened to one exchange with a partner, as the sending bindings report it (the OpenAI
Agents SDK binding and the local MCP proxy). Ids, decisions and a status: never content."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from .party import META_KEY, Counterparty, Outbound


@dataclass(frozen=True)
class ExchangeStatus:
    """What happened to one exchange with the partner. No content: ids, decisions and status only."""

    exchange_id: str | None
    tool_name: str
    status: str
    """``acknowledged``, ``mismatch`` (the partner received different content), ``missing`` (no
    acknowledgement came back), ``invalid`` (one came back but does not check out) or ``refused``
    (your component refused to sign; nothing was sent)."""
    delivered: bool
    outcome: str
    rule_id: str | None
    partner_content_check: str | None = None
    partner_outcome: str | None = None
    partner_rule_id: str | None = None
    detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def plain(value: Any) -> Any:
    """A deep, ordinary copy of what an SDK hands over as read-only mappings or models' dicts."""
    if isinstance(value, Mapping):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(v) for v in value]
    return value


async def settle(party: Counterparty, out: Outbound, *, tool_name: str, outcome: str, rule_id: str | None,
                 result_meta: Any) -> ExchangeStatus:
    """Check and keep the partner's acknowledgement from a result's ``_meta``; the exchange's status."""
    meta = plain(result_meta) if isinstance(result_meta, Mapping) else None
    try:
        answer = await party.accept_acknowledgement(out.exchange_id, meta)
    except Exception as exc:  # noqa: BLE001 - reported as a status, never raised into the agent's run
        answer = f"invalid: {type(exc).__name__}: {exc}"
    base = {"exchange_id": out.exchange_id, "tool_name": tool_name, "delivered": out.delivered,
            "outcome": outcome, "rule_id": rule_id}
    if answer == "acknowledged":
        ack = meta[META_KEY]["acknowledgement"]
        decision = ack.get("boundary_decision") or {}
        return ExchangeStatus(**base, status="mismatch" if ack.get("content_check") == "mismatch" else "acknowledged",
                              partner_content_check=ack.get("content_check"), partner_outcome=decision.get("outcome"),
                              partner_rule_id=decision.get("rule_id"))
    if answer == "none":
        return ExchangeStatus(**base, status="missing", detail="no acknowledgement in the result")
    return ExchangeStatus(**base, status="invalid", detail=answer)
