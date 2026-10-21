"""Configuration for one counterparty organisation (a JSON file it keeps next to its state)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Config:
    """Who this organisation is, which log it uses and which roots it has pinned.

    ``pins`` maps each partner's issuer id (a Norcaster organisation id, or another
    counterparty's id) to the root fingerprint exchanged at onboarding. ``agents`` are the
    agents this organisation publishes in its key document (their names become public).
    """

    org_id: str
    org_name: str
    state_dir: Path
    log_url: str
    log_id: str
    operator_public_key_pem: str
    pins: dict[str, str] = field(default_factory=dict)
    agents: list[dict[str, str]] = field(default_factory=list)
    witness_id: str | None = None
    policy_version: str = "1"
    policy_content_hash: str = ""
    ack_deadline_seconds: int = 86400
    retention_days: int = 2555
    signing_key_days: int = 365
    # A received receipt whose created_at is further than this from the receiver's clock is refused.
    max_clock_skew_seconds: int = 300

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        path = Path(path)
        raw: dict[str, Any] = json.loads(path.read_text())
        base = path.parent
        pem = raw.get("operator_public_key_pem")
        if not pem and raw.get("operator_public_key_file"):
            pem = (base / raw["operator_public_key_file"]).read_text()
        if not pem:
            raise ValueError("set operator_public_key_pem or operator_public_key_file (the log operator's key, pinned)")
        agents = [a for a in raw.get("agents") or [] if isinstance(a, dict) and a.get("agent_id")]
        return cls(
            org_id=str(raw["org_id"]),
            org_name=str(raw.get("org_name") or raw["org_id"]),
            state_dir=(base / str(raw.get("state_dir") or "state")).resolve(),
            log_url=str(raw["log_url"]),
            log_id=str(raw["log_id"]),
            operator_public_key_pem=str(pem),
            pins={str(k): str(v) for k, v in (raw.get("pins") or {}).items()},
            agents=[{"agent_id": str(a["agent_id"]), "name": str(a.get("name") or a["agent_id"]),
                     "kind": str(a.get("kind") or "agent")} for a in agents],
            witness_id=raw.get("witness_id"),
            policy_version=str(raw.get("policy_version") or "1"),
            policy_content_hash=str(raw.get("policy_content_hash") or ""),
            ack_deadline_seconds=int(raw.get("ack_deadline_seconds") or 86400),
            retention_days=int(raw.get("retention_days") or 2555),
            max_clock_skew_seconds=int(raw.get("max_clock_skew_seconds") or 300),
            signing_key_days=int(raw.get("signing_key_days") or 365),
        )
