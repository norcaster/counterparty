"""Norcaster Shared Record counterparty component (self-hosted, no Norcaster account).

Keeps an organisation's own keys and records, publishes its key documents to a Shared Record
log, signs receipts and acknowledgements for the tool calls it exchanges with a partner,
witnesses the log, and exports evidence that ``norcaster-verify`` checks offline.
"""

from .config import Config
from .log_client import HttpLogClient, LogClient, LogError
from .party import META_KEY, Counterparty, Inbound, Inconsistent, Outbound, Refused, tool_call_content
from .store import Store

__version__ = "0.1.0"
__all__ = [
    "Config", "Counterparty", "HttpLogClient", "Inbound", "Inconsistent", "LogClient", "LogError", "META_KEY",
    "Outbound", "Refused", "Store", "tool_call_content",
]
