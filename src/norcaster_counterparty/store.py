"""Local state: private keys on disk (0600) and records in SQLite, all inside ``state_dir``.

Nothing here leaves the machine except through the log client (hashes and key documents)
and the ``_meta`` blocks the integrator sends to its partner. Content and salts are kept in
plain form in the local database because a party can only prove what it sent if it keeps
it; protect ``state_dir`` like any other system of record (disk encryption, backups).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import sqlite3
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]
    import msvcrt

from cryptography.hazmat.primitives import serialization
from norcaster_verify.shared_record import es256

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS signing_keys (
    key_id TEXT PRIMARY KEY, public_key_pem TEXT NOT NULL, not_before TEXT NOT NULL, not_after TEXT NOT NULL,
    revoked_at TEXT, current INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS exchanges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL, exchange_id TEXT NOT NULL, counterparty TEXT NOT NULL, sequence INTEGER NOT NULL,
    delivered INTEGER NOT NULL, receipt TEXT NOT NULL, receipt_entry TEXT,
    ack TEXT, ack_entry TEXT, missing TEXT, missing_entry TEXT,
    content BLOB, salt BLOB, ack_deadline TEXT NOT NULL, retain_until TEXT NOT NULL, created_at TEXT NOT NULL,
    UNIQUE (role, exchange_id), UNIQUE (role, counterparty, sequence)
);
CREATE TABLE IF NOT EXISTS proxy_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    upstream TEXT NOT NULL, digest TEXT NOT NULL, rule_id TEXT NOT NULL, expires_at REAL NOT NULL,
    outcome TEXT NOT NULL DEFAULT 'redacted'
);
CREATE INDEX IF NOT EXISTS proxy_decisions_lookup ON proxy_decisions (upstream, digest);
"""

BUSY_TIMEOUT_SECONDS = 30.0  # another process sharing state_dir may hold the database briefly


class LockTimeout(TimeoutError):
    """Another process (or task) held a ``state_dir`` lock for longer than the timeout."""


def _try_lock(fd: int) -> bool:
    if fcntl is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # per open file: also excludes other tasks in this process
        except BlockingIOError:
            return False
        return True
    os.lseek(fd, 0, os.SEEK_SET)
    try:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    except OSError:
        return False
    return True


def _unlock(fd: int) -> None:
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)
    else:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


def _write_secret(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _pem(private_key: Any) -> bytes:
    return private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


class Store:
    def __init__(self, state_dir: Path) -> None:
        self.dir = Path(state_dir)
        self.keys_dir = self.dir / "keys"
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self.db = sqlite3.connect(self.dir / "records.sqlite3", timeout=BUSY_TIMEOUT_SECONDS)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(_SCHEMA)
        columns = {row["name"] for row in self.db.execute("PRAGMA table_info(proxy_decisions)")}
        if "outcome" not in columns:  # a state_dir from before approvals were recorded
            with self.db:
                self.db.execute("ALTER TABLE proxy_decisions ADD COLUMN outcome TEXT NOT NULL DEFAULT 'redacted'")
        os.chmod(self.dir / "records.sqlite3", 0o600)

    # --- locks ---------------------------------------------------------------------------------

    @contextlib.asynccontextmanager
    async def lock(self, name: str, *, timeout: float = 60.0) -> AsyncIterator[None]:
        """An exclusive lock on ``name`` for every process (and task) sharing this ``state_dir``:
        ``flock`` on POSIX, ``msvcrt.locking`` on Windows. Waits without blocking the event loop;
        raises ``LockTimeout`` after ``timeout`` seconds. Keep ``state_dir`` on a local disk: file
        locks are not reliable on network filesystems."""
        folder = self.dir / "locks"
        folder.mkdir(mode=0o700, exist_ok=True)
        digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:24]
        fd = os.open(folder / f"{name.split(':', 1)[0]}-{digest}.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            deadline, wait = time.monotonic() + timeout, 0.002
            while not _try_lock(fd):
                if time.monotonic() >= deadline:
                    raise LockTimeout(f"another process held the {name.split(':', 1)[0]} lock for {timeout:.0f} s")
                await asyncio.sleep(wait)
                wait = min(wait * 2, 0.05)
            try:
                yield
            finally:
                _unlock(fd)
        finally:
            os.close(fd)

    # --- keys ----------------------------------------------------------------------------------

    def _key(self, name: str, *, create: bool) -> Any:
        path = self.keys_dir / f"{name}.key"
        if path.exists():
            return serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not create:
            raise FileNotFoundError(path)
        key = es256.generate_private_key()
        _write_secret(path, _pem(key))
        return key

    def root_key(self) -> Any:
        return self._key("root", create=True)

    def next_root_key(self) -> Any:
        """The root a rotation in progress moves to (kept apart until the rotation is registered)."""
        return self._key("root.next", create=True)

    def has_next_root(self) -> bool:
        return (self.keys_dir / "root.next.key").exists()

    def drop_next_root(self) -> None:
        (self.keys_dir / "root.next.key").unlink(missing_ok=True)

    def promote_next_root(self) -> None:
        """Archive the current root as ``root-<key id>.key`` and make the next root current."""
        current = self.root_key()
        archived = self.keys_dir / f"root-{es256.key_id(es256.public_key_pem(current))}.key"
        os.replace(self.keys_dir / "root.key", archived)
        os.replace(self.keys_dir / "root.next.key", self.keys_dir / "root.key")

    def witness_key(self) -> Any:
        return self._key("witness", create=True)

    def signing_key(self, key_id: str) -> Any:
        return self._key(f"signing-{key_id}", create=False)

    def new_signing_key(self, *, not_before: str, not_after: str) -> tuple[str, str]:
        key = es256.generate_private_key()
        pem = es256.public_key_pem(key)
        key_id = es256.key_id(pem)
        _write_secret(self.keys_dir / f"signing-{key_id}.key", _pem(key))
        with self.db:
            self.db.execute("UPDATE signing_keys SET current = 0")
            self.db.execute("INSERT INTO signing_keys (key_id, public_key_pem, not_before, not_after, current) VALUES (?, ?, ?, ?, 1)",
                            (key_id, pem, not_before, not_after))
        return key_id, pem

    def current_signing_key(self) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM signing_keys WHERE current = 1").fetchone()

    def revoked_signing_keys(self) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM signing_keys WHERE revoked_at IS NOT NULL ORDER BY not_before"))

    def revoke_signing_key(self, key_id: str, at: str) -> None:
        with self.db:
            self.db.execute("UPDATE signing_keys SET revoked_at = ?, current = 0 WHERE key_id = ?", (at, key_id))

    # --- meta ----------------------------------------------------------------------------------

    def get(self, key: str) -> Any:
        row = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value"]) if row else None

    def put(self, key: str, value: Any) -> None:
        with self.db:
            self.db.execute("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                            (key, json.dumps(value)))

    # --- exchanges -----------------------------------------------------------------------------

    def last_sequence(self, role: str, counterparty: str) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM exchanges WHERE role = ? AND counterparty = ? ORDER BY sequence DESC LIMIT 1", (role, counterparty)
        ).fetchone()

    def exchange(self, role: str, exchange_id: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM exchanges WHERE role = ? AND exchange_id = ?", (role, exchange_id)).fetchone()

    def exchanges(self, exchange_ids: list[str]) -> list[sqlite3.Row]:
        marks = ",".join("?" for _ in exchange_ids)
        return list(self.db.execute(f"SELECT * FROM exchanges WHERE exchange_id IN ({marks}) ORDER BY id", exchange_ids))

    def add_exchange(self, **fields: Any) -> None:
        for name in ("receipt", "receipt_entry", "ack", "ack_entry"):
            if isinstance(fields.get(name), (dict, list)):
                fields[name] = json.dumps(fields[name])
        cols = ", ".join(fields)
        marks = ", ".join("?" for _ in fields)
        with self.db:
            self.db.execute(f"INSERT INTO exchanges ({cols}) VALUES ({marks})", list(fields.values()))

    def update_exchange(self, row_id: int, **fields: Any) -> None:
        for name, value in list(fields.items()):
            if isinstance(value, (dict, list)):
                fields[name] = json.dumps(value)
        sets = ", ".join(f"{k} = ?" for k in fields)
        with self.db:
            self.db.execute(f"UPDATE exchanges SET {sets} WHERE id = ?", [*fields.values(), row_id])

    def overdue(self, now: str) -> list[sqlite3.Row]:
        return list(self.db.execute(
            "SELECT * FROM exchanges WHERE role = 'sender' AND delivered = 1 AND ack IS NULL AND missing IS NULL "
            "AND ack_deadline < ? ORDER BY ack_deadline", (now,)))

    # --- the local proxy's decisions (shared by every process on this state_dir) ------------------

    def add_decision(self, upstream: str, digest: str, rule_id: str, expires_at: float, *, limit: int,
                     outcome: str = "redacted") -> bool:
        """Keep a decision for the call with these bytes. An approval (``allowed``) is not kept when a
        redaction of the same bytes is already pending: the receipt must show that the content was
        changed. Returns whether it was kept."""
        now = time.time()
        with self.db:
            self.db.execute("DELETE FROM proxy_decisions WHERE expires_at < ?", (now,))
            if outcome == "allowed" and self.db.execute(
                    "SELECT 1 FROM proxy_decisions WHERE upstream = ? AND digest = ? AND outcome = 'redacted' AND expires_at >= ?",
                    (upstream, digest, now)).fetchone():
                return False
            if self.db.execute("SELECT COUNT(*) FROM proxy_decisions").fetchone()[0] >= limit:
                raise ValueError("too many pending decisions")
            self.db.execute("INSERT INTO proxy_decisions (upstream, digest, rule_id, expires_at, outcome) VALUES (?, ?, ?, ?, ?)",
                            (upstream, digest, rule_id, expires_at, outcome))
        return True

    def take_decision(self, upstream: str, digest: str) -> tuple[str, str] | None:
        """(outcome, rule id) of the decision for these bytes, removed so it is used once (by one
        process). A pending redaction comes before an approval; otherwise the oldest first."""
        while True:
            row = self.db.execute(
                "SELECT id, outcome, rule_id FROM proxy_decisions WHERE upstream = ? AND digest = ? AND expires_at >= ? "
                "ORDER BY outcome = 'redacted' DESC, id LIMIT 1", (upstream, digest, time.time())).fetchone()
            if row is None:
                return None
            with self.db:
                taken = self.db.execute("DELETE FROM proxy_decisions WHERE id = ?", (row["id"],)).rowcount
            if taken == 1:
                return str(row["outcome"]), str(row["rule_id"])

    def purge(self, now: str) -> int:
        with self.db:
            return self.db.execute("DELETE FROM exchanges WHERE retain_until < ?", (now,)).rowcount
