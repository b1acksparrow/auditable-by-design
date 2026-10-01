"""Durable managed-state store.

Backed by SQLite so that state versions, the execution journal and consumed
authorizations survive process restarts.  This is the executor's authoritative
state.  Observers read it through ``ReadOnlyStateView``, a separate connection
opened with ``mode=ro``, so they cannot write even by mistake.

Guarantees provided inside the store:
  * monotonic per-asset state versions, changed on the governed path only by
    ``apply`` (compare-and-set and the 'applied' journal mark in one commit);
  * an authorization digest can be consumed exactly once (UNIQUE constraint);
  * a journal row is committed *before* the managed state changes, so an
    interrupted execution leaves a 'prepared' or 'applied' row without a
    receipt, which the reconciler can find.
"""

import json
import os
import sqlite3
import urllib.parse
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    asset_id      TEXT PRIMARY KEY,
    state_version INTEGER NOT NULL,
    config_json   TEXT NOT NULL,
    peers_json    TEXT NOT NULL,
    impls_json    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS consumed_authorizations (
    authorization_digest TEXT PRIMARY KEY,
    tx_id                TEXT NOT NULL,
    consumed_at          INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS journal (
    tx_id            TEXT NOT NULL,
    attempt          INTEGER NOT NULL,
    asset_id         TEXT NOT NULL,
    expected_version INTEGER NOT NULL,
    target_digest    TEXT NOT NULL,
    phase            TEXT NOT NULL,          -- prepared | applied | receipted | failed | reconciled
    result_version   INTEGER,
    receipt_digest   TEXT,
    updated_at       INTEGER NOT NULL,
    PRIMARY KEY (tx_id, attempt)
);
"""


class StateError(Exception):
    pass


class VersionConflict(StateError):
    pass


class AuthorizationAlreadyConsumed(StateError):
    pass


class AuthorizationExpired(StateError):
    """The authorization expired between the gate check and the apply commit; nothing was applied."""


def _read_asset(conn, asset_id: str) -> dict:
    row = conn.execute(
        'SELECT state_version, config_json, peers_json, impls_json FROM assets WHERE asset_id=?',
        (asset_id,)).fetchone()
    if row is None:
        raise StateError(f'unknown asset {asset_id!r}')
    return {
        'asset_id': asset_id,
        'state_version': row[0],
        'config': json.loads(row[1]),
        'peers': json.loads(row[2]),
        'implementations': json.loads(row[3]),
    }


class ReadOnlyStateView:
    """Read-only interface to the authoritative state for observers.

    A separate SQLite connection opened with ``mode=ro``: it exposes no write
    method, and the database engine rejects writes on it."""

    def __init__(self, path: str):
        uri = 'file:' + urllib.parse.quote(os.path.abspath(path)) + '?mode=ro'
        self._conn = sqlite3.connect(uri, uri=True)

    def read_asset(self, asset_id: str) -> dict:
        return _read_asset(self._conn, asset_id)

    def close(self):
        self._conn.close()


class ManagedStateStore:
    def __init__(self, path: str, durable: bool = True):
        """``durable=True`` (default) fsyncs every commit (synchronous=FULL), which is the
        configuration the contract requires.  ``durable=False`` disables fsync and is
        used only to construct benchmark archives quickly and to quantify the cost of
        durability; it must not be used for a governed deployment."""
        self.path = path
        self.durable = durable
        self._conn = sqlite3.connect(path, isolation_level=None)  # autocommit; explicit BEGIN below
        self._conn.execute('PRAGMA journal_mode=WAL')
        self._conn.execute('PRAGMA synchronous=' + ('FULL' if durable else 'OFF'))
        self._conn.executescript(SCHEMA)

    def close(self):
        self._conn.close()

    @contextmanager
    def _tx(self):
        self._conn.execute('BEGIN IMMEDIATE')
        try:
            yield self._conn
            self._conn.execute('COMMIT')
        except Exception:
            self._conn.execute('ROLLBACK')
            raise

    # --- asset inventory -------------------------------------------------
    def register_asset(self, asset_id: str, config: dict, peers: dict, implementations: list,
                       state_version: int = 0):
        with self._tx() as c:
            c.execute('INSERT INTO assets VALUES (?,?,?,?,?)',
                      (asset_id, state_version, json.dumps(config, sort_keys=True),
                       json.dumps(peers, sort_keys=True), json.dumps(implementations)))

    def read_asset(self, asset_id: str) -> dict:
        """Current state as seen by the gate and the executor."""
        return _read_asset(self._conn, asset_id)

    def set_peer(self, asset_id: str, peer_id: str, capabilities: list, readiness: str = 'known'):
        """Inventory maintenance (outside the governed change path; used by tests)."""
        with self._tx() as c:
            peers = _read_asset(c, asset_id)['peers']
            peers[peer_id] = {'capabilities': capabilities, 'readiness': readiness}
            c.execute('UPDATE assets SET peers_json=? WHERE asset_id=?',
                      (json.dumps(peers, sort_keys=True), asset_id))

    def ungoverned_change(self, asset_id: str, config: dict):
        """Simulates an administrative change outside the executor: bumps the version.

        Used only to test freshness/version-binding rejection and reconciliation."""
        with self._tx() as c:
            c.execute('UPDATE assets SET state_version=state_version+1, config_json=? WHERE asset_id=?',
                      (json.dumps(config, sort_keys=True), asset_id))

    # --- one-time consumption -------------------------------------------
    def consume_authorization(self, authorization_digest: str, tx_id: str, now: int):
        try:
            with self._tx() as c:
                c.execute('INSERT INTO consumed_authorizations VALUES (?,?,?)',
                          (authorization_digest, tx_id, now))
        except sqlite3.IntegrityError:
            raise AuthorizationAlreadyConsumed(authorization_digest)

    def is_consumed(self, authorization_digest: str) -> bool:
        return self._conn.execute('SELECT 1 FROM consumed_authorizations WHERE authorization_digest=?',
                                  (authorization_digest,)).fetchone() is not None

    # --- journal ---------------------------------------------------------
    def prepare(self, authorization_digest: str, tx_id: str, asset_id: str, expected_version: int,
                target_digest: str, now: int) -> int:
        """Atomically consume the authorization and journal the execution attempt.

        Both facts become durable in one commit, so a crash can never leave an
        authorization consumed without a journal row (or the reverse)."""
        try:
            with self._tx() as c:
                c.execute('INSERT INTO consumed_authorizations VALUES (?,?,?)',
                          (authorization_digest, tx_id, now))
                row = c.execute('SELECT COALESCE(MAX(attempt),0) FROM journal WHERE tx_id=?', (tx_id,)).fetchone()
                attempt = row[0] + 1
                c.execute('INSERT INTO journal VALUES (?,?,?,?,?,?,?,?,?)',
                          (tx_id, attempt, asset_id, expected_version, target_digest, 'prepared', None, None, now))
        except sqlite3.IntegrityError:
            raise AuthorizationAlreadyConsumed(authorization_digest)
        return attempt

    def apply(self, tx_id: str, attempt: int, asset_id: str, expected_version: int, new_config: dict, now: int,
              not_after: int | None = None) -> int:
        """Atomically change the managed configuration (compare-and-set) and mark the
        journal row 'applied'.  The state change and its journal record are one durable step.
        ``not_after`` (the authorization's expiry) is re-checked inside the same commit."""
        conflict = None
        new_version = None
        with self._tx() as c:
            row = c.execute('SELECT state_version FROM assets WHERE asset_id=?', (asset_id,)).fetchone()
            if row is None:
                raise StateError(f'unknown asset {asset_id!r}')
            if not_after is not None and now > not_after:
                c.execute("UPDATE journal SET phase='failed', updated_at=? WHERE tx_id=? AND attempt=?",
                          (now, tx_id, attempt))
                conflict = AuthorizationExpired(f'authorization expired at {not_after}, apply attempted at {now}')
            elif row[0] != expected_version:
                # Record the failed attempt durably; the managed state is untouched.
                c.execute("UPDATE journal SET phase='failed', updated_at=? WHERE tx_id=? AND attempt=?",
                          (now, tx_id, attempt))
                conflict = VersionConflict(f'asset {asset_id!r} at version {row[0]}, expected {expected_version}')
            else:
                new_version = expected_version + 1
                c.execute('UPDATE assets SET state_version=?, config_json=? WHERE asset_id=? AND state_version=?',
                          (new_version, json.dumps(new_config, sort_keys=True), asset_id, expected_version))
                c.execute("UPDATE journal SET phase='applied', result_version=?, updated_at=? "
                          "WHERE tx_id=? AND attempt=?", (new_version, now, tx_id, attempt))
        if conflict is not None:
            raise conflict
        return new_version

    def journal_update(self, tx_id: str, attempt: int, phase: str, now: int,
                       result_version: int | None = None, receipt_digest: str | None = None):
        with self._tx() as c:
            c.execute('UPDATE journal SET phase=?, updated_at=?, '
                      'result_version=COALESCE(?, result_version), receipt_digest=COALESCE(?, receipt_digest) '
                      'WHERE tx_id=? AND attempt=?',
                      (phase, now, result_version, receipt_digest, tx_id, attempt))

    def journal_entries(self, tx_id: str | None = None) -> list:
        q = 'SELECT tx_id, attempt, asset_id, expected_version, target_digest, phase, result_version, receipt_digest, updated_at FROM journal'
        args = ()
        if tx_id is not None:
            q += ' WHERE tx_id=?'
            args = (tx_id,)
        cols = ['tx_id', 'attempt', 'asset_id', 'expected_version', 'target_digest', 'phase',
                'result_version', 'receipt_digest', 'updated_at']
        return [dict(zip(cols, r)) for r in self._conn.execute(q + ' ORDER BY tx_id, attempt', args)]

    def unresolved(self) -> list:
        return [j for j in self.journal_entries() if j['phase'] in ('prepared', 'applied')]

    def has_unresolved(self, asset_id: str) -> bool:
        """True while an execution attempt on the asset awaits a receipt or reconciliation."""
        return self._conn.execute("SELECT 1 FROM journal WHERE asset_id=? AND phase IN ('prepared','applied') LIMIT 1",
                                  (asset_id,)).fetchone() is not None
