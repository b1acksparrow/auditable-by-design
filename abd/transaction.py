"""Transaction lifecycle (Section IV-B/C).

States: proposed -> evaluated -> authorized -> prepared -> executed -> verified -> closed,
with rejected, failed, unresolved and recovered as explicit branches.  Every
terminal transaction, including a rejected proposal, produces an audit
envelope and a checkpoint so that repeated denials remain visible.
"""

import json
import uuid
from dataclasses import dataclass, field

from . import crypto
from .policy import PolicyGate, PolicyRegistry
from .roles import (Approver, Clock, EvidenceService, ExecutionRefused, Executor, ExecutorCrash, OperationFailed,
                    OutcomeObserver, ScriptedAdvisor, SourceObserver, Witness)
from .state import (AuthorizationAlreadyConsumed, AuthorizationExpired, ManagedStateStore, ReadOnlyStateView,
                    VersionConflict)

PROPOSED, EVALUATED, AUTHORIZED, PREPARED, EXECUTED, VERIFIED, CLOSED = (
    'proposed', 'evaluated', 'authorized', 'prepared', 'executed', 'verified', 'closed')
REJECTED, FAILED, UNRESOLVED, RECOVERED = 'rejected', 'failed', 'unresolved', 'recovered'
TERMINAL = {CLOSED, REJECTED, FAILED, RECOVERED}


@dataclass
class Transaction:
    tx_id: str
    asset_id: str
    status: str = PROPOSED
    observation: dict | None = None
    proposal: dict | None = None
    gate: object = None
    authorization: dict | None = None
    receipt: dict | None = None
    outcome: dict | None = None
    envelope: dict | None = None
    checkpoint: dict | None = None
    chain_hash: str | None = None
    error: str | None = None
    history: list = field(default_factory=list)
    advisor_transcript: dict | None = None      # retained separately; the proposal references its digest

    def _to(self, status):
        self.history.append(status)
        self.status = status

    def record(self) -> dict:
        return {
            'schema': 'transaction_record_v2',
            'tx_id': self.tx_id,
            'asset_id': self.asset_id,
            'status': self.status,
            'source': self.observation,
            'proposal': self.proposal,
            'authorization': self.authorization,
            'executor': self.receipt,
            'outcome': self.outcome,
            'envelope': self.envelope,
            'chain_hash': self.chain_hash,
            'checkpoint': self.checkpoint,
            'error': self.error,
        }


class MigrationSystem:
    """Wires the roles together.  All roles run in one process; see Section VIII-D."""

    def __init__(self, signers: dict, store: ManagedStateStore, registry: PolicyRegistry, clock: Clock,
                 log_id: str = 'audit-log-001', delta_s: int = 600, sink=None):
        self.signers = signers
        self.store = store
        self.registry = registry
        self.clock = clock
        self.log_id = log_id
        self.delta_s = delta_s
        self.trust = crypto.TrustConfig.from_signers(signers)
        self.gate = PolicyGate(registry, clock)
        # Observers get a separate read-only connection; only the executor holds the writable store.
        self.view = ReadOnlyStateView(store.path)
        self.source = SourceObserver(signers['source_observer'], self.view, clock, registry)
        self.advisor = ScriptedAdvisor()
        self.approver = Approver(signers['authorizer'], clock)
        self.executor = Executor(signers['executor'], store, self.gate, self.trust, clock)
        self.outcome_observer = OutcomeObserver(signers['outcome_observer'], self.view, clock)
        self.evidence = EvidenceService(signers['evidence_service'], log_id, clock)
        self.witness = Witness(signers['checkpoint_witness'], clock)
        self.records: list = []
        self.sink = sink            # optional callable(record) for streaming archives
        self.open: dict[str, Transaction] = {}

    # --- lifecycle steps ------------------------------------------------
    def begin(self, asset_id: str) -> Transaction:
        tx = Transaction(tx_id=str(uuid.uuid4()), asset_id=asset_id)
        tx.history.append(PROPOSED)
        self.open[tx.tx_id] = tx
        return tx

    def observe(self, tx: Transaction) -> dict:
        tx.observation = self.source.observe(tx.asset_id, tx.tx_id)
        return tx.observation

    def propose(self, tx: Transaction, target_profile_id: str, endpoints=None) -> dict:
        policy = self.registry.active
        prof = policy.allowlist.get(target_profile_id)
        if prof is None:
            # The advisor may propose something not on the allowlist; the gate must reject it.
            from .policy import Profile
            prof = Profile(target_profile_id, 'TLS1.3', 'UNAPPROVED', 'UNAPPROVED', 'classical', 'kem:unapproved', 'unknown')
        tx.proposal = self.advisor.propose(tx.observation, prof, policy, endpoints)
        return tx.proposal

    def evaluate(self, tx: Transaction):
        current = self.executor.current_state(tx.asset_id)
        tx.gate = self.gate.evaluate_pre_approval(tx.observation['statement'], tx.proposal, current)
        tx._to(EVALUATED)
        return tx.gate

    def authorize(self, tx: Transaction, approve: bool = True, **kw) -> dict:
        tx.authorization = self.approver.decide(tx.proposal, tx.observation, tx.gate, self.registry.active,
                                                approve=approve, **kw)
        if tx.authorization['statement']['decision'] == 'authorized':
            tx._to(AUTHORIZED)
        else:
            tx.error = 'denied: ' + (tx.authorization['statement'].get('denial_reason') or 'by approver')
            tx._to(REJECTED)
        return tx.authorization

    def execute(self, tx: Transaction, fault: str | None = None) -> dict | None:
        if tx.status != AUTHORIZED:
            raise RuntimeError(f'cannot execute transaction in state {tx.status}')
        tx._to(PREPARED)
        try:
            tx.receipt = self.executor.execute(tx.observation, tx.proposal, tx.authorization, fault=fault)
        except ExecutionRefused as exc:
            tx.error = str(exc)
            tx._to(REJECTED)
            return None
        except AuthorizationAlreadyConsumed:
            tx.error = 'authorization already consumed'
            tx._to(REJECTED)
            return None
        except VersionConflict as exc:
            tx.error = f'version conflict: {exc}'
            tx._to(FAILED)
            return None
        except (OperationFailed, AuthorizationExpired) as exc:
            tx.error = str(exc)
            tx._to(FAILED)
            return None
        except ExecutorCrash as exc:
            tx.error = f'executor crashed: {exc}'
            tx._to(UNRESOLVED)
            return None
        tx._to(EXECUTED)
        return tx.receipt

    def observe_outcome(self, tx: Transaction) -> dict:
        tx.outcome = self.outcome_observer.observe(tx.asset_id, tx.tx_id, tx.receipt['digest'], self.registry.active)
        obs = tx.outcome['statement']
        rc = tx.receipt['statement']
        ok = (obs['observed']['state_version'] == rc['state_version_after']
              and obs['observed_profile_id'] == tx.proposal['target_profile_id']
              and obs['observed_config_digest'] == rc['applied_config_digest']
              and obs['health_checks']['profile_on_allowlist']
              and obs['health_checks']['config_matches_profile'])
        if ok:
            tx._to(VERIFIED)
        else:
            tx.error = 'outcome verification failed'
            tx._to(FAILED)
        return tx.outcome

    def reconcile(self, tx: Transaction) -> str:
        """Resolve an UNRESOLVED transaction from the durable journal and authoritative state."""
        if tx.status != UNRESOLVED:
            raise RuntimeError(f'cannot reconcile transaction in state {tx.status}')
        phase, late_receipt = self.executor.reconcile(tx.tx_id, tx.proposal, tx.authorization)
        if phase == 'applied_without_receipt':
            tx.receipt = late_receipt
            tx._to(EXECUTED)
            self.observe_outcome(tx)
            if tx.status == VERIFIED:
                tx._to(RECOVERED)
        elif phase == 'not_applied':
            tx.error = 'reconciled: change not applied; authorization consumed; reassessment required'
            tx._to(FAILED)
        else:
            tx.error = f'reconciled: {phase}'
            tx._to(FAILED)
        return tx.status

    def close(self, tx: Transaction) -> dict:
        if tx.status == VERIFIED:
            tx._to(CLOSED)
        if tx.status not in TERMINAL and tx.status != UNRESOLVED:
            raise RuntimeError(f'cannot close transaction in state {tx.status}')
        digests = {
            'source': tx.observation['digest'] if tx.observation else None,
            'proposal': crypto.action_digest_hex(tx.proposal) if tx.proposal else None,
            'authorization': tx.authorization['digest'] if tx.authorization else None,
            'executor': tx.receipt['digest'] if tx.receipt else None,
            'outcome': tx.outcome['digest'] if tx.outcome else None,
        }
        tx.envelope, tx.chain_hash = self.evidence.append(tx.tx_id, tx.status, digests)
        tx.checkpoint = self.witness.checkpoint(self.log_id, self.evidence.index, tx.chain_hash)
        rec = tx.record()
        self.open.pop(tx.tx_id, None)
        if self.sink is not None:
            self.sink(rec)
        else:
            self.records.append(rec)
        return rec

    # --- convenience ----------------------------------------------------
    def run(self, asset_id: str, target_profile_id: str, endpoints=None, approve: bool = True,
            fault: str | None = None, reconcile_on_crash: bool = True, **approve_kw) -> Transaction:
        tx = self.begin(asset_id)
        self.observe(tx)
        self.propose(tx, target_profile_id, endpoints)
        return self._complete(tx, approve, fault, reconcile_on_crash, **approve_kw)

    def advise(self, tx: Transaction, advisor, task: str, documents=()) -> dict:
        """Obtain the proposal from a model-backed advisor (see abd.llm_advisor)."""
        tx.proposal, tx.advisor_transcript = advisor.propose(tx.observation, self.registry.active, task, documents)
        return tx.proposal

    def run_advised(self, asset_id: str, advisor, task: str, documents=(), approve: bool = True,
                    **approve_kw) -> Transaction:
        """As ``run``, with the proposal produced by ``advisor``.  An advisor failure raises
        ``AdvisorError`` before anything is recorded: no proposal, no transaction."""
        tx = self.begin(asset_id)
        self.observe(tx)
        try:
            self.advise(tx, advisor, task, documents)
        except Exception:
            self.open.pop(tx.tx_id, None)
            raise
        return self._complete(tx, approve, None, True, **approve_kw)

    def _complete(self, tx: Transaction, approve: bool, fault: str | None, reconcile_on_crash: bool,
                  **approve_kw) -> Transaction:
        self.evaluate(tx)
        self.authorize(tx, approve=approve, **approve_kw)
        if tx.status == AUTHORIZED:
            self.execute(tx, fault=fault)
            if tx.status == EXECUTED:
                self.observe_outcome(tx)
            elif tx.status == UNRESOLVED and reconcile_on_crash:
                self.reconcile(tx)
        self.close(tx)
        return tx

    def retained_checkpoint(self) -> dict | None:
        return self.witness.latest(self.log_id)


# ---------------------------------------------------------------------------
class JsonlArchiveWriter:
    """Streams records to a JSON Lines file; used as a MigrationSystem sink."""

    def __init__(self, path: str):
        self.path = path
        self._fh = open(path, 'w', encoding='utf-8')
        self.count = 0
        self.bytes = 0

    def __call__(self, record: dict):
        line = json.dumps(record, separators=(',', ':')) + '\n'
        self._fh.write(line)
        self.count += 1
        self.bytes += len(line.encode('utf-8'))

    def close(self):
        self._fh.close()
