"""Logical roles of the architecture (Section III-A, IV-A).

Each role owns exactly one signing key and validates its own inputs before
signing.  Only the executor writes managed state.  Observers use the store's
read-only interface.  The advisor holds no key: its output is an advisory
artifact, never a signed statement.
"""

import time

from . import crypto
from .policy import RECOVERY_ISOLATE, PolicyGate, PolicyRegistry, PolicyVersion, Profile, meets_floor, recovery_permitted
from .state import ManagedStateStore, ReadOnlyStateView


class Clock:
    def now(self) -> int:
        return int(time.time())


class TestClock(Clock):
    def __init__(self, start: int = 1_800_000_000):
        self._t = start

    def now(self) -> int:
        return self._t

    def advance(self, seconds: int):
        self._t += seconds


class ExecutionRefused(Exception):
    def __init__(self, decision):
        super().__init__('execution refused: ' + ', '.join(decision.failed()))
        self.decision = decision


class ExecutorCrash(Exception):
    """Injected fault: the executor process dies at a chosen point."""


class OperationFailed(Exception):
    """The controlled operation failed after the authorization was consumed; nothing was applied."""


# ---------------------------------------------------------------------------
class SourceObserver:
    def __init__(self, signer: crypto.RoleSigner, view: ReadOnlyStateView, clock: Clock, registry: PolicyRegistry):
        self.signer = signer
        self.view = view
        self.clock = clock
        self.registry = registry

    def observe(self, asset_id: str, tx_id: str) -> dict:
        a = self.view.read_asset(asset_id)
        snapshot = {
            'asset_id': asset_id,
            'state_version': a['state_version'],
            'config': a['config'],
            'peers': a['peers'],
            'implementations': a['implementations'],
        }
        stmt = {
            'schema': 'source_observation_v2',
            'role': 'source_observer',
            'tx_id': tx_id,
            'source_id': self.signer.key_id,
            'captured_at': self.clock.now(),
            'freshness_limit_s': self.registry.active.freshness_limit_s,
            'snapshot': snapshot,
            'snapshot_digest': crypto.snapshot_digest_hex(snapshot),
        }
        return self.signer.sign_statement(stmt)


# ---------------------------------------------------------------------------
class ScriptedAdvisor:
    """Stand-in for the AI advisor.  Produces a typed proposal; free text stays advisory."""

    model = {'name': 'scripted-advisor', 'version': '2.0.0', 'inference': 'none'}

    def propose(self, observation: dict, target: Profile, policy: PolicyVersion,
                endpoints: list | None = None, alternatives: list | None = None) -> dict:
        snap = observation['statement']['snapshot']
        if endpoints is None:
            endpoints = sorted(p for p, c in snap['peers'].items() if c.get('readiness') == 'known')
        unknown = sorted(p for p, c in snap['peers'].items() if c.get('readiness') != 'known')
        return {
            'schema': 'ai_proposal_v2',
            'tx_id': observation['statement']['tx_id'],
            'asset_id': snap['asset_id'],
            'action': 'migrate_profile',
            'target_profile_id': target.profile_id,
            'target_config': target.target_config(),
            'endpoints': endpoints,
            'policy_version': policy.version,
            'evidence_refs': [{'kind': 'source_observation', 'digest': observation['digest']}],
            'model': dict(self.model),
            'alternatives': alternatives or [],
            'unresolved_dependencies': unknown,
            'uncertainty': {'confidence': None, 'calibration_ref': None, 'note': 'scripted proposal, no model inference'},
            'rationale': f"Asset {snap['asset_id']} currently on {snap['config']['profile_id']}; "
                         f"propose {target.profile_id} for {len(endpoints)} ready endpoint(s).",
        }


# ---------------------------------------------------------------------------
class Approver:
    def __init__(self, signer: crypto.RoleSigner, clock: Clock):
        self.signer = signer
        self.clock = clock

    def decide(self, proposal: dict, observation: dict, gate_decision, policy: PolicyVersion,
               approve: bool = True, basis: str = 'human:change-approver-1',
               permitted_recovery: str | None = None, test_evidence_refs: list | None = None) -> dict:
        now = self.clock.now()
        snap = observation['statement']['snapshot']
        recovery = permitted_recovery or self.default_recovery(snap['config']['profile_id'], policy)
        # The approver validates its own inputs before signing: it never authorizes a recovery
        # target that the policy does not permit.
        recovery_ok, recovery_why = recovery_permitted(policy, recovery)
        decision = 'authorized' if (approve and gate_decision.permitted and recovery_ok) else 'denied'
        if not approve:
            reason = 'declined by approver'
        elif not gate_decision.permitted:
            reason = 'gate: ' + ', '.join(gate_decision.failed())
        elif not recovery_ok:
            reason = f'permitted recovery: {recovery_why}'
        else:
            reason = None
        stmt = {
            'schema': 'authorization_v2',
            'role': 'authorizer',
            'tx_id': proposal['tx_id'],
            'asset_id': proposal['asset_id'],
            'decision': decision,
            'approval_basis': basis if approve else 'human:declined',
            'policy_version': policy.version,
            'policy_digest': policy.digest(),
            'expected_state_version': snap['state_version'],
            'target_profile_id': proposal['target_profile_id'],
            'target_config_digest': crypto.action_digest_hex(proposal),
            'source_record_digest': observation['digest'],
            'test_evidence_refs': test_evidence_refs or [],
            'gate': gate_decision.to_json(),
            'expires_at': now + policy.approval_ttl_s,
            'permitted_recovery': recovery,
            'denial_reason': reason,
            'timestamp': now,
        }
        return self.signer.sign_statement(stmt)

    @staticmethod
    def default_recovery(current_profile_id: str, policy: PolicyVersion) -> str:
        """Restore the current profile only if it still meets the security floor; otherwise isolate."""
        prof = policy.allowlist.get(current_profile_id)
        return current_profile_id if prof is not None and meets_floor(prof, policy) else RECOVERY_ISOLATE


# ---------------------------------------------------------------------------
class Executor:
    def __init__(self, signer: crypto.RoleSigner, store: ManagedStateStore, gate: PolicyGate,
                 trust: crypto.TrustConfig, clock: Clock):
        self.signer = signer
        self.store = store
        self.gate = gate
        self.trust = trust
        self.clock = clock

    def current_state(self, asset_id: str) -> dict:
        """Authoritative state plus whether an earlier attempt on the asset is still unresolved."""
        current = self.store.read_asset(asset_id)
        current['pending_reconciliation'] = self.store.has_unresolved(asset_id)
        return current

    def execute(self, observation: dict, proposal: dict, authorization: dict, fault: str | None = None) -> dict:
        asset_id = proposal['asset_id']
        tx_id = proposal['tx_id']
        current = self.current_state(asset_id)
        decision = self.gate.evaluate_full(observation, proposal, current, authorization, self.trust)
        if not decision.permitted:
            raise ExecutionRefused(decision)
        now = self.clock.now()
        expected = authorization['statement']['expected_state_version']
        target_digest = authorization['statement']['target_config_digest']
        # One-time consumption and the execution-attempt journal row: one durable commit before any change.
        attempt = self.store.prepare(authorization['digest'], tx_id, asset_id, expected, target_digest, now)
        if fault == 'crash_before_apply':
            raise ExecutorCrash('crash_before_apply')
        try:
            operation = crypto.kem_roundtrip()
        except Exception as exc:
            # Nothing was applied; the consumed authorization stays consumed and the attempt is closed as failed.
            self.store.journal_update(tx_id, attempt, 'failed', self.clock.now())
            raise OperationFailed(f'controlled operation failed: {exc}') from exc
        # Compare-and-set on the state version and the 'applied' journal mark: one durable commit.
        applied_at = self.clock.now()
        new_version = self.store.apply(tx_id, attempt, asset_id, expected, proposal['target_config'], applied_at,
                                       not_after=authorization['statement']['expires_at'])
        if fault == 'crash_after_apply':
            raise ExecutorCrash('crash_after_apply')
        receipt = self._receipt(tx_id, asset_id, attempt, authorization, proposal, expected, new_version, operation,
                                applied_at)
        self.store.journal_update(tx_id, attempt, 'receipted', self.clock.now(), receipt_digest=receipt['digest'])
        return receipt

    def _receipt(self, tx_id, asset_id, attempt, authorization, proposal, before, after, operation, applied_at,
                 late=False) -> dict:
        stmt = {
            'schema': 'executor_receipt_v2',
            'role': 'executor',
            'tx_id': tx_id,
            'asset_id': asset_id,
            'attempt': attempt,
            'authorization_digest': authorization['digest'],
            'proposal_digest': crypto.action_digest_hex(proposal),
            'state_version_before': before,
            'state_version_after': after,
            'applied_config_digest': crypto.snapshot_digest_hex(proposal['target_config']),
            'operation': operation,
            'late_receipt': late,
            'applied_at': applied_at,
            'timestamp': self.clock.now(),
        }
        return self.signer.sign_statement(stmt)

    def reconcile(self, tx_id: str, proposal: dict, authorization: dict) -> tuple[str, dict | None]:
        """Compare the journal with authoritative state for an unresolved transaction.

        Returns (phase, late_receipt_or_None).  Absence of a receipt is never
        taken as evidence that no change occurred: the state version and the
        applied configuration are compared with the journal row.
        """
        entries = [j for j in self.store.journal_entries(tx_id) if j['phase'] in ('prepared', 'applied')]
        if not entries:
            return 'resolved', None
        j = entries[-1]
        asset = self.store.read_asset(j['asset_id'])
        applied_digest = crypto.snapshot_digest_hex(asset['config'])
        target_digest = crypto.snapshot_digest_hex(proposal['target_config'])
        if (j['phase'] == 'applied' and asset['state_version'] == j['expected_version'] + 1
                and applied_digest == target_digest):
            # The journal row's timestamp is the durable time of the 'applied' commit.
            receipt = self._receipt(tx_id, j['asset_id'], j['attempt'], authorization, proposal,
                                    j['expected_version'], asset['state_version'],
                                    {'algorithm': crypto.KEM_ALG, 'key_agreement': None,
                                     'note': 'operation result not retained; change confirmed from authoritative state'},
                                    j['updated_at'], late=True)
            self.store.journal_update(tx_id, j['attempt'], 'receipted', self.clock.now(), receipt_digest=receipt['digest'])
            return 'applied_without_receipt', receipt
        if asset['state_version'] == j['expected_version']:
            self.store.journal_update(tx_id, j['attempt'], 'failed', self.clock.now())
            return 'not_applied', None
        self.store.journal_update(tx_id, j['attempt'], 'reconciled', self.clock.now())
        return 'state_diverged', None


# ---------------------------------------------------------------------------
class OutcomeObserver:
    """Independent observation of the resulting state through the read interface.

    The observed profile is read from the authoritative store; it is not
    derived from the source snapshot or from the receipt."""

    def __init__(self, signer: crypto.RoleSigner, view: ReadOnlyStateView, clock: Clock):
        self.signer = signer
        self.view = view
        self.clock = clock

    def observe(self, asset_id: str, tx_id: str, receipt_digest: str, policy: PolicyVersion) -> dict:
        a = self.view.read_asset(asset_id)
        profile_id = a['config'].get('profile_id')
        prof = policy.allowlist.get(profile_id)
        health = {
            'profile_on_allowlist': prof is not None,
            'config_matches_profile': prof is not None and a['config'] == prof.target_config(),
            'kem_negotiated': a['config'].get('kem'),
        }
        stmt = {
            'schema': 'outcome_observation_v2',
            'role': 'outcome_observer',
            'tx_id': tx_id,
            'asset_id': asset_id,
            'observer_id': self.signer.key_id,
            'receipt_digest': receipt_digest,
            'observed_at': self.clock.now(),
            'observed': {'state_version': a['state_version'], 'config': a['config']},
            'observed_profile_id': profile_id,
            'observed_config_digest': crypto.snapshot_digest_hex(a['config']),
            'health_checks': health,
        }
        return self.signer.sign_statement(stmt)


# ---------------------------------------------------------------------------
class EvidenceService:
    """Appends audit envelopes to a hash chain (Eq. 2)."""

    def __init__(self, signer: crypto.RoleSigner, log_id: str, clock: Clock):
        self.signer = signer
        self.log_id = log_id
        self.clock = clock
        self.index = -1
        self.head = crypto.GENESIS_HEAD

    def append(self, tx_id: str, status: str, digests: dict) -> tuple[dict, str]:
        index = self.index + 1
        stmt = {
            'schema': 'audit_envelope_v2',
            'role': 'evidence_service',
            'tx_id': tx_id,
            'log_id': self.log_id,
            'index': index,
            'chain_prev': self.head,
            'status': status,
            'source_digest': digests.get('source'),
            'proposal_digest': digests.get('proposal'),
            'authorization_digest': digests.get('authorization'),
            'executor_digest': digests.get('executor'),
            'outcome_digest': digests.get('outcome'),
            'timestamp': self.clock.now(),
        }
        signed = self.signer.sign_statement(stmt)
        head = crypto.chain_hash_hex(index, self.head, stmt)
        self.index, self.head = index, head
        return signed, head


# ---------------------------------------------------------------------------
class Witness:
    """External checkpoint witness.  Retains every checkpoint it signs."""

    def __init__(self, signer: crypto.RoleSigner, clock: Clock):
        self.signer = signer
        self.clock = clock
        self.retained: dict[str, list] = {}

    def checkpoint(self, log_id: str, sequence: int, head: str) -> dict:
        prev = self.retained.get(log_id)
        if prev and sequence <= prev[-1]['statement']['sequence']:
            raise ValueError('checkpoint sequence must increase')
        stmt = {
            'schema': 'checkpoint_v2',
            'role': 'checkpoint_witness',
            'witness_id': self.signer.key_id,
            'log_id': log_id,
            'sequence': sequence,
            'witnessed_head': head,
            'witness_time': self.clock.now(),
        }
        signed = self.signer.sign_statement(stmt)
        self.retained.setdefault(log_id, []).append(signed)
        return signed

    def latest(self, log_id: str) -> dict | None:
        lst = self.retained.get(log_id)
        return lst[-1] if lst else None
