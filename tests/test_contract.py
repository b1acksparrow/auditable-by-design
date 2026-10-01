"""Transaction contract tests: policy gate (Eq. 1), one-time consumption,
version binding, interrupted changes and reconciliation."""

import json
import sqlite3

import pytest

from abd import crypto
from abd.fixture import ASSET, CLASSICAL, HYBRID, PQC, READY_ENDPOINTS, make_system
from abd.policy import RECOVERY_ISOLATE, PolicyVersion, default_policy
from abd.state import AuthorizationAlreadyConsumed, ManagedStateStore
from abd.transaction import (AUTHORIZED, CLOSED, FAILED, RECOVERED, REJECTED, UNRESOLVED)
from conftest import failures_mention, resign, verify


def test_successful_migration_closes_with_full_state_history(system):
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS)
    assert tx.status == CLOSED
    assert tx.history == ['proposed', 'evaluated', 'authorized', 'prepared', 'executed', 'verified', 'closed']
    assert tx.receipt['statement']['operation']['key_agreement'] is True
    assert system.store.read_asset(ASSET)['state_version'] == 1
    assert system.store.read_asset(ASSET)['config']['profile_id'] == HYBRID
    r = verify(system)
    assert r.ok, r.failures
    assert r.signatures_checked == 7  # six roles in the record + retained checkpoint


def test_unapproved_profile_is_denied_by_allowed_conjunct(system):
    tx = system.run(ASSET, 'tls13-frodokem', endpoints=READY_ENDPOINTS)
    assert tx.status == REJECTED
    assert 'Allowed' in tx.gate.failed()
    assert tx.receipt is None
    assert verify(system).ok


def test_unsupported_peer_is_denied_by_compatible_conjunct(system):
    tx = system.run(ASSET, PQC, endpoints=['peer-a', 'peer-legacy'])
    assert tx.status == REJECTED
    assert tx.gate.failed() == ['Compatible']
    assert 'peer-legacy' in tx.error or 'Compatible' in tx.error


def test_unknown_peer_readiness_is_not_assumed_compatible(system):
    tx = system.run(ASSET, PQC, endpoints=['peer-unknown'])
    assert tx.status == REJECTED
    assert tx.gate.failed() == ['Compatible']
    assert 'peer-unknown' in tx.proposal['unresolved_dependencies']


def test_missing_implementation_is_denied(system):
    pv = default_policy(1)
    pv.allowlist[PQC] = pv.allowlist[PQC].__class__(**{**pv.allowlist[PQC].__dict__, 'implementation': 'liboqs-9.9.9'})
    system.registry.register(pv)
    tx = system.run(ASSET, PQC, endpoints=READY_ENDPOINTS)
    assert tx.status == REJECTED and tx.gate.failed() == ['Compatible']


def test_expired_observation_is_denied_by_fresh_conjunct(system, clock):
    tx = system.begin(ASSET)
    system.observe(tx)
    clock.advance(system.registry.active.freshness_limit_s + 1)
    system.propose(tx, HYBRID, READY_ENDPOINTS)
    system.evaluate(tx)
    assert tx.gate.failed() == ['Fresh']
    system.authorize(tx)
    assert tx.status == REJECTED
    system.close(tx)
    assert verify(system).ok


def test_state_change_between_approval_and_execution_invalidates_approval(system):
    tx = system.begin(ASSET)
    system.observe(tx)
    system.propose(tx, HYBRID, READY_ENDPOINTS)
    system.evaluate(tx)
    system.authorize(tx)
    assert tx.status == AUTHORIZED
    # An administrator changes the asset outside the executor.
    system.store.ungoverned_change(ASSET, {'profile_id': 'manual', 'kem': 'X25519', 'cipher_label': 'x', 'protocol': 'TLS1.3'})
    system.execute(tx)
    assert tx.status == REJECTED
    assert 'Fresh' in tx.error and 'Authorized' in tx.error
    assert not system.store.is_consumed(tx.authorization['digest'])
    system.close(tx)


def test_proposal_change_after_approval_invalidates_approval(system):
    tx = system.begin(ASSET)
    system.observe(tx)
    system.propose(tx, HYBRID, READY_ENDPOINTS)
    system.evaluate(tx)
    system.authorize(tx)
    tx.proposal['target_config']['kem'] = 'ML-KEM-1024'  # advisor edits after approval
    system.execute(tx)
    assert tx.status == REJECTED
    assert 'Allowed' in tx.error and 'Authorized' in tx.error


def test_expired_authorization_is_refused(system, clock):
    tx = system.begin(ASSET)
    system.observe(tx)
    system.propose(tx, HYBRID, READY_ENDPOINTS)
    system.evaluate(tx)
    system.authorize(tx)
    clock.advance(system.registry.active.approval_ttl_s + 1)
    system.execute(tx)
    assert tx.status == REJECTED and 'Authorized' in tx.error


def test_policy_version_change_invalidates_approval(system):
    tx = system.begin(ASSET)
    system.observe(tx)
    system.propose(tx, HYBRID, READY_ENDPOINTS)
    system.evaluate(tx)
    system.authorize(tx)
    system.registry.register(default_policy(2))
    system.execute(tx)
    assert tx.status == REJECTED and 'Allowed' in tx.error and 'Authorized' in tx.error


def test_recovery_below_security_floor_is_not_allowed(system):
    assert system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS).status == CLOSED
    back = system.run(ASSET, CLASSICAL, endpoints=READY_ENDPOINTS)
    assert back.status == REJECTED
    assert 'Allowed' in back.gate.failed()
    assert any('security floor' in c.reason for c in back.gate.conjuncts if not c.ok)


def test_approver_decline_is_retained_and_verifiable(system):
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS, approve=False)
    assert tx.status == REJECTED and tx.gate.permitted
    assert tx.authorization['statement']['decision'] == 'denied'
    assert verify(system).ok


def test_rejected_then_completed_sequence_verifies(system):
    assert system.run(ASSET, PQC, endpoints=['peer-legacy']).status == REJECTED
    assert system.run(ASSET, PQC, endpoints=READY_ENDPOINTS).status == CLOSED
    r = verify(system)
    assert r.ok and r.rejected == 1 and r.closed == 1


def test_authorization_is_consumed_exactly_once_and_survives_restart(store, clock, signers, tmp_path):
    system = make_system(store=store, clock=clock, signers=signers)
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS)
    digest = tx.authorization['digest']
    assert store.is_consumed(digest)
    with pytest.raises(AuthorizationAlreadyConsumed):
        store.consume_authorization(digest, tx.tx_id, clock.now())
    # Restart: new process over the same durable file.
    store.close()
    store2 = ManagedStateStore(str(tmp_path / 'state.sqlite'))
    assert store2.is_consumed(digest)
    with pytest.raises(AuthorizationAlreadyConsumed):
        store2.consume_authorization(digest, tx.tx_id, clock.now())
    assert store2.read_asset(ASSET)['state_version'] == 1


def test_replayed_authorization_after_restart_is_refused(store, clock, signers, tmp_path):
    system = make_system(store=store, clock=clock, signers=signers)
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS)
    store.close()
    store2 = ManagedStateStore(str(tmp_path / 'state.sqlite'))
    system2 = make_system(store=store2, clock=clock, signers=signers)
    # Present the old, already-consumed authorization to a restarted executor.
    from abd.roles import ExecutionRefused
    with pytest.raises(ExecutionRefused) as ei:
        system2.executor.execute(tx.observation, tx.proposal, tx.authorization)
    assert 'Fresh' in ei.value.decision.failed()  # version moved on; and if it had not:
    assert store2.is_consumed(tx.authorization['digest'])


def test_crash_after_apply_is_unresolved_then_recovered_by_reconciliation(system):
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS, fault='crash_after_apply', reconcile_on_crash=False)
    assert tx.status == UNRESOLVED
    assert system.store.read_asset(ASSET)['state_version'] == 1        # change happened
    assert len(system.store.unresolved()) == 1                         # journal row stays open
    # The journal row remains 'applied' with no receipt until reconciliation.
    assert system.store.journal_entries(tx.tx_id)[-1]['phase'] == 'applied'
    # Reconcile in a fresh transaction context (the record was closed as unresolved).
    tx.status = UNRESOLVED
    assert system.reconcile(tx) == RECOVERED
    assert tx.receipt['statement']['late_receipt'] is True
    assert system.store.journal_entries(tx.tx_id)[-1]['phase'] == 'receipted'


def test_crash_after_apply_with_inline_reconciliation_verifies(system):
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS, fault='crash_after_apply')
    assert tx.status == RECOVERED
    r = verify(system)
    assert r.ok, r.failures
    # A later transaction continues from the recovered version.
    assert system.run(ASSET, PQC, endpoints=READY_ENDPOINTS).status == CLOSED
    assert verify(system).ok


def test_crash_before_apply_leaves_state_unchanged_and_consumes_authorization(system):
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS, fault='crash_before_apply')
    assert tx.status == FAILED
    assert system.store.read_asset(ASSET)['state_version'] == 0
    assert system.store.is_consumed(tx.authorization['digest'])
    assert system.store.journal_entries(tx.tx_id)[-1]['phase'] == 'failed'
    # Reassessment requires a new transaction; it succeeds from the unchanged state.
    assert system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS).status == CLOSED
    assert verify(system).ok


def test_absence_of_receipt_is_not_evidence_of_no_change(system):
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS, fault='crash_after_apply', reconcile_on_crash=False)
    assert tx.receipt is None
    assert system.store.read_asset(ASSET)['config']['profile_id'] == HYBRID


def test_outcome_observer_reads_authoritative_state_not_receipt(system):
    tx = system.begin(ASSET)
    system.observe(tx)
    system.propose(tx, HYBRID, READY_ENDPOINTS)
    system.evaluate(tx)
    system.authorize(tx)
    system.execute(tx)
    # Drift after execution but before observation: the observer must report it.
    system.store.ungoverned_change(ASSET, {'profile_id': 'manual', 'kem': 'X25519', 'cipher_label': 'x', 'protocol': 'TLS1.3'})
    system.observe_outcome(tx)
    assert tx.status == FAILED
    assert tx.outcome['statement']['observed_profile_id'] == 'manual'


def test_exported_record_contains_no_private_or_shared_secret_bytes(system, signers):
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS)
    blob = json.dumps(tx.record())
    for s in signers.values():
        assert s._signer.export_secret_key().hex() not in blob
        assert s.public_key.hex() not in blob  # public keys travel in the trust config, not the record
    op = tx.receipt['statement']['operation']
    assert set(op) == {'algorithm', 'ciphertext_digest', 'public_key_bytes', 'ciphertext_bytes',
                       'shared_secret_bytes', 'key_agreement'}
    assert 'shared_secret' not in blob.replace('shared_secret_bytes', '')


def test_advisor_output_is_typed_and_unsigned(system):
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS)
    assert 'signature' not in tx.proposal
    assert tx.proposal['uncertainty']['confidence'] is None
    assert tx.authorization['statement']['target_config_digest'] == crypto.action_digest_hex(tx.proposal)


def test_multi_asset_continuity(store, clock, signers):
    from abd.fixture import make_store
    system = make_system(store=make_store(assets=3), clock=clock, signers=signers)
    for asset in ('svc-internal-01', 'svc-internal-02', 'svc-internal-03', 'svc-internal-01'):
        target = HYBRID if store.read_asset(ASSET)['state_version'] == 0 else PQC
        t = system.run(asset, HYBRID if system.store.read_asset(asset)['state_version'] == 0 else PQC,
                       endpoints=READY_ENDPOINTS)
        assert t.status == CLOSED
    assert system.store.read_asset('svc-internal-01')['state_version'] == 2
    assert verify(system).ok


# --- re-evaluation against the then-current state, policy-bound limits -------
def test_dependency_change_between_approval_and_execution_invalidates_approval(system):
    tx = system.begin(ASSET)
    system.observe(tx)
    system.propose(tx, HYBRID, READY_ENDPOINTS)
    system.evaluate(tx)
    system.authorize(tx)
    assert tx.status == AUTHORIZED
    # A proposed endpoint loses the hybrid capability; the state version does not change.
    system.store.set_peer(ASSET, 'peer-a', ['kem:x25519'])
    system.execute(tx)
    assert tx.status == REJECTED and 'Fresh' in tx.error
    assert not system.store.is_consumed(tx.authorization['digest'])


def test_policy_bounds_the_observation_freshness_limit(system, clock, signers):
    pv2 = default_policy(2)
    pv2.freshness_limit_s = 60
    system.registry.register(pv2)
    # New observations carry the tighter limit of the active policy ...
    tx = system.begin(ASSET)
    system.observe(tx)
    assert tx.observation['statement']['freshness_limit_s'] == 60
    clock.advance(61)
    system.propose(tx, HYBRID, READY_ENDPOINTS)
    system.evaluate(tx)
    assert tx.gate.failed() == ['Fresh']
    # ... and an observation cannot loosen it by declaring a larger limit.
    tx2 = system.begin(ASSET)
    system.observe(tx2)
    tx2.observation = resign(signers['source_observer'], tx2.observation,
                             lambda s: s.__setitem__('freshness_limit_s', 10**9))
    clock.advance(61)
    system.propose(tx2, HYBRID, READY_ENDPOINTS)
    system.evaluate(tx2)
    assert tx2.gate.failed() == ['Fresh']


def test_authorization_lifetime_is_bounded_by_policy(system, signers):
    orig = system.approver.decide
    system.approver.decide = lambda *a, **k: resign(signers['authorizer'], orig(*a, **k),
                                                    lambda s: s.__setitem__('expires_at', s['timestamp'] + 10**9))
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS)
    assert tx.status == REJECTED and 'Authorized' in tx.error
    assert failures_mention(verify(system), 'authorization.ttl')


def test_recovery_target_must_satisfy_security_floor(system):
    first = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS)      # previous profile is classical: isolate
    assert first.authorization['statement']['permitted_recovery'] == RECOVERY_ISOLATE
    second = system.run(ASSET, PQC, endpoints=READY_ENDPOINTS)        # previous profile meets the floor
    assert second.authorization['statement']['permitted_recovery'] == HYBRID
    # The approver refuses to sign a recovery target below the floor, so the archive stays valid.
    bad = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS, permitted_recovery=CLASSICAL)
    assert bad.status == REJECTED and bad.authorization['statement']['decision'] == 'denied'
    assert 'permitted recovery' in bad.error
    assert verify(system).ok
    # A key holder who signs such an authorization anyway is caught by the executor and the verifier.


# --- one-time consumption, reconciliation and failure paths ------------------
def test_replay_after_crash_before_apply_is_refused_by_one_time_consumption(store, clock, signers, tmp_path):
    system = make_system(store=store, clock=clock, signers=signers)
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS, fault='crash_before_apply')
    assert tx.status == FAILED and store.read_asset(ASSET)['state_version'] == 0
    store.close()
    store2 = ManagedStateStore(str(tmp_path / 'state.sqlite'))
    system2 = make_system(store=store2, clock=clock, signers=signers)
    # Every conjunct still holds (same version, fresh, unexpired): only durable one-time consumption refuses it.
    decision = system2.gate.evaluate_full(tx.observation, tx.proposal,
                                          system2.executor.current_state(ASSET), tx.authorization, system2.trust)
    assert decision.permitted
    with pytest.raises(AuthorizationAlreadyConsumed):
        system2.executor.execute(tx.observation, tx.proposal, tx.authorization)
    assert store2.read_asset(ASSET)['state_version'] == 0


def test_deferred_reconciliation_is_recorded_and_blocks_changes_until_resolved(system):
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS, fault='crash_after_apply', reconcile_on_crash=False)
    assert tx.status == UNRESOLVED and verify(system).ok             # the unresolved attempt is visible
    blocked = system.run(ASSET, PQC, endpoints=READY_ENDPOINTS)
    assert blocked.status == REJECTED
    assert any('pending reconciliation' in c.reason for c in blocked.gate.conjuncts)
    assert system.reconcile(tx) == RECOVERED
    system.close(tx)                                                  # resolution record for the same transaction
    assert system.run(ASSET, PQC, endpoints=READY_ENDPOINTS).status == CLOSED
    r = verify(system)
    assert r.ok, r.failures


def test_operation_failure_after_consumption_is_recorded_as_failed(system, monkeypatch):
    def broken():
        raise ValueError('KEM key agreement failed')
    monkeypatch.setattr(crypto, 'kem_roundtrip', broken)
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS)
    assert tx.status == FAILED and 'controlled operation failed' in tx.error
    assert system.store.read_asset(ASSET)['state_version'] == 0
    assert system.store.is_consumed(tx.authorization['digest'])
    assert system.store.journal_entries(tx.tx_id)[-1]['phase'] == 'failed'
    assert verify(system).ok


def test_observers_use_a_read_only_view(system):
    view = system.outcome_observer.view
    assert system.source.view is view
    assert not hasattr(view, 'apply') and not hasattr(view, 'ungoverned_change')
    with pytest.raises(sqlite3.OperationalError):
        view._conn.execute('UPDATE assets SET state_version = 99')


def test_floor_violating_recovery_signed_by_a_key_holder_is_refused_and_detected(system, signers):
    orig = system.approver.decide
    system.approver.decide = lambda *a, **k: resign(signers['authorizer'], orig(*a, **k),
                                                    lambda s: s.update(decision='authorized', permitted_recovery=CLASSICAL))
    system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS)                 # classical -> hybrid, recovery forged
    tx = system.records[-1]
    assert tx['status'] == REJECTED
    assert failures_mention(verify(system, collect_all=True), 'authorization.recovery')


def test_execution_is_bound_to_the_approved_observation(system):
    tx = system.begin(ASSET)
    system.observe(tx)
    system.propose(tx, HYBRID, READY_ENDPOINTS)
    system.evaluate(tx)
    system.authorize(tx)
    approved = tx.observation
    # A re-observation after a dependency change is signed and fresh, but it is not the observation approved.
    system.store.set_peer(ASSET, 'peer-legacy', [], 'unknown')
    system.observe(tx)
    system.execute(tx)
    assert tx.status == REJECTED and 'Authorized' in tx.error
    assert not system.store.is_consumed(tx.authorization['digest'])
    # A copy of the approved observation with a fresh capture time (signature no longer matches) is refused.
    system.clock.advance(system.registry.active.freshness_limit_s + 1)
    forged = {'statement': dict(approved['statement'], captured_at=system.clock.now()), 'digest': approved['digest'],
              'signature': approved['signature'], 'key_id': approved['key_id']}
    decision = system.gate.evaluate_full(forged, tx.proposal, system.executor.current_state(ASSET),
                                         tx.authorization, system.trust)
    assert not decision.permitted and 'Authorized' in decision.failed()


def test_authorization_expiring_before_the_apply_commit_is_not_applied(system, monkeypatch):
    tx = system.begin(ASSET)
    system.observe(tx)
    system.propose(tx, HYBRID, READY_ENDPOINTS)
    system.evaluate(tx)
    system.authorize(tx)
    real = crypto.kem_roundtrip

    def slow_operation():                              # the operation outlasts the authorization
        system.clock.advance(system.registry.active.approval_ttl_s + 1)
        return real()
    monkeypatch.setattr(crypto, 'kem_roundtrip', slow_operation)
    system.execute(tx)
    assert tx.status == FAILED and 'expired' in tx.error
    assert system.store.read_asset(ASSET)['state_version'] == 0
    assert system.store.journal_entries(tx.tx_id)[-1]['phase'] == 'failed'
    system.close(tx)
    assert verify(system, now=system.clock.now()).ok


def test_changed_policy_content_invalidates_an_approval_under_the_same_version(system):
    tx = system.begin(ASSET)
    system.observe(tx)
    system.propose(tx, HYBRID, READY_ENDPOINTS)
    system.evaluate(tx)
    system.authorize(tx)
    pv = default_policy(1)
    pv.approval_ttl_s = 60                              # same version number, different content
    system.registry.register(pv)
    system.execute(tx)
    assert tx.status == REJECTED and 'Authorized' in tx.error


def test_archive_with_a_drift_failed_transaction_verifies(system):
    tx = system.begin(ASSET)
    system.observe(tx)
    system.propose(tx, HYBRID, READY_ENDPOINTS)
    system.evaluate(tx)
    system.authorize(tx)
    system.execute(tx)
    system.store.ungoverned_change(ASSET, {'profile_id': 'manual', 'kem': 'X25519', 'cipher_label': 'x', 'protocol': 'TLS1.3'})
    system.observe_outcome(tx)
    system.close(tx)
    assert tx.status == FAILED
    r = verify(system)
    assert r.ok, r.failures
