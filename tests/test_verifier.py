"""Evidence verification tests: signature/digest checks, chain and checkpoint
checks, and semantic rejection of correctly signed but inconsistent evidence."""

import copy
import json

from abd import crypto
from abd.fixture import ASSET, HYBRID, PQC, READY_ENDPOINTS, make_system
from abd.policy import Conjunct
from abd.transaction import CLOSED, JsonlArchiveWriter
from abd.verify import verify_jsonl
from conftest import failures_mention, resign, verify


def _two(system):
    assert system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS).status == CLOSED
    assert system.run(ASSET, PQC, endpoints=READY_ENDPOINTS).status == CLOSED
    return copy.deepcopy(system.records)


def test_valid_archive_accepted(system):
    _two(system)
    r = verify(system)
    assert r.ok and r.records == 2 and r.closed == 2


def test_altered_signature_rejected(system):
    recs = _two(system)
    sig = recs[0]['executor']['signature']
    recs[0]['executor']['signature'] = ('0' if sig[0] != '0' else '1') + sig[1:]
    r = verify(system, recs)
    assert not r.ok and failures_mention(r, 'executor.signature')


def test_wrong_signing_role_rejected(system, signers):
    recs = _two(system)
    # Executor key signs a source observation (valid signature, wrong role key).
    stmt = copy.deepcopy(recs[0]['source']['statement'])
    stmt_bytes = crypto.encode(stmt)
    recs[0]['source']['signature'] = signers['executor'].sign_bytes(stmt_bytes)
    recs[0]['source']['key_id'] = signers['executor'].key_id
    r = verify(system, recs)
    assert not r.ok and failures_mention(r, 'source.signature')


def test_modified_statement_rejected(system):
    recs = _two(system)
    recs[1]['outcome']['statement']['observed_profile_id'] = HYBRID
    r = verify(system, recs)
    assert not r.ok and failures_mention(r, 'outcome.signature')


def test_truncated_archive_rejected_by_retained_checkpoint(system):
    recs = _two(system)
    r = verify(system, recs[:1])
    assert not r.ok and failures_mention(r, 'checkpoint.retained.sequence')


def test_reordered_archive_rejected(system):
    recs = _two(system)
    r = verify(system, [recs[1], recs[0]])
    assert not r.ok and failures_mention(r, 'envelope.index')


def test_mismatched_checkpoint_head_rejected(system, signers):
    _two(system)
    cp = resign(signers['checkpoint_witness'], system.retained_checkpoint(),
                lambda s: s.__setitem__('witnessed_head', 'f' * 96))
    r = verify(system, checkpoint=cp)
    assert not r.ok and failures_mention(r, 'checkpoint.retained.head')


def test_stale_checkpoint_rejected(system):
    _two(system)
    r = verify(system, now=system.clock.now() + 601, delta_s=600)
    assert not r.ok and failures_mention(r, 'checkpoint.retained.timeliness')


def test_checkpoint_from_another_log_rejected(system, signers):
    _two(system)
    cp = resign(signers['checkpoint_witness'], system.retained_checkpoint(),
                lambda s: s.__setitem__('log_id', 'audit-log-002'))
    r = verify(system, checkpoint=cp)
    assert not r.ok and failures_mention(r, 'checkpoint.retained.log_id')


def test_missing_retained_checkpoint_rejected_even_if_archive_carries_one(system):
    _two(system)
    r = verify(system, checkpoint=None)
    assert not r.ok and failures_mention(r, 'checkpoint.retained')


def test_replacement_checkpoint_from_untrusted_witness_rejected(system):
    _two(system)
    rogue = crypto.RoleSigner('checkpoint_witness', key_id='rogue-witness')
    cp = resign(rogue, system.retained_checkpoint())
    r = verify(system, checkpoint=cp)
    assert not r.ok and failures_mention(r, 'checkpoint.retained.signature')


def test_key_validity_period_enforced(system, signers):
    _two(system)
    t = system.records[0]['executor']['statement']['timestamp']
    trust = crypto.TrustConfig.from_signers(signers, valid_from=0, valid_to=t - 1)
    r = verify(system, trust=trust)
    assert not r.ok and failures_mention(r, 'signature')


def test_outer_tx_id_must_equal_signed_tx_id(system):
    recs = _two(system)
    recs[0]['tx_id'] = recs[0]['tx_id'][:-4] + 'dead'
    r = verify(system, recs)
    assert not r.ok and failures_mention(r, '.tx_id')


def test_inconsistent_outcome_with_valid_signature_rejected(system, signers):
    """Outcome observer key compromised: signs an observation of the wrong profile."""
    recs = _two(system)
    rec = recs[1]
    def mutate(s):
        s['observed_profile_id'] = HYBRID
        s['observed']['config']['profile_id'] = HYBRID
        s['observed_config_digest'] = crypto.snapshot_digest_hex(s['observed']['config'])
    rec['outcome'] = resign(signers['outcome_observer'], rec['outcome'], mutate)
    # Evidence service also compromised: re-issue the envelope so digests match.
    rec = _reissue_envelope(system, signers, rec, index=1, prev=recs[0]['chain_hash'])
    recs[1] = rec
    r = verify(system, recs, checkpoint=_cp(signers, system.log_id, 1, rec['chain_hash'], system.clock.now()))
    assert not r.ok and failures_mention(r, 'outcome.profile_matches_authorized')


def test_receipt_inconsistent_with_outcome_rejected(system, signers):
    recs = _two(system)
    rec = recs[1]
    rec['executor'] = resign(signers['executor'], rec['executor'],
                             lambda s: s.__setitem__('applied_config_digest', 'a' * 96))
    rec['outcome'] = resign(signers['outcome_observer'], rec['outcome'],
                            lambda s: s.__setitem__('receipt_digest', rec['executor']['digest']))
    rec = _reissue_envelope(system, signers, rec, index=1, prev=recs[0]['chain_hash'])
    recs[1] = rec
    r = verify(system, recs, checkpoint=_cp(signers, system.log_id, 1, rec['chain_hash'], system.clock.now()))
    assert not r.ok and failures_mention(r, 'executor.applied_config')


def test_duplicate_completed_transaction_in_newly_signed_chain_rejected(system, signers):
    recs = _two(system)
    dup = copy.deepcopy(recs[1])
    dup = _reissue_envelope(system, signers, dup, index=2, prev=recs[1]['chain_hash'])
    recs.append(dup)
    r = verify(system, recs, checkpoint=_cp(signers, system.log_id, 2, dup['chain_hash'], system.clock.now()),
               collect_all=True)
    assert not r.ok
    assert failures_mention(r, 'record.unique_tx')
    assert failures_mention(r, 'authorization.single_use')
    assert failures_mention(r, 'executor.continuity')


def test_replayed_transaction_under_fresh_id_rejected_by_continuity(system, signers):
    """Same signed receipt re-used under a new outer id and new envelope: version continuity breaks."""
    recs = _two(system)
    dup = copy.deepcopy(recs[1])
    new_id = dup['tx_id'][:-4] + 'beef'
    dup['tx_id'] = new_id
    # Attacker re-signs every statement with the new id (all role keys compromised).
    for section, role in (('source', 'source_observer'), ('authorization', 'authorizer'),
                          ('executor', 'executor'), ('outcome', 'outcome_observer')):
        dup[section] = resign(signers[role], dup[section], lambda s: s.__setitem__('tx_id', new_id))
    dup['proposal']['tx_id'] = new_id
    dup = _reissue_envelope(system, signers, dup, index=2, prev=recs[1]['chain_hash'])
    recs.append(dup)
    r = verify(system, recs, checkpoint=_cp(signers, system.log_id, 2, dup['chain_hash'], system.clock.now()),
               collect_all=True)
    assert not r.ok and failures_mention(r, 'executor.continuity')


def test_state_version_continuity_break_rejected(system, signers):
    recs = _two(system)
    rec = recs[1]
    def mutate(s):
        s['state_version_before'] = 5
        s['state_version_after'] = 6
    rec['executor'] = resign(signers['executor'], rec['executor'], mutate)
    rec['authorization'] = resign(signers['authorizer'], rec['authorization'],
                                  lambda s: s.__setitem__('expected_state_version', 5))
    rec['outcome'] = resign(signers['outcome_observer'], rec['outcome'],
                            lambda s: (s.__setitem__('receipt_digest', rec['executor']['digest']),
                                       s['observed'].__setitem__('state_version', 6)))
    rec = _reissue_envelope(system, signers, rec, index=1, prev=recs[0]['chain_hash'])
    recs[1] = rec
    r = verify(system, recs, checkpoint=_cp(signers, system.log_id, 1, rec['chain_hash'], system.clock.now()),
               collect_all=True)
    assert not r.ok and failures_mention(r, 'executor.continuity')


def test_rejected_record_with_receipt_rejected(system, signers):
    recs = _two(system)
    denied = system.run(ASSET, PQC, endpoints=['peer-legacy'])
    recs = copy.deepcopy(system.records)
    rec = recs[2]
    rec['executor'] = recs[1]['executor']
    rec = _reissue_envelope(system, signers, rec, index=2, prev=recs[1]['chain_hash'])
    recs[2] = rec
    r = verify(system, recs, checkpoint=_cp(signers, system.log_id, 2, rec['chain_hash'], system.clock.now()),
               collect_all=True)
    assert not r.ok and failures_mention(r, 'status.rejected_has_no_receipt')


def test_authorization_below_allowlist_rejected_even_if_signed(system, signers):
    """Authorizer key compromised: authorizes a profile that is not on the allowlist."""
    recs = _two(system)
    rec = recs[1]
    rec['proposal']['target_profile_id'] = 'tls13-frodokem'
    pd = crypto.action_digest_hex(rec['proposal'])
    rec['authorization'] = resign(signers['authorizer'], rec['authorization'],
                                  lambda s: (s.__setitem__('target_config_digest', pd),
                                             s.__setitem__('target_profile_id', 'tls13-frodokem')))
    rec['executor'] = resign(signers['executor'], rec['executor'],
                             lambda s: (s.__setitem__('proposal_digest', pd),
                                        s.__setitem__('authorization_digest', rec['authorization']['digest'])))
    rec['outcome'] = resign(signers['outcome_observer'], rec['outcome'],
                            lambda s: s.__setitem__('receipt_digest', rec['executor']['digest']))
    rec = _reissue_envelope(system, signers, rec, index=1, prev=recs[0]['chain_hash'])
    recs[1] = rec
    r = verify(system, recs, checkpoint=_cp(signers, system.log_id, 1, rec['chain_hash'], system.clock.now()),
               collect_all=True)
    assert not r.ok and failures_mention(r, 'authorization.allowed')


def test_stale_observation_at_authorization_rejected(system, signers):
    recs = _two(system)
    rec = recs[1]
    rec['authorization'] = resign(signers['authorizer'], rec['authorization'],
                                  lambda s: s.__setitem__('timestamp', s['timestamp'] + 10_000))
    rec['executor'] = resign(signers['executor'], rec['executor'],
                             lambda s: s.__setitem__('authorization_digest', rec['authorization']['digest']))
    rec['outcome'] = resign(signers['outcome_observer'], rec['outcome'],
                            lambda s: s.__setitem__('receipt_digest', rec['executor']['digest']))
    rec = _reissue_envelope(system, signers, rec, index=1, prev=recs[0]['chain_hash'])
    recs[1] = rec
    r = verify(system, recs, checkpoint=_cp(signers, system.log_id, 1, rec['chain_hash'], system.clock.now()),
               collect_all=True)
    assert not r.ok and failures_mention(r, 'authorization.freshness')


def test_malformed_record_is_rejected_not_crashed(system):
    recs = _two(system)
    del recs[0]['source']
    r = verify(system, recs)
    assert not r.ok and r.failures


def test_streaming_jsonl_verifier_matches_in_memory(tmp_path, clock, signers, store):
    path = str(tmp_path / 'archive.jsonl')
    writer = JsonlArchiveWriter(path)
    system = make_system(store=store, clock=clock, signers=signers, sink=writer)
    for _ in range(3):
        system.run(ASSET, HYBRID if system.store.read_asset(ASSET)['state_version'] == 0 else PQC,
                   endpoints=READY_ENDPOINTS)
    system.run(ASSET, PQC, endpoints=['peer-legacy'])
    writer.close()
    assert writer.count == 4
    r = verify_jsonl(path, trust=system.trust, registry=system.registry, log_id=system.log_id,
                     retained_checkpoint=system.retained_checkpoint(), now=clock.now(), delta_s=600)
    assert r.ok, r.failures
    assert r.records == 4 and r.rejected == 1
    # Trust material is a separate artifact and round-trips through JSON.
    tc = crypto.TrustConfig.from_json(json.loads(json.dumps(system.trust.to_json())))
    assert verify_jsonl(path, trust=tc, registry=system.registry, log_id=system.log_id,
                        retained_checkpoint=system.retained_checkpoint(), now=clock.now(), delta_s=600).ok


# --- helpers ---------------------------------------------------------------
def _reissue_envelope(system, signers, rec, index, prev):
    """Compromised evidence service: sign a fresh envelope binding the (tampered) sections."""
    stmt = copy.deepcopy(rec['envelope']['statement'])
    stmt['index'] = index
    stmt['chain_prev'] = prev
    stmt['tx_id'] = rec['tx_id']
    stmt['source_digest'] = rec['source']['digest'] if rec.get('source') else None
    stmt['proposal_digest'] = crypto.action_digest_hex(rec['proposal'])
    stmt['authorization_digest'] = rec['authorization']['digest']
    stmt['executor_digest'] = rec['executor']['digest'] if rec.get('executor') else None
    stmt['outcome_digest'] = rec['outcome']['digest'] if rec.get('outcome') else None
    stmt['status'] = rec['status']
    rec['envelope'] = signers['evidence_service'].sign_statement(stmt)
    rec['chain_hash'] = crypto.chain_hash_hex(index, prev, stmt)
    rec['checkpoint'] = _cp(signers, system.log_id, index, rec['chain_hash'], system.clock.now())
    return rec


def _cp(signers, log_id, seq, head, now):
    return signers['checkpoint_witness'].sign_statement({
        'schema': 'checkpoint_v2', 'role': 'checkpoint_witness', 'witness_id': signers['checkpoint_witness'].key_id,
        'log_id': log_id, 'sequence': seq, 'witnessed_head': head, 'witness_time': now})


# --- key validity, recomputed Compatible, and remaining Table VI rejection paths ---
def test_expired_evidence_service_key_rejected(system, signers):
    _two(system)
    trust = crypto.TrustConfig()
    for role, s in signers.items():
        trust.add(s.public_entry(valid_to=1000 if role == 'evidence_service' else None))
    r = verify(system, trust=trust)
    assert not r.ok and failures_mention(r, 'envelope.signature')


def test_incompatible_endpoint_rejected_even_if_signed_gate_record_claims_success(system):
    """Compromised policy evaluator: the signed gate record says Compatible, the signed snapshot says otherwise."""
    system.gate.check_compatible = lambda proposal, obs, policy: Conjunct('Compatible', True, 'forced')
    assert system.run(ASSET, HYBRID, endpoints=['peer-legacy']).status == CLOSED
    r = verify(system)
    assert not r.ok and failures_mention(r, 'authorization.compatible')


def test_substituted_proposal_rejected_by_proposal_binding(system, signers):
    """Evidence service compromised: the archive carries a proposal other than the one authorized and executed."""
    recs = _two(system)
    rec = recs[1]
    rec['proposal']['endpoints'] = ['peer-a']
    rec = _reissue_envelope(system, signers, rec, index=1, prev=recs[0]['chain_hash'])
    recs[1] = rec
    r = verify(system, recs, checkpoint=_cp(signers, system.log_id, 1, rec['chain_hash'], system.clock.now()),
               collect_all=True)
    assert not r.ok
    assert failures_mention(r, 'authorization.binds_proposal') and failures_mention(r, 'executor.binds_proposal')


def test_authorization_with_wrong_policy_digest_rejected(system, signers):
    recs = _two(system)
    rec = recs[1]
    rec['authorization'] = resign(signers['authorizer'], rec['authorization'],
                                  lambda s: s.__setitem__('policy_digest', 'b' * 96))
    rec['executor'] = resign(signers['executor'], rec['executor'],
                             lambda s: s.__setitem__('authorization_digest', rec['authorization']['digest']))
    rec['outcome'] = resign(signers['outcome_observer'], rec['outcome'],
                            lambda s: s.__setitem__('receipt_digest', rec['executor']['digest']))
    rec = _reissue_envelope(system, signers, rec, index=1, prev=recs[0]['chain_hash'])
    recs[1] = rec
    r = verify(system, recs, checkpoint=_cp(signers, system.log_id, 1, rec['chain_hash'], system.clock.now()))
    assert not r.ok and failures_mention(r, 'authorization.policy_digest')


def test_receipt_before_version_must_equal_authorized_version(system, signers):
    recs = _two(system)
    rec = recs[1]
    def mutate(s):
        s['state_version_before'], s['state_version_after'] = 7, 8
    rec['executor'] = resign(signers['executor'], rec['executor'], mutate)
    rec['outcome'] = resign(signers['outcome_observer'], rec['outcome'],
                            lambda s: s.__setitem__('receipt_digest', rec['executor']['digest']))
    rec = _reissue_envelope(system, signers, rec, index=1, prev=recs[0]['chain_hash'])
    recs[1] = rec
    r = verify(system, recs, checkpoint=_cp(signers, system.log_id, 1, rec['chain_hash'], system.clock.now()),
               collect_all=True)
    assert not r.ok and failures_mention(r, 'executor.version_bound')


def test_outcome_configuration_must_match_receipt(system, signers):
    recs = _two(system)
    rec = recs[1]
    def mutate(s):
        s['observed']['config']['cipher_label'] = 'TLS_AES_128_GCM_SHA256+MLKEM768'
        s['observed_config_digest'] = crypto.snapshot_digest_hex(s['observed']['config'])
    rec['outcome'] = resign(signers['outcome_observer'], rec['outcome'], mutate)
    rec = _reissue_envelope(system, signers, rec, index=1, prev=recs[0]['chain_hash'])
    recs[1] = rec
    r = verify(system, recs, checkpoint=_cp(signers, system.log_id, 1, rec['chain_hash'], system.clock.now()))
    assert not r.ok and failures_mention(r, 'outcome.matches_receipt')


def test_unknown_status_rejected(system, signers):
    recs = _two(system)
    rec = recs[1]
    rec['status'] = 'approved'
    rec = _reissue_envelope(system, signers, rec, index=1, prev=recs[0]['chain_hash'])
    recs[1] = rec
    r = verify(system, recs, checkpoint=_cp(signers, system.log_id, 1, rec['chain_hash'], system.clock.now()))
    assert not r.ok and failures_mention(r, 'record.status')


# --- rejection paths added after the adversarial review ---------------------------------
from abd.fixture import CLASSICAL  # noqa: E402
from abd.policy import default_policy  # noqa: E402


def _retarget_last(system, signers, recs, mutate_proposal=None, mutate_auth=None, mutate_receipt=None,
                   mutate_outcome=None, mutate_envelope=None):
    """Key-holder tampering of the last record: re-sign every section so that all digests still bind."""
    rec = recs[-1]
    if mutate_proposal:
        mutate_proposal(rec['proposal'])
    pdig = crypto.action_digest_hex(rec['proposal'])

    def auth_m(s):
        s['target_config_digest'] = pdig
        if mutate_auth:
            mutate_auth(s)
    rec['authorization'] = resign(signers['authorizer'], rec['authorization'], auth_m)
    if rec.get('executor'):
        def rc_m(s):
            s['authorization_digest'] = rec['authorization']['digest']
            s['proposal_digest'] = pdig
            s['applied_config_digest'] = crypto.snapshot_digest_hex(rec['proposal']['target_config'])
            if mutate_receipt:
                mutate_receipt(s)
        rec['executor'] = resign(signers['executor'], rec['executor'], rc_m)
    if rec.get('outcome'):
        def oc_m(s):
            s['receipt_digest'] = rec['executor']['digest']
            if mutate_outcome:
                mutate_outcome(s)
        rec['outcome'] = resign(signers['outcome_observer'], rec['outcome'], oc_m)
    index = len(recs) - 1
    prev = recs[-2]['chain_hash'] if len(recs) > 1 else crypto.GENESIS_HEAD
    rec = _reissue_envelope(system, signers, rec, index=index, prev=prev)
    if mutate_envelope:
        stmt = copy.deepcopy(rec['envelope']['statement'])
        mutate_envelope(stmt)
        rec['envelope'] = signers['evidence_service'].sign_statement(stmt)
        rec['chain_hash'] = crypto.chain_hash_hex(index, prev, stmt)
        rec['checkpoint'] = _cp(signers, system.log_id, index, rec['chain_hash'], system.clock.now())
    recs[-1] = rec
    return verify(system, recs, checkpoint=_cp(signers, system.log_id, index, rec['chain_hash'], system.clock.now()),
                  collect_all=True)


def test_unpermitted_action_rejected_even_if_signed(system, signers):
    r = _retarget_last(system, signers, _two(system), mutate_proposal=lambda p: p.__setitem__('action', 'disable_pq_kex'))
    assert failures_mention(r, 'authorization.action')


def test_proposal_citing_another_policy_version_rejected(system, signers):
    r = _retarget_last(system, signers, _two(system), mutate_proposal=lambda p: p.__setitem__('policy_version', 99))
    assert failures_mention(r, 'authorization.proposal_policy_version')


def test_inexact_configuration_rejected_even_if_signed(system, signers):
    r = _retarget_last(system, signers, _two(system), mutate_proposal=lambda p: p['target_config'].__setitem__('kem', 'X25519'))
    assert failures_mention(r, 'authorization.exact_config')


def test_profile_below_floor_rejected_even_if_signed(system, signers):
    classical = default_policy().allowlist[CLASSICAL].target_config()

    def to_classical(p):
        p['target_profile_id'], p['target_config'] = CLASSICAL, classical
    r = _retarget_last(system, signers, _two(system), mutate_proposal=to_classical,
                       mutate_auth=lambda s: s.__setitem__('target_profile_id', CLASSICAL))
    assert failures_mention(r, 'authorization.security_floor')


def test_apply_after_expiry_rejected(system, signers):
    r = _retarget_last(system, signers, _two(system),
                       mutate_receipt=lambda s: s.update(applied_at=s['timestamp'] + 10**6, timestamp=s['timestamp'] + 10**6))
    assert failures_mention(r, 'executor.before_expiry')


def test_apply_before_authorization_rejected(system, signers):
    r = _retarget_last(system, signers, _two(system), mutate_receipt=lambda s: s.__setitem__('applied_at', s['applied_at'] - 5))
    assert failures_mention(r, 'executor.after_authorization')


def test_failed_health_checks_rejected_for_a_closed_transaction(system, signers):
    r = _retarget_last(system, signers, _two(system),
                       mutate_outcome=lambda s: s['health_checks'].__setitem__('config_matches_profile', False))
    assert failures_mention(r, 'outcome.health')


def test_observation_preceding_the_receipt_rejected(system, signers):
    r = _retarget_last(system, signers, _two(system), mutate_outcome=lambda s: s.__setitem__('observed_at', s['observed_at'] - 5))
    assert failures_mention(r, 'outcome.after_receipt')


def test_decreasing_envelope_time_rejected(system, signers):
    r = _retarget_last(system, signers, _two(system), mutate_envelope=lambda s: s.__setitem__('timestamp', s['timestamp'] - 5))
    assert failures_mention(r, 'envelope.time_monotonic')


def test_statement_without_time_rejected(system, signers):
    r = _retarget_last(system, signers, _two(system), mutate_envelope=lambda s: s.pop('timestamp'))
    # 'envelope.time:' (with the separator) so that the monotonic check 'envelope.time_monotonic' does not satisfy it
    assert failures_mention(r, 'envelope.time:')
    assert failures_mention(r, 'envelope.signature')        # no time: key validity cannot hold, fails closed


def test_stripping_signed_sections_from_a_failed_record_rejected(system):
    tx = system.begin(ASSET)
    system.observe(tx)
    system.propose(tx, HYBRID, READY_ENDPOINTS)
    system.evaluate(tx)
    system.authorize(tx)
    system.execute(tx)
    system.store.ungoverned_change(ASSET, {'profile_id': 'manual', 'kem': 'X25519', 'cipher_label': 'x', 'protocol': 'TLS1.3'})
    system.observe_outcome(tx)
    system.close(tx)
    recs = copy.deepcopy(system.records)
    assert recs[0]['status'] == 'failed' and verify(system, recs).ok
    recs[0]['executor'] = recs[0]['outcome'] = None                # no key needed to delete sections
    r = verify(system, recs, collect_all=True)
    assert failures_mention(r, 'envelope.binds_executor') and failures_mention(r, 'envelope.binds_outcome')


def _deferred(system):
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS, fault='crash_after_apply', reconcile_on_crash=False)
    system.reconcile(tx)
    system.close(tx)
    recs = copy.deepcopy(system.records)
    assert [r['status'] for r in recs] == ['unresolved', 'recovered'] and verify(system, recs).ok
    return recs


def test_second_resolution_record_rejected(system, signers):
    recs = _deferred(system)
    extra = _reissue_envelope(system, signers, copy.deepcopy(recs[1]), index=2, prev=recs[1]['chain_hash'])
    recs.append(extra)
    r = verify(system, recs, checkpoint=_cp(signers, system.log_id, 2, extra['chain_hash'], system.clock.now()),
               collect_all=True)
    assert failures_mention(r, 'record.unique_tx')


def test_resolution_with_a_non_resolution_status_rejected(system, signers):
    recs = _deferred(system)
    recs[1]['status'] = 'closed'
    recs[1] = _reissue_envelope(system, signers, recs[1], index=1, prev=recs[0]['chain_hash'])
    r = verify(system, recs, checkpoint=_cp(signers, system.log_id, 1, recs[1]['chain_hash'], system.clock.now()),
               collect_all=True)
    assert failures_mention(r, 'record.resolution_status')


def test_resolution_carrying_a_different_authorization_rejected(system, signers):
    recs = _deferred(system)
    r = _retarget_last(system, signers, recs, mutate_auth=lambda s: s.__setitem__('test_evidence_refs', ['forged']))
    assert failures_mention(r, 'record.resolution_binding')
