"""Confidential predicate binding (Eq. 3-5) without a zero-knowledge backend."""

import copy
from dataclasses import replace

import pytest

from abd import crypto, predicate
from abd.fixture import ASSET, HYBRID, READY_ENDPOINTS
from conftest import resign


def _setup(system, signers, key_age=120, min_age=90, freshness=300, max_age=300):
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS)
    now = system.clock.now()
    pc = predicate.PolicyCommitment.create('rotation_threshold_v1', 1,
                                           {'min_key_age_days': min_age, 'permitted_profiles': [HYBRID]})
    reg = predicate.register_policy(signers['policy_authority'], pc, [ASSET], now - 10, now + 10_000, max_age)
    kappa = {'tx_id': tx.tx_id, 'asset_id': ASSET, 'state_version': 0, 'period': 'daily'}
    sc = predicate.source_commit(signers['source_observer'], kappa, {'key_age_days': key_age}, freshness, now)
    stmt, w = predicate.Prover(pc).statement(sc, tx.proposal)
    return tx, pc, reg, sc, stmt, w


def _verify(system, tx, reg, sc, stmt, w=None, now=None, authorization=None):
    return predicate.verify_bound_statement(stmt, reg, sc.attestation, authorization or tx.authorization,
                                            system.trust, system.clock.now() if now is None else now, opening=w)


def test_relation_holds_and_bindings_verify(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers)
    assert stmt.q_i is True
    assert predicate.relation_holds(stmt, w)
    ok, why = _verify(system, tx, reg, sc, stmt, w)
    assert ok, why


def test_bindings_alone_do_not_accept(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers)
    ok, why = _verify(system, tx, reg, sc, stmt)
    assert not ok and 'no proof or opening' in why


def test_forged_result_without_proof_rejected(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers, key_age=10)
    stmt.q_i = True
    ok, why = _verify(system, tx, reg, sc, stmt)
    assert not ok and 'no proof or opening' in why


def test_false_predicate_result_is_recorded_not_hidden(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers, key_age=10)
    assert stmt.q_i is False and predicate.relation_holds(stmt, w)


def test_tampered_result_fails_relation(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers, key_age=10)
    stmt.q_i = True
    assert not predicate.relation_holds(stmt, w)
    ok, why = _verify(system, tx, reg, sc, stmt, w)
    assert not ok and 'relation R' in why


def test_wrong_policy_opening_fails(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers)
    w2 = copy.deepcopy(w)
    w2.theta['min_key_age_days'] = 1
    assert not predicate.relation_holds(stmt, w2)


def test_unregistered_commitment_rejected(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers)
    other = predicate.PolicyCommitment.create('rotation_threshold_v1', 1, pc.theta)  # prover-chosen commitment
    stmt.C_v = other.C_v
    ok, why = _verify(system, tx, reg, sc, stmt, replace(w, r=other.r))
    assert not ok and 'registration' in why


def test_registration_by_untrusted_authority_rejected(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers)
    rogue = crypto.RoleSigner('policy_authority', key_id='rogue')
    ok, why = _verify(system, tx, resign(rogue, reg), sc, stmt, w)
    assert not ok and 'registration' in why


def test_statement_not_bound_to_authorized_action_rejected(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers)
    other = copy.deepcopy(tx.proposal)
    other['target_config']['kem'] = 'ML-KEM-1024'
    stmt.D_i = crypto.action_digest_hex(other)
    ok, why = _verify(system, tx, reg, sc, stmt, replace(w, a=other))
    assert not ok and 'authorized action' in why


def test_unsigned_authorization_rejected(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers)
    other = copy.deepcopy(tx.proposal)
    other['target_config']['kem'] = 'X25519'
    stmt.D_i = crypto.action_digest_hex(other)
    forged = copy.deepcopy(tx.authorization)
    forged['statement']['target_config_digest'] = stmt.D_i
    for auth in ({'tx_id': tx.tx_id, 'target_config_digest': stmt.D_i}, forged):
        ok, why = _verify(system, tx, reg, sc, stmt, replace(w, a=other), authorization=auth)
        assert not ok and why.startswith('authorization:'), why


def test_authorization_by_untrusted_authorizer_rejected(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers)
    rogue = crypto.RoleSigner('authorizer', key_id='rogue')
    ok, why = _verify(system, tx, reg, sc, stmt, w, authorization=resign(rogue, tx.authorization))
    assert not ok and why.startswith('authorization:'), why


@pytest.mark.parametrize('field, value, reason', [
    ('decision', 'denied', 'decision'),
    ('schema', 'authorization_v1', 'schema'),
])
def test_authorization_must_be_an_authorized_v2_decision(system, signers, field, value, reason):
    tx, pc, reg, sc, stmt, w = _setup(system, signers)
    auth = resign(signers['authorizer'], tx.authorization, lambda s: s.__setitem__(field, value))
    ok, why = _verify(system, tx, reg, sc, stmt, w, authorization=auth)
    assert not ok and reason in why, why


def test_stale_source_measurement_rejected(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers)
    ok, why = _verify(system, tx, reg, sc, stmt, w, now=system.clock.now() + 301)
    assert not ok and 'stale' in why


def test_registration_caps_source_freshness_limit(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers, freshness=10**9, max_age=300)
    ok, why = _verify(system, tx, reg, sc, stmt, w, now=system.clock.now() + 299)
    assert ok, why
    ok, why = _verify(system, tx, reg, sc, stmt, w, now=system.clock.now() + 9999)
    assert not ok and 'stale' in why


def test_registration_without_measurement_age_cap_rejected(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers)
    reg2 = resign(signers['policy_authority'], reg, lambda s: s.pop('max_measurement_age_s'))
    ok, why = _verify(system, tx, reg2, sc, stmt, w)
    assert not ok and 'maximum measurement age' in why


def test_prover_supplied_commitment_not_attested_by_source(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers)
    r_i = predicate.fresh_randomness()
    stmt.X_i = predicate.commit(crypto.encode({'kappa': stmt.kappa, 'x': w.x}), r_i)
    ok, why = _verify(system, tx, reg, sc, stmt, replace(w, r_i=r_i))
    assert not ok and 'X_i' in why


@pytest.mark.parametrize('theta, x, action', [
    ({'min_key_age_days': 1, 'permitted_profiles': 'x-' + HYBRID + '-y'}, {'key_age_days': 5},
     {'target_profile_id': HYBRID}),                                           # substring test, not membership
    ({'min_key_age_days': 1, 'permitted_profiles': [HYBRID]}, {'key_age_days': True}, {'target_profile_id': HYBRID}),
    ({'min_key_age_days': True, 'permitted_profiles': [HYBRID]}, {'key_age_days': 5}, {'target_profile_id': HYBRID}),
    ({'min_key_age_days': 1, 'permitted_profiles': [HYBRID]}, {'key_age_days': '5'}, {'target_profile_id': HYBRID}),
    ({'min_key_age_days': 1, 'permitted_profiles': [HYBRID]}, {'key_age_days': 5}, {'target_profile_id': 7}),
    ({'min_key_age_days': 1, 'permitted_profiles': [HYBRID]}, {}, {'target_profile_id': HYBRID}),
    ({'min_key_age_days': 1, 'permitted_profiles': [HYBRID]}, [5], {'target_profile_id': HYBRID}),
])
def test_predicate_types_are_as_strict_as_the_guest(theta, x, action):
    with pytest.raises(ValueError):
        predicate.evaluate('rotation_threshold_v1', theta, x, action)


def test_predicate_ignores_non_string_profiles_like_the_guest():
    x, a = {'key_age_days': 5}, {'target_profile_id': HYBRID}
    assert predicate.evaluate('rotation_threshold_v1', {'min_key_age_days': 1, 'permitted_profiles': [5, None, HYBRID]}, x, a)
    assert not predicate.evaluate('rotation_threshold_v1', {'min_key_age_days': 1, 'permitted_profiles': [[HYBRID]]}, x, a)
    with pytest.raises(ValueError):
        predicate.evaluate('no_such_predicate', {}, x, a)


def test_off_schema_opening_does_not_satisfy_relation(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers)
    bad = predicate.PolicyCommitment.create('rotation_threshold_v1', 1,
                                            {'min_key_age_days': True, 'permitted_profiles': [HYBRID]})
    with pytest.raises(ValueError):
        predicate.Prover(bad).statement(sc, tx.proposal)
    stmt2, w2 = replace(stmt, C_v=bad.C_v), replace(w, theta=bad.theta, r=bad.r)
    assert not predicate.relation_holds(stmt2, w2)
    assert not predicate.relation_holds(replace(stmt2, q_i=not stmt2.q_i), w2)


def test_backend_strips_dev_mode_and_external_prover_variables(tmp_path, monkeypatch):
    host = tmp_path / 'fake-host'
    host.write_text('#!/usr/bin/env python3\nimport json, os\n'
                    'print(json.dumps({"env": sorted(k for k in os.environ if k.startswith("RISC0_"))}))\n')
    host.chmod(0o755)
    for k, v in {'RISC0_DEV_MODE': '1', 'RISC0_PROVER': 'ipc', 'RISC0_SERVER_PATH': '/x/r0vm',
                 'RISC0_INFO': '1'}.items():
        monkeypatch.setenv(k, v)
    assert predicate.RiscZeroBackend(host=str(host))._run('image-id') == {'env': ['RISC0_INFO']}


def test_zk_backend_is_explicitly_unimplemented(system, signers):
    tx, pc, reg, sc, stmt, w = _setup(system, signers)
    with pytest.raises(NotImplementedError):
        predicate.ZKBackend().prove(stmt, w)
