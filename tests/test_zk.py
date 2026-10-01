"""Zero-knowledge argument of relation R (Eq. 5) with RISC Zero.

Requires zk/ to be built (cd zk && cargo build --release).  Executing the guest
without a proof takes well under a second, so those tests run whenever the host
is built.  Proving is opt-in (ABD_ZK=1) because each proof takes minutes on a
CPU; one succinct receipt is produced for the module and reused by every test.
"""

import os
import sys
from dataclasses import replace

import pytest

from abd import crypto, predicate
from abd.fixture import ASSET, HYBRID, READY_ENDPOINTS, make_system

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bench'))
import bench_zk as B  # noqa: E402

ZK = predicate.RiscZeroBackend()
needs_host = pytest.mark.skipif(not ZK.available(), reason='build zk/ first (cd zk && cargo build --release)')
needs_proof = pytest.mark.skipif(not (ZK.available() and os.environ.get('ABD_ZK') == '1'),
                                 reason='set ABD_ZK=1 after building zk/ (proving takes minutes)')


@pytest.fixture(scope='module')
def proven():
    system = make_system()
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS)
    now = system.clock.now()
    pc = predicate.PolicyCommitment.create('rotation_threshold_v1', 1,
                                           {'min_key_age_days': 90, 'permitted_profiles': [HYBRID]})
    program_id = ZK.program_id()
    reg = predicate.register_policy(system.signers['policy_authority'], pc, [ASSET], now - 10, now + 10_000, 300,
                                    program_id=program_id)
    kappa = {'tx_id': tx.tx_id, 'asset_id': ASSET, 'state_version': 0, 'period': 'daily'}
    sc = predicate.source_commit(system.signers['source_observer'], kappa, {'key_age_days': 120}, 300, now)
    stmt, w = predicate.Prover(pc).statement(sc, tx.proposal)
    proof = ZK.prove(stmt, w)
    return system, tx, pc, reg, sc, stmt, w, proof, program_id


@needs_host
@pytest.mark.parametrize('name', sorted(B.encoding_vectors()))
def test_guest_journal_is_the_canonical_statement(name):
    stmt, w = B.encoding_vectors()[name]
    res = ZK.execute(stmt, w)
    assert res['exit_code'] == 'Halted(0)'
    assert bytes.fromhex(res['journal_hex']) == crypto.encode(stmt.to_json())


@needs_host
@pytest.mark.parametrize('theta, x, action', [
    ({'min_key_age_days': 90, 'permitted_profiles': [HYBRID]}, {'key_age_days': True}, {'target_profile_id': HYBRID}),
    ({'min_key_age_days': False, 'permitted_profiles': [HYBRID]}, {'key_age_days': 120}, {'target_profile_id': HYBRID}),
    ({'min_key_age_days': 90, 'permitted_profiles': 'x-' + HYBRID + '-y'}, {'key_age_days': 120},
     {'target_profile_id': HYBRID}),
    ({'min_key_age_days': 90, 'permitted_profiles': [HYBRID]}, {'key_age_days': 120}, {'target_profile_id': 5}),
    ({'min_key_age_days': 90, 'permitted_profiles': [HYBRID]}, {}, {'target_profile_id': HYBRID}),
])
def test_off_schema_inputs_rejected_by_python_and_guest_alike(theta, x, action):
    with pytest.raises(ValueError):
        predicate.evaluate('rotation_threshold_v1', theta, x, action)
    stmt, w = B.encoding_vectors()['escapes']
    with pytest.raises(RuntimeError):
        ZK.execute(stmt, replace(w, theta=theta, x=x, a=action))


@needs_proof
def test_proof_verifies_for_the_registered_predicate_program(proven):
    system, tx, pc, reg, sc, stmt, w, proof, program_id = proven
    assert ZK.last_stats['receipt_kind'] == 'succinct'
    ok, why = predicate.verify_bound_statement(stmt, reg, sc.attestation, tx.authorization,
                                               system.trust, system.clock.now(), proof=proof, backend=ZK)
    assert ok, why


@needs_proof
def test_receipt_control_id_reveals_the_segment_size(proven):
    stats = ZK.last_stats
    if stats['segments'] == 1:
        assert stats['recursion_program'] == f"lift_rv32im_v2_{stats['lift_po2']}"
        assert stats['total_cycles'] == 2 ** stats['lift_po2']
    else:
        assert stats['recursion_program'] == 'join'


@needs_proof
def test_receipt_does_not_verify_for_a_different_result(proven):
    *_, stmt, w, proof, program_id = proven
    assert not ZK.verify(replace(stmt, q_i=not stmt.q_i), proof, program_id)


@needs_proof
def test_receipt_does_not_verify_for_another_program(proven):
    *_, stmt, w, proof, program_id = proven
    assert not ZK.verify(stmt, proof, '0' * 64)


@needs_proof
def test_registration_must_name_the_predicate_program(proven):
    system, tx, pc, reg, sc, stmt, w, proof, program_id = proven
    unnamed = predicate.register_policy(system.signers['policy_authority'], pc, [ASSET], system.clock.now() - 10,
                                        system.clock.now() + 10_000, 300)
    ok, why = predicate.verify_bound_statement(stmt, unnamed, sc.attestation, tx.authorization,
                                               system.trust, system.clock.now(), proof=proof, backend=ZK)
    assert not ok and 'no predicate program' in why


@needs_proof
def test_receipt_carries_no_witness_encoding(proven):
    *_, stmt, w, proof, program_id = proven
    for secret in (crypto.encode(w.theta), crypto.encode(w.x), w.r, w.r_i, w.r.hex().encode(), w.r_i.hex().encode()):
        assert secret not in proof


@needs_host
def test_soundness_calculator_matches_the_vendor_reference_value():
    snd = ZK.soundness()
    at20 = next(x for x in snd['rv32im_segment'] if x['po2'] == 20)
    assert abs(at20['toy_model'] - 97.14198) < 1e-3            # risc0-zkvm's own soundness::toy_model test
    levels = [x['toy_model'] for x in snd['rv32im_segment']]
    assert levels == sorted(levels, reverse=True)                # larger segments are weaker
    assert snd['max_accepted_po2'] == 19
