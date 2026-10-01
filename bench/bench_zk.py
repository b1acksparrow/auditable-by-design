"""Cost of the zero-knowledge argument of relation R (Eq. 5) with RISC Zero.

The statement is built from a real transaction of the reference pipeline: the
action digest D_i covers the actual proposal that the authorization and the
receipt bind.  Each run produces a succinct (recursion) receipt locally with
abd-zk-host and records proving time, in-process verification time, receipt
size, cycle counts, the prover's peak resident set (VmHWM) and the receipt's
recursion control id (which, for one segment, names the lift program of the
padded power-of-two cycle count, so execution length is not hidden).  Negative
checks confirm that the receipt does not verify for a statement with a
different result or for a different predicate program, and that the receipt
bytes do not contain the canonical encodings of theta, x or the commitment
openings.  A cross-language encoding check executes the guest (no proof) on
off-fixture vectors with JSON escapes, negative integers, null, empty and
nested containers, and compares each journal with the Python encoding of the
statement.

Usage: python3 bench/bench_zk.py OUTDIR [RUNS]
"""

import json
import os
import statistics
import sys
import time
from dataclasses import replace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from abd import crypto, predicate  # noqa: E402
from abd.fixture import ASSET, HYBRID, READY_ENDPOINTS, make_system  # noqa: E402
import envinfo  # noqa: E402

RISC0_VERSION = '3.0.6'


def build_statement():
    system = make_system()
    tx = system.run(ASSET, HYBRID, endpoints=READY_ENDPOINTS)
    now = system.clock.now()
    pc = predicate.PolicyCommitment.create('rotation_threshold_v1', 1,
                                           {'min_key_age_days': 90, 'permitted_profiles': [HYBRID]})
    kappa = {'tx_id': tx.tx_id, 'asset_id': ASSET, 'state_version': 0, 'period': 'daily'}
    sc = predicate.source_commit(system.signers['source_observer'], kappa, {'key_age_days': 120}, 300, now)
    stmt, w = predicate.Prover(pc).statement(sc, tx.proposal)
    return system, tx, pc, sc, stmt, w


def _vector(theta, x, kappa, action, v=1):
    pc = predicate.PolicyCommitment.create('rotation_threshold_v1', v, theta)
    r_i = predicate.fresh_randomness()
    X_i = predicate.commit(crypto.encode({'kappa': kappa, 'x': x}), r_i)
    return predicate.Prover(pc).statement(predicate.SourceCommitment(kappa, x, r_i, X_i, {}), action)


def encoding_vectors() -> dict:
    """name -> (statement, witness) exercising the guest encoder beyond the evaluated statement."""
    q, b = '"', '\\'
    return {
        'escapes': _vector(
            {'min_key_age_days': 90, 'permitted_profiles': [f'p{q}1', f'p{b}2', f'p{b}{q}3'], 'note': f'say {q}hi{q} {b} bye'},
            {'key_age_days': 120, 'comment': f'{b}{q}{b}{b}'},
            {'tx_id': f'tx{q}{b}1', 'asset_id': f'a{b}b{q}c', 'state_version': 0, 'period': 'daily'},
            {'target_profile_id': f'p{b}{q}3', 'free_text': f'He said: {q}rotate {b} now{q} / ~', f'key {q}q{q}': 'v',
             f'back{b}slash': 1}),
        'negatives_nulls_empties': _vector(
            {'min_key_age_days': -5, 'permitted_profiles': [], 'n': None, 'o': {}, 'l': [],
             'lo': -(2**53 - 1), 'hi': 2**53 - 1},
            {'key_age_days': -7, 'z': None},
            {'tx_id': '', 'asset_id': ' ', 'state_version': -1, 'period': None, 'extra': []},
            {'target_profile_id': '', 'params': {}, 'list': [None, [], {}, 0, -1, False]}, v=-2),
        'nested': _vector(
            {'min_key_age_days': 0, 'permitted_profiles': [None, 7, ['target'], {'k': 'target'}, 'target']},
            {'key_age_days': 0, 'deep': {'a': {'b': {'c': [{'d': None}, {}], 'e': -1}}}},
            {'tx_id': 't', 'asset_id': 'a', 'state_version': 3, 'period': {'from': -10, 'to': [1, [2, [3]]]}},
            {'target_profile_id': 'target', 'Zed': 1,
             'alpha': {'b': 2, 'B': 3, f'a{q}': 4, f'a{b}': 5, '_': 6, ' ': 7, '~': 8, '': {'': []}}}),
    }


def check_encoding_vectors(backend) -> dict:
    """Executes the guest on each vector; journal_matches is journal == Enc(statement)."""
    out = {}
    for name, (stmt, w) in encoding_vectors().items():
        res = backend.execute(stmt, w)
        out[name] = {'journal_matches': bytes.fromhex(res['journal_hex']) == crypto.encode(stmt.to_json()),
                     'q_i': stmt.q_i, 'journal_bytes': res['journal_bytes'], 'total_cycles': res['total_cycles'],
                     'user_cycles': res['user_cycles'], 'segments': res['segments'],
                     'segment_po2s': res['segment_po2s']}
    return out


def main(outdir, runs=3):
    os.makedirs(outdir, exist_ok=True)
    backend = predicate.RiscZeroBackend()
    if not backend.available():
        raise SystemExit(f'abd-zk-host not built at {backend.host}; run: cd zk && cargo build --release')
    program_id = backend.program_id()
    system, tx, pc, sc, stmt, w = build_statement()
    reg = predicate.register_policy(system.signers['policy_authority'], pc, [ASSET], system.clock.now() - 10,
                                    system.clock.now() + 10_000, 300, program_id=program_id)
    results = []
    proof = None
    for i in range(runs):
        t0 = time.monotonic()
        proof = backend.prove(stmt, w)
        wall = time.monotonic() - t0
        stats = dict(backend.last_stats, wall_s_including_process=wall)
        t1 = time.monotonic()
        ok = backend.verify(stmt, proof, program_id)
        stats['external_verify_wall_s'] = time.monotonic() - t1
        stats['verified'] = ok
        results.append(stats)
        print(f"run {i + 1}/{runs}: prove {stats['prove_s']:.1f}s, receipt {stats['receipt_bytes']} B, "
              f"cycles {stats['total_cycles']}, peak {stats['peak_rss_kib'] / 2**20:.2f} GiB, verified {ok}", flush=True)
    secrets = [crypto.encode(w.theta), crypto.encode(w.x), w.r, w.r_i, w.r.hex().encode(), w.r_i.hex().encode()]
    negative = {
        'flipped_result_rejected': not backend.verify(replace(stmt, q_i=not stmt.q_i), proof, program_id),
        'other_program_rejected': not backend.verify(stmt, proof, '0' * 64),
        'bound_statement_verifies': predicate.verify_bound_statement(
            stmt, reg, sc.attestation, tx.authorization, system.trust, system.clock.now(),
            proof=proof, backend=backend)[0],
        'secrets_absent_from_receipt': not any(s in proof for s in secrets),
    }
    vectors = check_encoding_vectors(backend)
    negative['encoding_vectors_match'] = all(v['journal_matches'] for v in vectors.values())
    summary = {
        'runs': runs,
        'prove_s_median': statistics.median(r['prove_s'] for r in results),
        'verify_ms_median': 1000 * statistics.median(r['verify_s'] for r in results),
        'receipt_bytes': results[-1]['receipt_bytes'],
        'journal_bytes': results[-1]['journal_bytes'],
        'peak_rss_kib_max': max(r['peak_rss_kib'] for r in results),
        'total_cycles': results[-1]['total_cycles'],
        'user_cycles': results[-1]['user_cycles'],
        'segments': results[-1]['segments'],
        'segment_po2': results[-1]['segment_po2'],
        'control_id': results[-1].get('control_id'),
        'recursion_program': results[-1].get('recursion_program'),
        'lift_po2': results[-1].get('lift_po2'),
        'action_bytes': len(crypto.encode(w.a)),
    }
    try:
        snd = backend.soundness()
    except RuntimeError:          # host built before the soundness subcommand existed
        snd = None
    summary['soundness'] = soundness_summary(snd)
    out = {'risc0_version': RISC0_VERSION, 'soundness_calculator': snd, 'receipt_kind': 'succinct (recursion)', 'image_id': program_id,
           'statement': stmt.to_json(), 'summary': summary, 'negative_checks': negative,
           'encoding_vectors': vectors, 'runs': results, 'environment': envinfo.collect(wait_quiet=True)}
    with open(os.path.join(outdir, 'zk_results.json'), 'w') as fh:
        json.dump(out, fh, indent=2)
    print(json.dumps({'summary': summary, 'negative_checks': negative, 'encoding_vectors': vectors}, indent=2))
    assert all(negative.values()), negative
    return out


def soundness_summary(snd):
    """Bits for the worst receipt the verifier accepts (one segment at max_accepted_po2, then recursion).

    A receipt is only as sound as the weakest proof in its chain, so each end-to-end figure is the minimum
    of the segment figure and the recursion figure under the same model.
    """
    if snd is None:
        return None
    seg = next(x for x in snd['rv32im_segment'] if x['po2'] == snd['max_accepted_po2'])
    rec = snd['recursion']
    out = {'max_accepted_po2': snd['max_accepted_po2'], 'recursion_po2': rec['po2']}
    for model in ('toy_model', 'conjectured_strict', 'proven'):
        out[f'segment_{model}_bits'] = seg[model]
        out[f'recursion_{model}_bits'] = rec[model]
        out[f'end_to_end_{model}_bits'] = min(seg[model], rec[model])
    return out


def refresh_soundness(outdir):
    """Re-run only the soundness calculator and update an existing zk_results.json (no new proofs)."""
    path = os.path.join(outdir, 'zk_results.json')
    with open(path) as fh:
        out = json.load(fh)
    snd = predicate.RiscZeroBackend().soundness()
    out['soundness_calculator'] = snd
    out['summary']['soundness'] = soundness_summary(snd)
    with open(path, 'w') as fh:
        json.dump(out, fh, indent=2)
    print(json.dumps(out['summary']['soundness'], indent=2))


if __name__ == '__main__':
    if '--soundness-only' in sys.argv:
        sys.argv.remove('--soundness-only')
        refresh_soundness(sys.argv[1] if len(sys.argv) > 1 else
                          os.path.join(os.path.dirname(__file__), '..', 'results', 'v2', 'zk'))
        sys.exit(0)
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'results', 'v2', 'zk'),
         int(sys.argv[2]) if len(sys.argv) > 2 else 3)
