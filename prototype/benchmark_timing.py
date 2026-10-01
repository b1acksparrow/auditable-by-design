"""
Task 2: Timing decomposition benchmark.
20 warm-up + 200 timed repetitions per the paper's protocol.
Measures 5 non-overlapping categories per transaction:
  - ML-DSA signing
  - Canonical serialization
  - Hashing (SHA-384)
  - Hex encoding
  - Everything else (KEM, validation, object handling)
"""

import hashlib
import json
import time
import uuid
import os
import sys
import statistics

import oqs
from canonical_json import canonical_encode

HASH_ALG = 'sha384'
SIG_ALG = 'ML-DSA-65'
KEM_ALG = 'ML-KEM-768'

WARMUP = 20
TIMED = 200

ROLES = [
    'source_observer',
    'authorizer',
    'executor',
    'outcome_observer',
    'audit_envelope',
    'checkpoint_witness',
]


def ns():
    return time.monotonic_ns()


def generate_role_keys():
    keys = {}
    for role in ROLES:
        signer = oqs.Signature(SIG_ALG)
        pub = signer.generate_keypair()
        keys[role] = {'signer': signer, 'public_key': pub}
    return keys


def instrumented_transaction(role_keys, tx_id, prev_chain_hash, state_version):
    t_signing = 0
    t_canonical = 0
    t_hashing = 0
    t_hex = 0
    signing_count = 0

    total_start = ns()

    asset_profile = {
        'asset_id': 'tls-endpoint-01',
        'current_cipher': 'TLS_AES_256_GCM_SHA384',
        'target_cipher': 'TLS_AES_256_GCM_SHA384_ML_KEM_768',
        'state_version': state_version,
    }

    # Source observation
    source_stmt = {
        'schema': 'source_observation_v1',
        'role': 'source_observer',
        'tx_id': tx_id,
        'timestamp': int(time.time()),
        'asset_profile': asset_profile,
    }

    t0 = ns()
    ap_bytes = canonical_encode(asset_profile)
    t1 = ns()
    t_canonical += t1 - t0

    t0 = ns()
    h = hashlib.sha384(ap_bytes)
    digest_bytes = h.digest()
    t1 = ns()
    t_hashing += t1 - t0

    t0 = ns()
    source_stmt['evidence_digest'] = digest_bytes.hex()
    t1 = ns()
    t_hex += t1 - t0

    t0 = ns()
    source_bytes = canonical_encode(source_stmt)
    t1 = ns()
    t_canonical += t1 - t0

    t0 = ns()
    source_sig = role_keys['source_observer']['signer'].sign(source_bytes)
    t1 = ns()
    t_signing += t1 - t0
    signing_count += 1

    t0 = ns()
    source_sig_hex = source_sig.hex()
    t1 = ns()
    t_hex += t1 - t0

    t0 = ns()
    h = hashlib.sha384(source_bytes)
    source_digest_bytes = h.digest()
    t1 = ns()
    t_hashing += t1 - t0

    t0 = ns()
    source_digest = source_digest_bytes.hex()
    t1 = ns()
    t_hex += t1 - t0

    # Authorization
    proposal = {
        'action': 'migrate_to_pqc',
        'target_algorithm': KEM_ALG,
        'policy_version': 1,
        'source_digest': source_digest,
    }

    t0 = ns()
    prop_bytes = canonical_encode(proposal)
    t1 = ns()
    t_canonical += t1 - t0

    t0 = ns()
    h = hashlib.sha384(prop_bytes)
    prop_digest_bytes = h.digest()
    t1 = ns()
    t_hashing += t1 - t0

    t0 = ns()
    prop_digest_hex = prop_digest_bytes.hex()
    t1 = ns()
    t_hex += t1 - t0

    auth_stmt = {
        'schema': 'authorization_v1',
        'role': 'authorizer',
        'tx_id': tx_id,
        'timestamp': int(time.time()),
        'proposal': proposal,
        'proposal_digest': prop_digest_hex,
        'source_record_digest': source_digest,
    }

    t0 = ns()
    auth_bytes = canonical_encode(auth_stmt)
    t1 = ns()
    t_canonical += t1 - t0

    t0 = ns()
    auth_sig = role_keys['authorizer']['signer'].sign(auth_bytes)
    t1 = ns()
    t_signing += t1 - t0
    signing_count += 1

    t0 = ns()
    auth_sig_hex = auth_sig.hex()
    t1 = ns()
    t_hex += t1 - t0

    t0 = ns()
    h = hashlib.sha384(auth_bytes)
    auth_digest_bytes = h.digest()
    t1 = ns()
    t_hashing += t1 - t0

    t0 = ns()
    auth_digest = auth_digest_bytes.hex()
    t1 = ns()
    t_hex += t1 - t0

    # Executor receipt with KEM
    receiver = oqs.KeyEncapsulation(KEM_ALG)
    receiver_pk = receiver.generate_keypair()
    sender = oqs.KeyEncapsulation(KEM_ALG)
    ciphertext, ss_sender = sender.encap_secret(receiver_pk)
    ss_receiver = receiver.decap_secret(ciphertext)
    agreement = ss_sender == ss_receiver

    t0 = ns()
    h = hashlib.sha384(ciphertext)
    ct_digest_bytes = h.digest()
    t1 = ns()
    t_hashing += t1 - t0

    t0 = ns()
    ct_digest_hex = ct_digest_bytes.hex()
    t1 = ns()
    t_hex += t1 - t0

    kem_result = {
        'algorithm': KEM_ALG,
        'ciphertext_digest': ct_digest_hex,
        'ciphertext_len': len(ciphertext),
        'shared_secret_len': len(ss_sender),
        'agreement': agreement,
    }

    exec_stmt = {
        'schema': 'executor_receipt_v1',
        'role': 'executor',
        'tx_id': tx_id,
        'timestamp': int(time.time()),
        'authorization_digest': auth_digest,
        'proposal_digest': prop_digest_hex,
        'state_version_before': state_version,
        'state_version_after': state_version + 1,
        'kem_result': kem_result,
    }

    t0 = ns()
    exec_bytes = canonical_encode(exec_stmt)
    t1 = ns()
    t_canonical += t1 - t0

    t0 = ns()
    exec_sig = role_keys['executor']['signer'].sign(exec_bytes)
    t1 = ns()
    t_signing += t1 - t0
    signing_count += 1

    t0 = ns()
    exec_sig_hex = exec_sig.hex()
    t1 = ns()
    t_hex += t1 - t0

    t0 = ns()
    h = hashlib.sha384(exec_bytes)
    exec_digest_bytes = h.digest()
    t1 = ns()
    t_hashing += t1 - t0

    t0 = ns()
    exec_digest = exec_digest_bytes.hex()
    t1 = ns()
    t_hex += t1 - t0

    # Outcome observation
    outcome_profile = dict(asset_profile)
    outcome_profile['current_cipher'] = asset_profile['target_cipher']
    outcome_profile['state_version'] = state_version + 1

    outcome_stmt = {
        'schema': 'outcome_observation_v1',
        'role': 'outcome_observer',
        'tx_id': tx_id,
        'timestamp': int(time.time()),
        'receipt_digest': exec_digest,
        'observed_profile': outcome_profile,
    }

    t0 = ns()
    op_bytes = canonical_encode(outcome_profile)
    t1 = ns()
    t_canonical += t1 - t0

    t0 = ns()
    h = hashlib.sha384(op_bytes)
    op_digest_bytes = h.digest()
    t1 = ns()
    t_hashing += t1 - t0

    t0 = ns()
    outcome_stmt['profile_digest'] = op_digest_bytes.hex()
    t1 = ns()
    t_hex += t1 - t0

    t0 = ns()
    outcome_bytes = canonical_encode(outcome_stmt)
    t1 = ns()
    t_canonical += t1 - t0

    t0 = ns()
    outcome_sig = role_keys['outcome_observer']['signer'].sign(outcome_bytes)
    t1 = ns()
    t_signing += t1 - t0
    signing_count += 1

    t0 = ns()
    outcome_sig_hex = outcome_sig.hex()
    t1 = ns()
    t_hex += t1 - t0

    t0 = ns()
    h = hashlib.sha384(outcome_bytes)
    outcome_digest_bytes = h.digest()
    t1 = ns()
    t_hashing += t1 - t0

    t0 = ns()
    outcome_digest = outcome_digest_bytes.hex()
    t1 = ns()
    t_hex += t1 - t0

    # Audit envelope
    envelope_stmt = {
        'schema': 'audit_envelope_v1',
        'role': 'audit_envelope',
        'tx_id': tx_id,
        'timestamp': int(time.time()),
        'chain_prev': prev_chain_hash,
        'source_digest': source_digest,
        'authorization_digest': auth_digest,
        'executor_digest': exec_digest,
        'outcome_digest': outcome_digest,
    }

    t0 = ns()
    envelope_bytes = canonical_encode(envelope_stmt)
    t1 = ns()
    t_canonical += t1 - t0

    t0 = ns()
    envelope_sig = role_keys['audit_envelope']['signer'].sign(envelope_bytes)
    t1 = ns()
    t_signing += t1 - t0
    signing_count += 1

    t0 = ns()
    envelope_sig_hex = envelope_sig.hex()
    t1 = ns()
    t_hex += t1 - t0

    t0 = ns()
    h = hashlib.sha384(envelope_bytes)
    envelope_digest_bytes = h.digest()
    t1 = ns()
    t_hashing += t1 - t0

    t0 = ns()
    envelope_digest = envelope_digest_bytes.hex()
    t1 = ns()
    t_hex += t1 - t0

    # Checkpoint
    checkpoint_stmt = {
        'schema': 'checkpoint_v1',
        'role': 'checkpoint_witness',
        'tx_id': tx_id,
        'timestamp': int(time.time()),
        'log_identity': 'audit-log-001',
        'chain_length': state_version + 1,
        'witnessed_head': envelope_digest,
    }

    t0 = ns()
    checkpoint_bytes = canonical_encode(checkpoint_stmt)
    t1 = ns()
    t_canonical += t1 - t0

    t0 = ns()
    checkpoint_sig = role_keys['checkpoint_witness']['signer'].sign(checkpoint_bytes)
    t1 = ns()
    t_signing += t1 - t0
    signing_count += 1

    t0 = ns()
    checkpoint_sig_hex = checkpoint_sig.hex()
    t1 = ns()
    t_hex += t1 - t0

    t0 = ns()
    h = hashlib.sha384(checkpoint_bytes)
    checkpoint_digest_bytes = h.digest()
    t1 = ns()
    t_hashing += t1 - t0

    t0 = ns()
    checkpoint_digest = checkpoint_digest_bytes.hex()
    t1 = ns()
    t_hex += t1 - t0

    total_end = ns()
    total_elapsed = total_end - total_start
    everything_else = total_elapsed - t_signing - t_canonical - t_hashing - t_hex

    return {
        'tx_id': tx_id,
        'total_ns': total_elapsed,
        'signing_ns': t_signing,
        'canonical_ns': t_canonical,
        'hashing_ns': t_hashing,
        'hex_ns': t_hex,
        'everything_else_ns': everything_else,
        'signing_count': signing_count,
    }


def uninstrumented_transaction(role_keys, tx_id, prev_chain_hash, state_version):
    from transaction import create_transaction
    t0 = ns()
    create_transaction(role_keys, tx_id, prev_chain_hash, state_version)
    t1 = ns()
    return t1 - t0


def percentile(data, p):
    data_sorted = sorted(data)
    k = (len(data_sorted) - 1) * p / 100
    f = int(k)
    c = f + 1
    if c >= len(data_sorted):
        return data_sorted[f]
    return data_sorted[f] + (k - f) * (data_sorted[c] - data_sorted[f])


def run_benchmark(output_dir):
    print(f"Generating {len(ROLES)} role keys (ML-DSA-65)...")
    role_keys = generate_role_keys()

    print(f"Warm-up: {WARMUP} transactions...")
    for i in range(WARMUP):
        tx_id = str(uuid.uuid4())
        instrumented_transaction(role_keys, tx_id, '0' * 96, i)

    print(f"Timed: {TIMED} instrumented transactions...")
    samples = []
    for i in range(TIMED):
        tx_id = str(uuid.uuid4())
        row = instrumented_transaction(role_keys, tx_id, '0' * 96, i)
        samples.append(row)

    print(f"Warm-up: {WARMUP} uninstrumented transactions...")
    for i in range(WARMUP):
        tx_id = str(uuid.uuid4())
        uninstrumented_transaction(role_keys, tx_id, '0' * 96, i)

    print(f"Timed: {TIMED} uninstrumented transactions...")
    uninstr_samples = []
    for i in range(TIMED):
        tx_id = str(uuid.uuid4())
        t = uninstrumented_transaction(role_keys, tx_id, '0' * 96, i)
        uninstr_samples.append(t)

    # Check for negative residuals
    neg_residuals = sum(1 for s in samples if s['everything_else_ns'] < 0)
    if neg_residuals > 0:
        print(f"WARNING: {neg_residuals} samples had negative residual (timing overlap)")

    categories = ['signing_ns', 'canonical_ns', 'hashing_ns', 'hex_ns', 'everything_else_ns', 'total_ns']
    labels = ['ML-DSA signing', 'Canonical serialization', 'Hashing (SHA-384)', 'Hex encoding', 'Everything else', 'Instrumented total']

    results = {}
    for cat, label in zip(categories, labels):
        vals = [s[cat] for s in samples]
        med = statistics.median(vals)
        p95 = percentile(vals, 95)
        results[label] = {
            'median_ns': med,
            'median_ms': med / 1e6,
            'p95_ns': p95,
            'p95_ms': p95 / 1e6,
        }

    uninstr_med = statistics.median(uninstr_samples)
    uninstr_p95 = percentile(uninstr_samples, 95)
    results['Uninstrumented total'] = {
        'median_ns': uninstr_med,
        'median_ms': uninstr_med / 1e6,
        'p95_ns': uninstr_p95,
        'p95_ms': uninstr_p95 / 1e6,
    }

    # Raw samples
    raw_path = os.path.join(output_dir, 'timing_raw_samples.json')
    with open(raw_path, 'w') as f:
        json.dump({
            'config': {
                'warmup': WARMUP,
                'timed': TIMED,
                'sig_alg': SIG_ALG,
                'kem_alg': KEM_ALG,
                'hash_alg': HASH_ALG,
                'roles': len(ROLES),
            },
            'instrumented_samples': samples,
            'uninstrumented_samples_ns': uninstr_samples,
            'negative_residuals': neg_residuals,
        }, f, indent=2)

    summary_path = os.path.join(output_dir, 'timing_summary.json')
    with open(summary_path, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n{'='*70}")
    print("Table VI: Transaction creation timing decomposition")
    print(f"{'='*70}")
    print(f"{'Component':<30} {'Median ms':>12} {'95th pct ms':>14}")
    print(f"{'-'*30} {'-'*12} {'-'*14}")
    for label in labels + ['Uninstrumented total']:
        r = results[label]
        print(f"{label:<30} {r['median_ms']:>12.3f} {r['p95_ms']:>14.3f}")

    signing_pct = results['ML-DSA signing']['median_ns'] / results['Instrumented total']['median_ns'] * 100
    serial_pct = results['Canonical serialization']['median_ns'] / results['Instrumented total']['median_ns'] * 100
    hash_pct = results['Hashing (SHA-384)']['median_ns'] / results['Instrumented total']['median_ns'] * 100
    hex_pct = results['Hex encoding']['median_ns'] / results['Instrumented total']['median_ns'] * 100
    other_pct = results['Everything else']['median_ns'] / results['Instrumented total']['median_ns'] * 100

    print(f"\nMedian share: signing {signing_pct:.1f}%, serialization {serial_pct:.1f}%, "
          f"hashing {hash_pct:.1f}%, hex {hex_pct:.1f}%, other {other_pct:.1f}%")

    overhead = (results['Instrumented total']['median_ns'] - results['Uninstrumented total']['median_ns']) / results['Uninstrumented total']['median_ns'] * 100
    print(f"Instrumentation overhead: {overhead:+.1f}%")
    print(f"Signing calls per transaction: {samples[0]['signing_count']}")

    return results


if __name__ == '__main__':
    output_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(output_dir, exist_ok=True)
    run_benchmark(output_dir)
