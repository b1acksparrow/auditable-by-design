"""
Task 3: Verification scaling benchmark.
Builds valid archives at 10, 100, 1000, 10000 transactions.
100,000 attempted if resources permit.
Each transaction has distinct ID and valid state continuity.
20 warm-up + 200 timed full verifications at each size.
Memory measured in a separate pass.
"""

import hashlib
import json
import os
import resource
import statistics
import sys
import time
import uuid

import oqs
from canonical_json import canonical_encode
from transaction import create_transaction, verify_record, generate_role_keys, sha384_hex

WARMUP = 20
TIMED = 200
SIZES = [10, 100, 1_000, 10_000, 100_000]
WALL_LIMIT_S = 600
MEMORY_LIMIT_MIB = 4096


def build_archive(role_keys, n):
    records = []
    prev_hash = '0' * 96
    for i in range(n):
        tx_id = str(uuid.uuid4())
        rec = create_transaction(role_keys, tx_id, prev_hash, i)
        prev_hash = rec['envelope']['digest']
        records.append(rec)
    checkpoint = records[-1]['checkpoint']
    return records, checkpoint


def full_verify(archive, role_keys, checkpoint):
    seen_tx_ids = set()
    prev_hash = '0' * 96
    for rec in archive:
        checks = verify_record(rec, role_keys)
        for c in checks:
            if 'digest_valid' in c and not c['digest_valid']:
                return False, f"digest invalid: {c['section']}"
            if 'signature_valid' in c and not c['signature_valid']:
                return False, f"signature invalid: {c['section']}"

        tx_id = rec['tx_id']
        if tx_id in seen_tx_ids:
            return False, f"duplicate tx_id: {tx_id}"
        seen_tx_ids.add(tx_id)

        if rec['envelope']['statement']['chain_prev'] != prev_hash:
            return False, f"chain break at {tx_id}"
        prev_hash = rec['envelope']['digest']

    if archive[-1]['envelope']['digest'] != checkpoint['statement']['witnessed_head']:
        return False, "checkpoint head mismatch"

    return True, "ok"


def percentile(data, p):
    data_sorted = sorted(data)
    k = (len(data_sorted) - 1) * p / 100
    f = int(k)
    c = f + 1
    if c >= len(data_sorted):
        return data_sorted[f]
    return data_sorted[f] + (k - f) * (data_sorted[c] - data_sorted[f])


def run_scaling(output_dir):
    print(f"Generating role keys (ML-DSA-65)...")
    role_keys = generate_role_keys()

    all_results = []

    for size in SIZES:
        print(f"\n{'='*60}")
        print(f"Archive size: {size:,} transactions")
        print(f"{'='*60}")

        print(f"  Building archive...")
        build_start = time.monotonic()
        try:
            archive, checkpoint = build_archive(role_keys, size)
        except Exception as e:
            print(f"  BUILD FAILED: {e}")
            all_results.append({
                'transactions': size,
                'status': f'build_failed: {e}',
            })
            continue
        build_time = time.monotonic() - build_start
        print(f"  Built in {build_time:.1f}s")

        archive_json = json.dumps([{
            'tx_id': r['tx_id'],
            'source': r['source'],
            'authorization': r['authorization'],
            'executor': r['executor'],
            'outcome': r['outcome'],
            'envelope': r['envelope'],
            'checkpoint': r['checkpoint'],
        } for r in archive])
        archive_bytes = len(archive_json.encode('utf-8'))
        print(f"  Archive size: {archive_bytes / 1024 / 1024:.2f} MiB")

        # Timing pass
        print(f"  Warm-up: {WARMUP} verifications...")
        for _ in range(WARMUP):
            ok, msg = full_verify(archive, role_keys, checkpoint)
            if not ok:
                print(f"  VERIFY FAILED during warmup: {msg}")
                break

        print(f"  Timed: {TIMED} verifications...")
        timing_samples = []
        failed = False
        for i in range(TIMED):
            t0 = time.monotonic()
            ok, msg = full_verify(archive, role_keys, checkpoint)
            t1 = time.monotonic()
            if not ok:
                print(f"  VERIFY FAILED at rep {i}: {msg}")
                failed = True
                break
            elapsed = t1 - t0
            timing_samples.append(elapsed)
            if elapsed > WALL_LIMIT_S:
                print(f"  WALL LIMIT exceeded at rep {i}: {elapsed:.1f}s")
                failed = True
                break

        if failed or len(timing_samples) < TIMED:
            status = f'partial: {len(timing_samples)}/{TIMED} completed'
        else:
            status = 'complete'

        if timing_samples:
            med_s = statistics.median(timing_samples)
            p95_s = percentile(timing_samples, 95)
        else:
            med_s = p95_s = None

        # Memory pass (measure peak RSS)
        print(f"  Memory pass: single verification for peak RSS...")
        mem_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        ok, _ = full_verify(archive, role_keys, checkpoint)
        mem_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        peak_rss_kib = mem_after
        peak_rss_mib = peak_rss_kib / 1024

        result = {
            'transactions': size,
            'archive_mib': archive_bytes / 1024 / 1024,
            'build_time_s': build_time,
            'median_verify_s': med_s,
            'p95_verify_s': p95_s,
            'peak_rss_mib': peak_rss_mib,
            'timing_samples_count': len(timing_samples),
            'status': status,
        }
        all_results.append(result)

        if med_s is not None:
            print(f"  Median verify: {med_s:.4f}s, P95: {p95_s:.4f}s")
        print(f"  Peak RSS: {peak_rss_mib:.1f} MiB")

        del archive
        del archive_json

    # Save results
    raw_path = os.path.join(output_dir, 'scaling_results.json')
    with open(raw_path, 'w') as f:
        json.dump({
            'config': {
                'warmup': WARMUP,
                'timed': TIMED,
                'sizes': SIZES,
                'wall_limit_s': WALL_LIMIT_S,
                'memory_limit_mib': MEMORY_LIMIT_MIB,
            },
            'results': all_results,
        }, f, indent=2)

    print(f"\n{'='*70}")
    print("Table: Verification scaling")
    print(f"{'='*70}")
    print(f"{'Txns':>10} {'Med verify s':>14} {'P95 verify s':>14} {'Peak RSS MiB':>14} {'Status':>20}")
    print(f"{'-'*10} {'-'*14} {'-'*14} {'-'*14} {'-'*20}")
    for r in all_results:
        med = f"{r['median_verify_s']:.4f}" if r['median_verify_s'] is not None else 'N/A'
        p95 = f"{r['p95_verify_s']:.4f}" if r['p95_verify_s'] is not None else 'N/A'
        print(f"{r['transactions']:>10,} {med:>14} {p95:>14} {r['peak_rss_mib']:>14.1f} {r['status']:>20}")

    # Linearity check
    completed = [r for r in all_results if r['median_verify_s'] is not None and r['transactions'] >= 10]
    if len(completed) >= 2:
        per_tx = [(r['median_verify_s'] / r['transactions'] * 1000) for r in completed]
        print(f"\nPer-transaction cost (ms): " + ", ".join(
            f"{r['transactions']:,}={pt:.4f}" for r, pt in zip(completed, per_tx)))
        ratio = max(per_tx) / min(per_tx) if min(per_tx) > 0 else float('inf')
        if ratio < 2.0:
            print(f"Approximately linear: per-tx cost ratio {ratio:.2f}x across sizes")
        else:
            print(f"Non-linear growth detected: per-tx cost ratio {ratio:.2f}x")

    return all_results


if __name__ == '__main__':
    output_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(output_dir, exist_ok=True)
    run_scaling(output_dir)
