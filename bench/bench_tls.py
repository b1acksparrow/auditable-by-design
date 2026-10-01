"""Deployed-service observation and the silent-downgrade scenarios (Section VIII).

Runs a real user-space TLS 1.3 service (nginx on OpenSSL) whose key-exchange
groups are the governed configuration, and:

  1. observes delivered protection from a panel of reference clients, one per
     capability class, by completing real handshakes (independent observation of
     a deployed service, not of a receipt or of the service's self-report);
  2. reproduces the silent downgrade of Han (arXiv:2609.07849) in two scenarios
     from a base service offering both hybrid groups: A removes X25519MLKEM768,
     B removes SecP256r1MLKEM768.  Each edited configuration still validates and
     still serves every peer it served before (handshake and HTTP 200), yet the
     peers of one hybrid class silently fall back to a classical group.  Each
     single peer class misses at least one scenario; the panel detects both.
     The pqc_strict peer fails in every state (no pure-PQ group is offered).

Per-probe wall time (one s_client process: start, handshake, trace, HTTP GET,
close) is recorded with a client process-start baseline (``openssl version``);
it is not handshake latency.  Requires nginx and openssl.

Usage: python3 bench/bench_tls.py OUTDIR [REPS]
"""

import json
import os
import statistics
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from abd import tls_probe as T  # noqa: E402
import envinfo  # noqa: E402

BASE_CONF = 'SecP256r1MLKEM768:X25519MLKEM768:X25519:secp256r1'
SCENARIOS = {'A': 'X25519MLKEM768', 'B': 'SecP256r1MLKEM768'}   # scenario -> group removed from BASE_CONF


def openssl_version() -> str:
    import subprocess
    return subprocess.run(['openssl', 'version'], capture_output=True, text=True).stdout.strip()


def nginx_version() -> str:
    import subprocess
    return subprocess.run(['nginx', '-v'], capture_output=True, text=True).stderr.strip()


def _wall_samples_ms(fn, reps: int) -> list:
    samples = []
    for _ in range(reps):
        t0 = time.monotonic()
        if fn():
            samples.append((time.monotonic() - t0) * 1000)
    return samples


def probe_wall_time(port: int, reps: int) -> dict:
    """Median wall time of one probe per class, including client process start.

    The baseline is the median wall time of ``openssl version`` (process start
    and library load, no network); the difference of medians is the probe's cost
    beyond process start (connect, handshake, trace output, HTTP GET, close)."""
    import subprocess
    base = _wall_samples_ms(lambda: subprocess.run(['openssl', 'version'], capture_output=True).returncode == 0, reps)
    baseline = round(statistics.median(base), 2)
    per_class = {}
    for name, groups in T.REFERENCE_CLIENTS.items():
        samples = _wall_samples_ms(lambda g=groups: T.handshake(port, g)['handshake_ok'], reps)
        if not samples:
            per_class[name] = {'ok': False}
            continue
        med = round(statistics.median(samples), 2)
        per_class[name] = {'ok': True, 'n': len(samples), 'median_probe_wall_ms_incl_process_start': med,
                           'median_probe_minus_baseline_ms': round(med - baseline, 2)}
    return {'process_start_baseline': {'command': 'openssl version', 'n': len(base), 'median_ms': baseline},
            'per_class': per_class}


def main(outdir, reps=10):
    os.makedirs(outdir, exist_ok=True)
    if not T.tools_available():
        raise SystemExit('nginx and openssl are required for the TLS observation benchmark')
    obs = T.TlsOutcomeObserver()
    wd = tempfile.mkdtemp(prefix='abd-tls-bench-')

    svc = T.TlsService(wd, groups=BASE_CONF)
    base_valid = svc.config_valid()
    svc.start()
    try:
        before = obs.observe(svc)
        wall = probe_wall_time(svc.port, reps)
        scenarios = {}
        for name, removed in SCENARIOS.items():
            # The administrator removes one hybrid group; the artifact-side check still passes.
            conf = ':'.join(g for g in BASE_CONF.split(':') if g != removed)
            svc.reconfigure(groups=conf)
            valid = svc.config_valid()
            after = obs.observe(svc)
            scenarios[name] = {'removed_group': removed, 'config': conf, 'config_valid': valid,
                               'config_still_valid_and_serves': valid and T.still_serves(before, after),
                               'after': after.to_json(), 'detection': T.downgrade_detected(before, after)}
    finally:
        svc.stop()
    panel = T.panel_argument({n: sc['detection'] for n, sc in scenarios.items()})

    result = {
        'tools': {'nginx': nginx_version(), 'openssl': openssl_version()},
        'reference_clients': T.REFERENCE_CLIENTS,
        'base_config': BASE_CONF, 'base_config_valid': base_valid, 'base': before.to_json(),
        'scenarios': scenarios,
        'panel': panel,
        'probe_wall_time': wall,
        'environment': envinfo.collect(wait_quiet=True),
    }
    with open(os.path.join(outdir, 'tls_results.json'), 'w') as fh:
        json.dump(result, fh, indent=2)

    cols = ['base'] + [f'{n}: -{sc["removed_group"]}' for n, sc in scenarios.items()]
    print('delivered protection by client class:')
    print(f"  {'class':18s}" + ''.join(f'{c:26s}' for c in cols) + 'detects')
    for c in T.REFERENCE_CLIENTS:
        cells = [before.delivered_class(c) or 'failed']
        for sc in scenarios.values():
            d = sc['detection']
            cells.append(f"{d['per_class'][c]['after'] or 'failed'}{'' if d[f'single_peer_{c}_would_miss'] else ' (LOST)'}")
        print(f'  {c:18s}' + ''.join(f'{x:26s}' for x in cells) + (','.join(panel['scenarios_detected_by_single_peer'][c]) or '-'))
    for n, sc in scenarios.items():
        print(f"scenario {n}: config {sc['config']} still validates and serves: {sc['config_still_valid_and_serves']}; "
              f"hard failures: {sc['detection']['hard_failed_clients']}")
    print('panel detects all scenarios:', panel['panel_detects_all'],
          '| single peers detecting all:', panel['single_peers_detecting_all'],
          '| no single peer suffices:', panel['no_single_peer_detects_all_but_panel_does'])
    b = wall['process_start_baseline']
    print(f"process-start baseline (openssl version): {b['median_ms']} ms")
    for c, w in wall['per_class'].items():
        if w['ok']:
            print(f"  {c:18s} probe wall time incl. process start {w['median_probe_wall_ms_incl_process_start']} ms "
                  f"(minus baseline {w['median_probe_minus_baseline_ms']} ms, n={w['n']})")
    assert base_valid and panel['no_single_peer_detects_all_but_panel_does'], panel
    assert all(sc['config_still_valid_and_serves'] for sc in scenarios.values()), scenarios
    return result


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'results', 'v2', 'tls'),
         int(sys.argv[2]) if len(sys.argv) > 2 else 10)
