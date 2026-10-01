"""Capture the run environment (resolves the [VERIFY] notes of the manuscript)."""

import json
import os
import platform
import re
import subprocess
import sys
import time


def _cpu_model():
    try:
        with open('/proc/cpuinfo') as fh:
            for line in fh:
                if line.startswith('model name'):
                    return line.split(':', 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or 'unknown'


def _mem_total_mib():
    try:
        with open('/proc/meminfo') as fh:
            for line in fh:
                if line.startswith('MemTotal'):
                    return int(line.split()[1]) // 1024
    except OSError:
        pass
    return None


def _liboqs_build():
    import oqs
    info = {'liboqs': oqs.oqs_version(), 'liboqs_python': oqs.oqs_python_version()}
    try:
        import oqs.oqs as _m
        path = _m._liboqs._name  # ctypes CDLL path
        info['liboqs_path'] = path
        out = subprocess.run(['strings', path], capture_output=True, text=True, timeout=30).stdout
        m = re.search(r'GCC: \([^)]*\) [0-9.]+', out)
        info['compiler'] = m.group(0) if m else 'not recorded in binary'
    except Exception as exc:  # pragma: no cover
        info['compiler'] = f'unavailable ({exc})'
    return info


def _read(path):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return None


def _run_conditions() -> dict:
    """Conditions that change measured latency: power source, frequency governor, load, storage device."""
    supplies = {}
    base = '/sys/class/power_supply'
    if os.path.isdir(base):
        for name in sorted(os.listdir(base)):
            kind = _read(os.path.join(base, name, 'type'))
            if kind == 'Mains':
                supplies['ac_online'] = _read(os.path.join(base, name, 'online')) == '1'
            elif kind == 'Battery':
                supplies['battery_status'] = _read(os.path.join(base, name, 'status'))
    governors = sorted({g for g in (_read(f'/sys/devices/system/cpu/cpufreq/policy{i}/scaling_governor')
                                    for i in range(os.cpu_count() or 1)) if g})
    try:
        device = subprocess.run(['findmnt', '-no', 'SOURCE,FSTYPE', '--target', os.getcwd()],
                                capture_output=True, text=True, timeout=10).stdout.strip()
    except OSError:
        device = None
    return {'power': supplies, 'cpufreq_governors': governors,
            'loadavg_1_5_15': list(os.getloadavg()), 'results_filesystem': device}


def wait_until_quiet(threshold: float = 1.5, max_wait_s: int = 300, poll_s: int = 5) -> float:
    """Wait until the 1-minute load average falls below ``threshold`` (or give up); return the wait."""
    t0 = time.monotonic()
    while os.getloadavg()[0] >= threshold and time.monotonic() - t0 < max_wait_s:
        time.sleep(poll_s)
    return round(time.monotonic() - t0, 1)


def collect(wait_quiet: bool = False) -> dict:
    waited = wait_until_quiet() if wait_quiet else 0.0
    return {
        'run_conditions': dict(_run_conditions(), waited_for_quiet_s=waited),
        'timestamp_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'python': platform.python_version(),
        'python_implementation': platform.python_implementation(),
        'platform': platform.platform(),
        'kernel': platform.release(),
        'machine': platform.machine(),
        'cpu_model': _cpu_model(),
        'cpu_count_logical': os.cpu_count(),
        'mem_total_mib': _mem_total_mib(),
        **_liboqs_build(),
        'sig_algorithm': 'ML-DSA-65',
        'kem_algorithm': 'ML-KEM-768',
        'hash_algorithm': 'SHA-384',
        'sqlite': __import__('sqlite3').sqlite_version,
    }


if __name__ == '__main__':
    info = collect()
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'w') as fh:
            json.dump(info, fh, indent=2)
    print(json.dumps(info, indent=2))
