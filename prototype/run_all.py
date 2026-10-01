"""
Master runner: executes all benchmarks and generates the report.
"""

import json
import os
import sys
import time
import platform

RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

# System info
sysinfo = {
    'python': platform.python_version(),
    'platform': platform.platform(),
    'machine': platform.machine(),
    'processor': platform.processor(),
    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
}
print(f"System: {sysinfo['platform']}, Python {sysinfo['python']}")

# Save system info
with open(os.path.join(RESULTS_DIR, 'system_info.json'), 'w') as f:
    json.dump(sysinfo, f, indent=2)

# Task 2: Timing decomposition
print("\n" + "=" * 70)
print("TASK 2: Timing Decomposition")
print("=" * 70)
from benchmark_timing import run_benchmark
timing_results = run_benchmark(RESULTS_DIR)

# Task 3: Verification scaling (skip 100k to avoid hanging)
print("\n" + "=" * 70)
print("TASK 3: Verification Scaling")
print("=" * 70)
import benchmark_scaling
benchmark_scaling.SIZES = [10, 100, 1_000, 10_000]
benchmark_scaling.TIMED = 50  # reduce for 10k to keep runtime sane
scaling_results = benchmark_scaling.run_scaling(RESULTS_DIR)

print("\n\nAll benchmarks complete. Results in:", RESULTS_DIR)
