#!/bin/bash
cd "$(dirname "$0")/.."
exec python3 bench/bench_scaling.py results/v2
