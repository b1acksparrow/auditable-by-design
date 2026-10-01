#!/usr/bin/env bash
# Reproduce the artifact: tests -> (optional) benchmarks -> tables -> PDF.
#   ./build.sh            tests + tables + PDF (uses retained results/v2)
#   ./build.sh --bench    additionally re-runs the timing, scaling and zero-knowledge benchmarks
#                         (the 100k scaling size takes ~15-20 min; run on AC power with other
#                         applications closed -- run conditions are recorded in environment.json)
# The zero-knowledge tests and benchmark need zk/ built first: (cd zk && cargo build --release).
# The advisor evaluation (bench/advisor_eval.py) calls a language model and is run separately.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p results/v2
ZK_HOST=zk/target/release/abd-zk-host
if [[ -x "$ZK_HOST" ]]; then
  export ABD_ZK=1
fi
HAVE_TLS=0
if command -v nginx >/dev/null && command -v openssl >/dev/null; then
  export ABD_TLS=1
  HAVE_TLS=1
fi
# Benchmarks run first, on a quiet machine: the zero-knowledge test below runs a multi-core proof.
# Each benchmark waits for the load to settle and records its own run conditions.
if [[ "${1:-}" == "--bench" ]]; then
  python3 bench/envinfo.py results/v2/environment.json >/dev/null
  python3 bench/bench_timing.py results/v2 >/dev/null
  python3 bench/bench_wal.py results/v2/wal
  python3 bench/bench_scaling.py results/v2
  if [[ -x "$ZK_HOST" ]]; then
    python3 bench/bench_zk.py results/v2/zk 3
  fi
  if [[ "$HAVE_TLS" == 1 ]]; then
    python3 bench/bench_tls.py results/v2/tls 10
  fi
fi
python3 -m pytest --junitxml=results/v2/junit.xml
python3 paper/gen_tables.py >/dev/null
python3 paper/assemble.py
latex() { pdflatex -interaction=nonstopmode -halt-on-error "$1.tex" >/dev/null; }
# main text and supplement cross-reference each other (xr-hyper), so each is compiled after the other
( cd paper && latex auditable-by-design && latex supplement && latex auditable-by-design \
            && latex supplement && latex auditable-by-design && latex arxiv && latex arxiv )
echo "PDFs: paper/auditable-by-design.pdf (submission), paper/supplement.pdf, paper/arxiv.pdf (extended)"
