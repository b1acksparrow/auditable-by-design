# Auditable by Design — reference implementation and artifact

Reference implementation, measurements and manuscript sources for
*Auditable by Design: Secure AI-Assisted Migration to Post-Quantum Cryptography*
(Sergey Mkrtchyan, 2026).

```
abd/            the package (see abd/__init__.py for the module map)
tests/          regression suite (pytest)
bench/          drivers: creation-cost decomposition, archive-verification scaling, WAL, earlier
                checker, RISC Zero proving, TLS observation, LLM advisor evaluation, environment capture
zk/             RISC Zero guest and host for the confidential-predicate relation
results/v2/     retained measurements: environment.json, timing_*.json, scaling_results.json, junit.xml,
                advisor-*/ (prompts, transcripts, trials, archives), zk/, tls/, wal/, oldchecker/
paper/          IEEEtran manuscript; paper/assemble.py builds the main text, the supplement and the
                extended version from paper/sections/, and paper/gen_tables.py builds the tables from results/v2
submission/     compiled PDFs (main text, supplementary material, extended version) and the arXiv source
prototype/      the earlier record-construction fixture (superseded; kept for comparison)
results/*.json  earlier fixture measurements (superseded)
```

## Requirements

* Python 3.12+, `liboqs-python` 0.16 (ML-KEM-768, ML-DSA-65), `pytest` (`pip install -r requirements.txt`;
  without a system liboqs, `liboqs-python` builds liboqs into `~/_oqs` on first import, which needs git,
  CMake and a C compiler)
* `pdflatex` with `IEEEtran.cls` (a copy is in `paper/`) for the manuscript
* Optional, for the zero-knowledge tests and benchmark: a Rust toolchain and the RISC Zero toolchain
  matching `risc0-zkvm` 3.0.6; build with `cargo build --release` in `zk/` (produces
  `zk/target/release/abd-zk-host`), then run with `ABD_ZK=1`
* Optional, for the TLS observation tests and benchmark: `nginx` and `openssl`, run with `ABD_TLS=1`
* Optional, for `bench/advisor_eval.py`: the Claude Code command-line interface with a logged-in account

## Reproduce

```bash
./build.sh            # tests -> tables -> PDFs using the retained results
./build.sh --bench    # also re-runs the benchmarks (the 100,000-transaction size takes ~15 min)
python3 -m pytest -v  # the regression suite alone
```

`results/v2/archives/` (about 5 GB of scaling archives) is not in the repository; `./build.sh --bench`
regenerates it with `bench/bench_scaling.py`.

Advisor runs: each trial's archive, retained checkpoint and trust configuration are in
`results/v2/advisor-*/advisor_archives/` (the hardened run has no per-trial archives). In the retained
`trials.jsonl` files the `archive` field still reads `archives/<name>`; the directory was renamed so that
it is never confused with the scaling benchmark's `archives/`.

## What the implementation enforces

* **Policy gate, Eq. (1)** — `Fresh`, `Allowed_v`, `Compatible`, `Authorized` as separate
  conjuncts with structured reasons; all four are re-evaluated by the executor against the
  then-current state immediately before the change. `Fresh` compares the whole observed
  snapshot (version, configuration, peer capabilities, implementations) with the current
  state, so a dependency change invalidates an approval; the freshness limit is capped by the
  policy. `Authorized` bounds the approval lifetime by the policy TTL and requires the
  permitted recovery target to meet the security floor (or to be service isolation).
* **Durable one-time consumption** — the authorization digest and the execution-attempt
  journal row are committed together (SQLite, WAL, `synchronous=FULL`) before any change;
  the compare-and-set on the state version and the `applied` mark are one commit.
* **Independent outcome observation** — the outcome observer reads the authoritative state
  through a separate read-only SQLite connection (`mode=ro`); it never derives the outcome
  from the receipt.
* **Reconciliation** — a crash after `apply` leaves an unresolved transaction that the
  reconciler resolves from journal + state (late receipt); a crash before `apply` is marked
  failed with the authorization consumed. Absence of a receipt is never taken as absence of
  change. While an attempt is unresolved, new changes to that asset are refused; if the
  unresolved transaction was already archived, its resolution is appended as one further
  record for the same transaction, which the verifier accepts exactly once.
* **Evidence chain, Eq. (2)** — versioned, domain-separated SHA-384 chain; witness
  checkpoints retained outside the archive.
* **Streaming semantic verifier** — all thirteen obligations of the paper, including
  `Compatible` recomputed from the signed snapshot and key validity checked for every role.
  Memory grows linearly with the number of transactions (retained identifier and digest
  sets), not with record size.
* **Confidential predicate binding, Eq. (3)-(5)** — commitments, signed registration and
  attestation, a public statement bound to the authorized action, and a RISC Zero guest
  program (`zk/`) that proves the relation. Soundness is the vendor's conjectured level;
  zero knowledge is assumed, not proven (see the paper).
* **LLM advisor** (`abd/llm_advisor.py`, `bench/advisor_eval.py`) — Claude Sonnet 5 through the
  Claude Code CLI on synthetic scenarios with planted attack prose, under hardened and naive
  prompts, plus a scripted compromised proposer.
* **Wire-level TLS observation** (`abd/tls_probe.py`, `bench/bench_tls.py`) — a four-client panel
  that reads the key-exchange group a local nginx TLS 1.3 service negotiates with each client.

## What it does not establish

One host; all roles in one process, so role keys separate provenance, not authority; local
SQLite state; an ML-KEM-768 round trip as the governed operation; keys not hardware-protected
and no validated cryptographic module; observers not administratively independent of the
executor; witness checkpoints held in process memory; durability tested only with injected
faults. ML-DSA-65 and ML-KEM-768 are below CNSA 2.0 (ML-DSA-87, ML-KEM-1024). The TLS panel
is a standalone loopback experiment, and one advisor model was evaluated. See Section IX
(Limitations) of the paper.

## Privacy redaction

The Claude Code CLI adds context of its own to the model input, even with a replaced system
prompt, and that context is not part of the recorded prompt. It included the e-mail address of
the account used for the advisor runs, and in one naive-prompt benign trial
(`benign:s014:none:r0`) the model repeated that address in its rationale. The address is replaced
by `[redacted-email]` in `results/v2/advisor-naive/transcripts.jsonl`, `trials.jsonl` and
`advisor_archives/benign_s014_none_r0.json`. The proposal digest covers the rationale, so that one
archive no longer verifies against its signed digests; it verified at run time
(`archive_verified` in `trials.jsonl`). Nothing else was changed.

## License

The code, drivers and measurement data are released under the Apache License 2.0 (`LICENSE`).
The manuscript (`paper/`, `submission/`) is the author's preprint; all rights reserved by the
author. `paper/IEEEtran.cls` is distributed under the LaTeX Project Public License.

## Citation

```bibtex
@misc{mkrtchyan2026auditable,
  author = {Sergey Mkrtchyan},
  title  = {Auditable by Design: Secure {AI}-Assisted Migration to Post-Quantum Cryptography},
  year   = {2026},
  note   = {Manuscript},
  url    = {https://github.com/b1acksparrow/auditable-by-design}
}
```
