"""Streaming semantic verifier for an evidence archive (Sections IV-V).

The verifier consumes records one at a time.  It retains the previous chain
head, the last completed version per asset, and the sets of transaction
identifiers and authorization digests seen so far.  Memory therefore grows
linearly with the number of transactions (about 0.9 KiB each in the measured
run; see results/v2 scaling), not with record size, so a 100,000-transaction
archive can be checked without loading it into memory.

Explicit verifier inputs (never taken from the archive):
  * trust configuration (role public keys with validity periods),
  * public policy registry (allowlists per version),
  * the independently retained checkpoint,
  * the expected log identity, the reference time and the checkpoint bound Delta.
"""

import json
from dataclasses import dataclass, field

from . import crypto
from .policy import PolicyRegistry, compatibility, meets_floor, recovery_permitted

ACCEPTED_SCHEMAS = {
    'source': 'source_observation_v2',
    'authorization': 'authorization_v2',
    'executor': 'executor_receipt_v2',
    'outcome': 'outcome_observation_v2',
    'envelope': 'audit_envelope_v2',
    'checkpoint': 'checkpoint_v2',
}
ROLE_OF = {
    'source': 'source_observer',
    'authorization': 'authorizer',
    'executor': 'executor',
    'outcome': 'outcome_observer',
    'envelope': 'evidence_service',
    'checkpoint': 'checkpoint_witness',
}
STATUSES_WITH_RECEIPT = {'closed', 'recovered'}
STATUSES_WITHOUT_RECEIPT = {'rejected'}
STATUSES_MAYBE_RECEIPT = {'failed', 'unresolved'}
KNOWN_STATUSES = STATUSES_WITH_RECEIPT | STATUSES_WITHOUT_RECEIPT | STATUSES_MAYBE_RECEIPT
# A transaction recorded as 'unresolved' may be followed by exactly one resolution record.
RESOLUTION_STATUSES = {'recovered', 'failed'}


class VerificationFailure(Exception):
    def __init__(self, index, tx_id, check, detail):
        super().__init__(f'record {index} tx {tx_id}: {check}: {detail}')
        self.index, self.tx_id, self.check, self.detail = index, tx_id, check, detail


@dataclass
class VerificationResult:
    ok: bool
    failures: list = field(default_factory=list)
    records: int = 0
    closed: int = 0
    rejected: int = 0
    other: int = 0
    signatures_checked: int = 0
    final_head: str | None = None
    checks: int = 0

    def to_json(self) -> dict:
        return {'ok': self.ok, 'failures': self.failures, 'records': self.records, 'closed': self.closed,
                'rejected': self.rejected, 'other': self.other, 'signatures_checked': self.signatures_checked,
                'final_head': self.final_head, 'checks': self.checks}


def iter_jsonl(path: str):
    with open(path, 'r', encoding='utf-8') as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


class ArchiveVerifier:
    def __init__(self, trust: crypto.TrustConfig, registry: PolicyRegistry, log_id: str,
                 retained_checkpoint: dict | None, now: int, delta_s: int,
                 collect_all: bool = False):
        self.trust = trust
        self.registry = registry
        self.log_id = log_id
        self.retained_checkpoint = retained_checkpoint
        self.now = now
        self.delta_s = delta_s
        self.collect_all = collect_all
        # retained state: linear in transactions, independent of record size
        self._seen_tx: set = set()
        self._seen_auth: set = set()
        self._asset_version: dict = {}
        self._unresolved: dict = {}          # tx_id -> authorization digest awaiting a resolution record
        self._prev_head = crypto.GENESIS_HEAD
        self._expected_index = 0
        self._last_envelope_time = 0
        self.result = VerificationResult(ok=True)

    # --- helpers -----------------------------------------------------------
    def _fail(self, index, tx_id, check, detail):
        f = VerificationFailure(index, tx_id, check, detail)
        self.result.ok = False
        self.result.failures.append(str(f))
        if not self.collect_all:
            raise f

    def _check(self, cond, index, tx_id, check, detail):
        self.result.checks += 1
        if not cond:
            self._fail(index, tx_id, check, detail)
        return cond

    def _verify_signed(self, index, tx_id, section, signed, at_time):
        role = ROLE_OF[section]
        if not isinstance(signed, dict):
            self._fail(index, tx_id, f'{section}.present', 'missing signed section')
            return False
        stmt = signed.get('statement', {})
        self._check(stmt.get('schema') == ACCEPTED_SCHEMAS[section], index, tx_id, f'{section}.schema',
                    f"schema {stmt.get('schema')!r} not accepted")
        # Key validity is judged at the statement's own time, which must therefore be present.
        if not (isinstance(at_time, int) and not isinstance(at_time, bool)):
            self._fail(index, tx_id, f'{section}.time', 'statement time missing or not an integer')
            at_time = -1          # matches no validity window: the signature check then fails closed
        ok, why = self.trust.verify_signed(role, signed, at_time)
        self.result.signatures_checked += 1
        self._check(ok, index, tx_id, f'{section}.signature', why)
        self._check(stmt.get('tx_id') == tx_id, index, tx_id, f'{section}.tx_id',
                    f"signed tx_id {stmt.get('tx_id')!r} != outer {tx_id!r}")
        return ok

    # --- per record --------------------------------------------------------
    def verify_record(self, index: int, rec: dict):
        r = self.result
        r.records += 1
        tx_id = rec.get('tx_id')
        status = rec.get('status')
        self._check(rec.get('schema') == 'transaction_record_v2', index, tx_id, 'record.schema', 'unexpected record schema')
        self._check(isinstance(tx_id, str) and len(tx_id) == 36, index, tx_id, 'record.tx_id', 'malformed tx_id')
        self._check(status in KNOWN_STATUSES, index, tx_id, 'record.status', f'unknown status {status!r}')
        # A repeated identifier is accepted only as the single resolution of an earlier 'unresolved' record.
        resolving = tx_id in self._seen_tx and tx_id in self._unresolved
        self._check(tx_id not in self._seen_tx or resolving, index, tx_id, 'record.unique_tx',
                    'transaction id repeated in archive')
        self._seen_tx.add(tx_id)

        # -- envelope first: it authenticates which sections must exist -------
        env = rec.get('envelope')
        env_time = env.get('statement', {}).get('timestamp') if isinstance(env, dict) else None
        self._verify_signed(index, tx_id, 'envelope', env, env_time)
        e = env['statement'] if isinstance(env, dict) else {}
        self._check(e.get('log_id') == self.log_id, index, tx_id, 'envelope.log_id',
                    f"log {e.get('log_id')!r} != expected {self.log_id!r}")
        self._check(e.get('index') == index, index, tx_id, 'envelope.index', f"index {e.get('index')} != position {index}")
        self._check(e.get('chain_prev') == self._prev_head, index, tx_id, 'envelope.chain_prev', 'chain break')
        self._check(e.get('status') == status, index, tx_id, 'envelope.status', 'outer status differs from signed status')
        self._check(e.get('timestamp', 0) >= self._last_envelope_time, index, tx_id, 'envelope.time_monotonic',
                    'envelope timestamp decreased')
        self._last_envelope_time = e.get('timestamp', self._last_envelope_time)
        head = crypto.chain_hash_hex(index, self._prev_head, e) if e else None
        self._check(rec.get('chain_hash') == head, index, tx_id, 'envelope.chain_hash', 'recomputed chain hash differs')

        # -- source observation ---------------------------------------------
        src = rec.get('source')
        self._verify_signed(index, tx_id, 'source', src, src.get('statement', {}).get('captured_at') if src else None)
        s = src['statement'] if src else {}
        self._check(src and src['digest'] == e.get('source_digest'), index, tx_id, 'envelope.binds_source', 'source digest mismatch')
        snap = s.get('snapshot', {})
        self._check(crypto.snapshot_digest_hex(snap) == s.get('snapshot_digest'), index, tx_id, 'source.snapshot_digest',
                    'snapshot digest mismatch')
        asset_id = rec.get('asset_id')
        self._check(snap.get('asset_id') == asset_id, index, tx_id, 'source.asset', 'observed asset differs from record asset')

        # -- proposal (advisory, unsigned, digest-bound) ---------------------
        prop = rec.get('proposal')
        pdig = crypto.action_digest_hex(prop) if isinstance(prop, dict) else None
        self._check(pdig == e.get('proposal_digest'), index, tx_id, 'envelope.binds_proposal', 'proposal digest mismatch')
        self._check(prop.get('tx_id') == tx_id and prop.get('asset_id') == asset_id, index, tx_id, 'proposal.binding',
                    'proposal transaction or asset differs')
        self._check(any(ref.get('digest') == src['digest'] for ref in prop.get('evidence_refs', [])),
                    index, tx_id, 'proposal.evidence_ref', 'proposal does not reference the observation')

        # -- authorization ----------------------------------------------------
        auth = rec.get('authorization')
        self._verify_signed(index, tx_id, 'authorization', auth, auth.get('statement', {}).get('timestamp') if auth else None)
        a = auth['statement'] if auth else {}
        self._check(auth and auth['digest'] == e.get('authorization_digest'), index, tx_id, 'envelope.binds_authorization',
                    'authorization digest mismatch')
        self._check(a.get('source_record_digest') == src['digest'], index, tx_id, 'authorization.binds_source',
                    'authorization does not bind the observation')
        self._check(a.get('target_config_digest') == pdig, index, tx_id, 'authorization.binds_proposal',
                    'authorization does not cover this exact proposal')
        self._check(a.get('asset_id') == asset_id, index, tx_id, 'authorization.asset', 'authorization asset differs')
        self._check(a.get('expected_state_version') == snap.get('state_version'), index, tx_id,
                    'authorization.expected_version', 'expected version differs from observed version')
        policy = self.registry.get(a.get('policy_version'))
        self._check(policy is not None, index, tx_id, 'authorization.policy_version',
                    f"unknown policy version {a.get('policy_version')}")
        if policy is not None:
            self._check(a.get('policy_digest') == policy.digest(), index, tx_id, 'authorization.policy_digest',
                        'policy digest differs from registry')
        decision = a.get('decision')
        if resolving:
            self._check(status in RESOLUTION_STATUSES, index, tx_id, 'record.resolution_status',
                        f'resolution of an unresolved transaction has status {status!r}')
            self._check(auth and auth['digest'] == self._unresolved.pop(tx_id, None), index, tx_id,
                        'record.resolution_binding', 'resolution record carries a different authorization')

        if decision == 'authorized':
            # freshness at authorization time (a denial may legitimately record a stale observation);
            # the cited policy bounds the limit, an observation can only tighten it
            limit = s.get('freshness_limit_s', -1)
            if policy is not None:
                limit = min(limit, policy.freshness_limit_s)
            age = a.get('timestamp', 0) - s.get('captured_at', 0)
            self._check(0 <= age <= limit, index, tx_id, 'authorization.freshness',
                        f'observation age at authorization {age}s outside limit {limit}s')
            self._check(policy is not None and prop.get('target_profile_id') in policy.allowlist, index, tx_id,
                        'authorization.allowed', 'authorized profile not on allowlist for that policy version')
            # the rest of Allowed_v(a_i): permitted action, the proposal cites the same policy version,
            # and the authorization names the proposal's target profile
            self._check(policy is not None and prop.get('action') in policy.permitted_actions, index, tx_id,
                        'authorization.action', f"action {prop.get('action')!r} not permitted by the cited policy")
            self._check(prop.get('policy_version') == a.get('policy_version'), index, tx_id,
                        'authorization.proposal_policy_version', 'proposal cites a different policy version')
            self._check(a.get('target_profile_id') == prop.get('target_profile_id'), index, tx_id,
                        'authorization.target_profile', 'authorization names a different target profile')
            if policy is not None:
                lifetime = a.get('expires_at', 0) - a.get('timestamp', 0)
                self._check(lifetime <= policy.approval_ttl_s, index, tx_id, 'authorization.ttl',
                            f'authorization lifetime {lifetime}s exceeds policy approval TTL {policy.approval_ttl_s}s')
                ok, why = recovery_permitted(policy, a.get('permitted_recovery'))
                self._check(ok, index, tx_id, 'authorization.recovery', why)
            if policy is not None and prop.get('target_profile_id') in policy.allowlist:
                prof = policy.allowlist[prop['target_profile_id']]
                self._check(prop.get('target_config') == prof.target_config(), index, tx_id, 'authorization.exact_config',
                            'authorized target configuration differs from allowlisted profile')
                self._check(meets_floor(prof, policy), index, tx_id,
                            'authorization.security_floor', 'authorized profile below security floor')
                # Compatible(a_i, x_i) recomputed from the signed snapshot, not taken from the authorizer's gate record
                ok, why = compatibility(prof, snap, prop.get('endpoints', []))
                self._check(ok, index, tx_id, 'authorization.compatible', why)
            self._check(auth['digest'] not in self._seen_auth or resolving, index, tx_id, 'authorization.single_use',
                        'authorization digest already consumed earlier in archive')
            self._seen_auth.add(auth['digest'])
            gate = a.get('gate', {})
            self._check(gate.get('permitted') is True and all(c.get('ok') for c in gate.get('conjuncts', [])),
                        index, tx_id, 'authorization.gate', 'authorized despite failed gate conjunct')
        else:
            self._check(decision == 'denied', index, tx_id, 'authorization.decision', f'unknown decision {decision!r}')
            self._check(status == 'rejected', index, tx_id, 'status.denied_is_rejected',
                        f'denied authorization with status {status!r}')

        # -- executor receipt --------------------------------------------------
        rcpt = rec.get('executor')
        out = rec.get('outcome')
        if status in STATUSES_WITH_RECEIPT:
            self._check(rcpt is not None and out is not None, index, tx_id, 'status.requires_receipt_and_outcome',
                        f'status {status!r} without receipt/outcome')
        if status in STATUSES_WITHOUT_RECEIPT:
            self._check(rcpt is None and out is None, index, tx_id, 'status.rejected_has_no_receipt',
                        'rejected transaction carries a receipt or outcome')
        # The signed envelope fixes which sections exist: a section it binds cannot be removed, and a
        # section it does not bind cannot be added, for every status.
        self._check(e.get('executor_digest') == (rcpt.get('digest') if isinstance(rcpt, dict) else None),
                    index, tx_id, 'envelope.binds_executor', 'receipt present/absent differs from the envelope')
        self._check(e.get('outcome_digest') == (out.get('digest') if isinstance(out, dict) else None),
                    index, tx_id, 'envelope.binds_outcome', 'outcome present/absent differs from the envelope')

        if rcpt is not None:
            self._check(decision == 'authorized', index, tx_id, 'executor.requires_authorization',
                        'receipt present without an authorized decision')
            self._verify_signed(index, tx_id, 'executor', rcpt, rcpt.get('statement', {}).get('timestamp'))
            x = rcpt['statement']
            self._check(x.get('authorization_digest') == auth['digest'], index, tx_id, 'executor.binds_authorization',
                        'receipt does not bind the authorization')
            self._check(x.get('proposal_digest') == pdig, index, tx_id, 'executor.binds_proposal',
                        'receipt does not bind the proposal')
            self._check(x.get('asset_id') == asset_id, index, tx_id, 'executor.asset', 'receipt asset differs')
            self._check(x.get('state_version_before') == a.get('expected_state_version'), index, tx_id,
                        'executor.version_bound', 'receipt before-version differs from authorized expected version')
            self._check(x.get('state_version_after') == x.get('state_version_before', -2) + 1, index, tx_id,
                        'executor.version_increment', 'state version did not increment by one')
            # applied_at is the durable time of the change; a late receipt is issued after it
            applied_at = x.get('applied_at', x.get('timestamp', 0))
            self._check(applied_at <= a.get('expires_at', -1), index, tx_id, 'executor.before_expiry',
                        'execution after authorization expiry')
            self._check(a.get('timestamp', 0) <= applied_at <= x.get('timestamp', 0), index, tx_id,
                        'executor.after_authorization', 'execution before authorization or after its own receipt')
            self._check(x.get('applied_config_digest') == crypto.snapshot_digest_hex(prop.get('target_config')),
                        index, tx_id, 'executor.applied_config', 'applied configuration differs from proposal target')
            op = x.get('operation', {})
            self._check(op.get('algorithm') == crypto.KEM_ALG, index, tx_id, 'executor.operation_algorithm',
                        f"operation algorithm {op.get('algorithm')!r}")
            if not x.get('late_receipt'):
                self._check(op.get('key_agreement') is True, index, tx_id, 'executor.kem_agreement', 'KEM agreement not established')
            # continuity across the archive, per asset
            last = self._asset_version.get(asset_id)
            if last is not None:
                self._check(x.get('state_version_before') == last, index, tx_id, 'executor.continuity',
                            f"before-version {x.get('state_version_before')} != last completed version {last}")
            self._asset_version[asset_id] = x.get('state_version_after')

        if out is not None:
            self._check(rcpt is not None, index, tx_id, 'outcome.requires_receipt', 'outcome without receipt')
            self._verify_signed(index, tx_id, 'outcome', out, out.get('statement', {}).get('observed_at'))
            o = out['statement']
            self._check(o.get('receipt_digest') == rcpt['digest'], index, tx_id, 'outcome.binds_receipt',
                        'outcome does not bind the receipt')
            self._check(o.get('asset_id') == asset_id, index, tx_id, 'outcome.asset', 'outcome asset differs')
            obs = o.get('observed', {})
            self._check(crypto.snapshot_digest_hex(obs.get('config')) == o.get('observed_config_digest'), index, tx_id,
                        'outcome.config_digest', 'observed configuration digest mismatch')
            self._check(o.get('observed_at', 0) >= rcpt['statement'].get('timestamp', 0), index, tx_id,
                        'outcome.after_receipt', 'observation precedes receipt')
            if status in STATUSES_WITH_RECEIPT:
                # A drift-failed transaction legitimately observes a different version and configuration.
                self._check(obs.get('state_version') == rcpt['statement'].get('state_version_after'), index, tx_id,
                            'outcome.version', 'observed version differs from receipt after-version')
                self._check(o.get('observed_profile_id') == prop.get('target_profile_id'), index, tx_id,
                            'outcome.profile_matches_authorized', 'observed profile differs from authorized target')
                self._check(o.get('observed_config_digest') == rcpt['statement'].get('applied_config_digest'), index, tx_id,
                            'outcome.matches_receipt', 'observed configuration differs from receipt')
                hc = o.get('health_checks', {})
                self._check(hc.get('profile_on_allowlist') is True and hc.get('config_matches_profile') is True,
                            index, tx_id, 'outcome.health', 'health checks failed for a closed transaction')

        # -- per-record checkpoint in the archive (informational binding) ------
        cp = rec.get('checkpoint')
        if cp is not None:
            self._verify_signed_checkpoint(index, tx_id, cp, head)

        if status == 'unresolved' and decision == 'authorized' and not resolving:
            self._unresolved[tx_id] = auth['digest']

        if status == 'closed':
            r.closed += 1
        elif status == 'rejected':
            r.rejected += 1
        else:
            r.other += 1
        self._prev_head = head
        self._expected_index = index + 1

    def _verify_signed_checkpoint(self, index, tx_id, cp, head):
        role = ROLE_OF['checkpoint']
        stmt = cp.get('statement', {})
        self._check(stmt.get('schema') == ACCEPTED_SCHEMAS['checkpoint'], index, tx_id, 'checkpoint.schema', 'schema')
        wt = stmt.get('witness_time')
        if not (isinstance(wt, int) and not isinstance(wt, bool)):
            self._fail(index, tx_id, 'checkpoint.time', 'witness time missing or not an integer')
            wt = -1
        ok, why = self.trust.verify_signed(role, cp, wt)
        self.result.signatures_checked += 1
        self._check(ok, index, tx_id, 'checkpoint.signature', why)
        self._check(stmt.get('log_id') == self.log_id, index, tx_id, 'checkpoint.log_id', 'checkpoint for another log')
        self._check(stmt.get('sequence') == index, index, tx_id, 'checkpoint.sequence', 'sequence differs from index')
        self._check(stmt.get('witnessed_head') == head, index, tx_id, 'checkpoint.head', 'witnessed head differs')

    # --- whole archive -----------------------------------------------------
    def finish(self) -> VerificationResult:
        r = self.result
        r.final_head = self._prev_head
        n = self._expected_index
        cp = self.retained_checkpoint
        if cp is None:
            self._fail(n, None, 'checkpoint.retained', 'no independently retained checkpoint supplied')
            return r
        stmt = cp.get('statement', {})
        wt_raw = stmt.get('witness_time')
        if not (isinstance(wt_raw, int) and not isinstance(wt_raw, bool)):
            self._fail(n, None, 'checkpoint.retained.time', 'witness time missing or not an integer')
            wt_raw = -1
        ok, why = self.trust.verify_signed(ROLE_OF['checkpoint'], cp, wt_raw)
        r.signatures_checked += 1
        self._check(ok, n, None, 'checkpoint.retained.signature', why)
        self._check(stmt.get('log_id') == self.log_id, n, None, 'checkpoint.retained.log_id',
                    f"retained checkpoint is for log {stmt.get('log_id')!r}")
        seq = stmt.get('sequence')
        self._check(isinstance(seq, int) and seq == n - 1, n, None, 'checkpoint.retained.sequence',
                    f'retained checkpoint covers sequence {seq}, archive ends at {n - 1}')
        self._check(stmt.get('witnessed_head') == self._prev_head, n, None, 'checkpoint.retained.head',
                    'archive head differs from witnessed head')
        wt = stmt.get('witness_time', 0)
        self._check(wt >= self._last_envelope_time, n, None, 'checkpoint.retained.after_last_envelope',
                    'checkpoint precedes the last envelope')
        self._check(self.now - wt <= self.delta_s, n, None, 'checkpoint.retained.timeliness',
                    f'checkpoint age {self.now - wt}s exceeds Delta {self.delta_s}s')
        self._check(wt <= self.now, n, None, 'checkpoint.retained.not_future', 'checkpoint from the future')
        return r

    def run(self, records) -> VerificationResult:
        i = -1
        try:
            for i, rec in enumerate(records):
                self.verify_record(i, rec)
            return self.finish()
        except VerificationFailure:
            return self.result
        except (KeyError, TypeError, AttributeError, ValueError) as exc:
            # Malformed record: structurally incomplete evidence is a rejection, not a crash.
            self.result.ok = False
            self.result.failures.append(f'record {i}: malformed: {type(exc).__name__}: {exc}')
            return self.result


def verify_archive(records, trust, registry, log_id, retained_checkpoint, now, delta_s,
                   collect_all: bool = False) -> VerificationResult:
    v = ArchiveVerifier(trust, registry, log_id, retained_checkpoint, now, delta_s, collect_all)
    return v.run(records)


def verify_jsonl(path, **kw) -> VerificationResult:
    return verify_archive(iter_jsonl(path), **kw)
