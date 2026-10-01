"""Confidential policy predicate binding (Section VI, Eq. 3-5).

Implemented here:
  * a hash commitment
      Com(m; r) = SHA-384("ABD/v2/commitment" || 0x00 || u16be(|r|) || r || m)
    with 32-byte r (binding under collision resistance; hiding modelled as
    random-oracle, stated explicitly -- Section VI-C);
  * C_v = Com(Enc(v, theta); r)                                     Eq. (3)
  * a signed policy registration (policy authority) covering C_v, predicate id,
    applicable assets, validity period and the maximum source measurement age;
  * X_i = Com(Enc(kappa_i, x_i); r_i) with a signed source attestation   Eq. (4)
  * D_i = H(Enc(action, a_i)), the same action digest used by the authorization
    and receipt, so the public statement is bound to the transaction;
  * the public statement (C_v, X_i, kappa_i, D_i, v, predicate_id, q_i) and the
    relation R of Eq. (5) checked by *opening* the commitments.

Two ways to check R:
  * the reviewer path opens the commitments (``relation_holds``); it reveals
    theta and x_i and is suitable only for an authorised policy reviewer;
  * ``RiscZeroBackend`` proves R with the RISC Zero zkVM: the relation is a
    guest program (zk/methods/guest), the proof is a hash-based STARK
    recursion ("succinct") receipt, and the guest's image identifier is part
    of the signed policy registration, so a proof produced by any other
    program is rejected.  RISC Zero states that its STARK receipts are not
    known to be vulnerable to quantum attacks and that it targets, but has not
    proven, perfect zero-knowledge; zero-knowledge is therefore a stated
    assumption here.  The verifier accepts only a succinct receipt lifted from
    one segment of at most 2^19 cycles; by the vendor's soundness calculator
    (``abd-zk-host soundness``), the end-to-end soundness of such a receipt is
    98.0 bits under the vendor's toy-model conjecture, 76.8 bits under the
    strict conjecture and 43.5 bits proven (the recursion layer alone has
    99.8 bits in the toy model).  Groth16 receipts (not post-quantum) are
    never produced.
    Succinct-only does not hide the execution length: the receipt's public
    control id reveals the segment-count class (join for two or more segments)
    and, for one segment, the lift program of its padded power-of-two cycle
    count.
"""

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass

from . import crypto

COMMIT_RAND_BYTES = 32


def commit(message: bytes, r: bytes) -> str:
    if len(r) != COMMIT_RAND_BYTES:
        raise ValueError('commitment randomness must be 32 bytes')
    return crypto.domain_digest_hex(crypto.DOMAIN_COMMITMENT, len(r).to_bytes(2, 'big') + r + message)


def fresh_randomness() -> bytes:
    return os.urandom(COMMIT_RAND_BYTES)


# --- predicate catalogue ----------------------------------------------------
def _field(obj, key: str, kind, name: str):
    """obj[key] if it has type ``kind`` (a bool is not an int), else ValueError -- as strict as the guest."""
    v = obj.get(key) if isinstance(obj, dict) else None
    if not isinstance(v, kind) or isinstance(v, bool):
        kinds = kind if isinstance(kind, tuple) else (kind,)
        raise ValueError(f"{name} must be of type {'/'.join(k.__name__ for k in kinds)}")
    return v


def _pred_rotation_threshold(theta: dict, x: dict, a: dict) -> bool:
    """Q: rotation permitted iff key age >= confidential minimum and the action is a permitted profile.

    As in the guest, list entries that are not strings never match."""
    age = _field(x, 'key_age_days', int, 'x.key_age_days')
    minimum = _field(theta, 'min_key_age_days', int, 'theta.min_key_age_days')
    permitted = _field(theta, 'permitted_profiles', (list, tuple), 'theta.permitted_profiles')   # same encoding
    target = _field(a, 'target_profile_id', str, 'action.target_profile_id')
    return age >= minimum and target in permitted


PREDICATES = {
    'rotation_threshold_v1': _pred_rotation_threshold,
}


def evaluate(predicate_id: str, theta: dict, x: dict, a: dict) -> bool:
    """Q_{v,theta}(x, a); raises ValueError where the guest would panic (unknown predicate, off-schema input)."""
    if predicate_id not in PREDICATES:
        raise ValueError(f'unknown predicate {predicate_id!r}')
    return bool(PREDICATES[predicate_id](theta, x, a))


# --- Eq. (3): policy commitment and registration ----------------------------
@dataclass
class PolicyCommitment:
    predicate_id: str
    version: int
    theta: dict           # confidential
    r: bytes              # confidential opening
    C_v: str

    @classmethod
    def create(cls, predicate_id: str, version: int, theta: dict) -> 'PolicyCommitment':
        r = fresh_randomness()
        C_v = commit(crypto.encode({'v': version, 'theta': theta}), r)
        return cls(predicate_id, version, theta, r, C_v)


def register_policy(authority: crypto.RoleSigner, pc: PolicyCommitment, applicable_assets: list,
                    valid_from: int, valid_to: int, max_measurement_age_s: int, reviewer_ref: str | None = None,
                    program_id: str | None = None) -> dict:
    """``program_id`` is the image identifier of the zkVM program that implements the predicate;
    ``max_measurement_age_s`` caps the freshness limit a source may declare."""
    stmt = {
        'schema': 'policy_registration_v2',
        'role': 'policy_authority',
        'predicate_id': pc.predicate_id,
        'version': pc.version,
        'commitment': pc.C_v,
        'predicate_program_id': program_id,
        'applicable_assets': sorted(applicable_assets),
        'valid_from': valid_from,
        'valid_to': valid_to,
        'max_measurement_age_s': max_measurement_age_s,
        'reviewer_approval_ref': reviewer_ref,
        'timestamp': valid_from,
    }
    return authority.sign_statement(stmt)


# --- Eq. (4): source commitment to its own measurement ---------------------
@dataclass
class SourceCommitment:
    kappa: dict
    x: dict               # confidential measurement
    r_i: bytes
    X_i: str
    attestation: dict     # signed by source observer


def source_commit(source: crypto.RoleSigner, kappa: dict, x: dict, freshness_limit_s: int, now: int) -> SourceCommitment:
    """The source measures x itself, commits to it and signs the binding.
    It does not sign opaque commitments supplied by a prover."""
    r_i = fresh_randomness()
    X_i = commit(crypto.encode({'kappa': kappa, 'x': x}), r_i)
    stmt = {
        'schema': 'source_commitment_attestation_v2',
        'role': 'source_observer',
        'tx_id': kappa['tx_id'],
        'kappa': kappa,
        'commitment': X_i,
        'measurement_semantics': 'key_age_days:int',
        'source_id': source.key_id,
        'captured_at': now,
        'freshness_limit_s': freshness_limit_s,
    }
    return SourceCommitment(kappa, x, r_i, X_i, source.sign_statement(stmt))


# --- Eq. (5): public statement, witness and relation ------------------------
@dataclass
class PublicStatement:
    C_v: str
    X_i: str
    kappa: dict
    D_i: str
    v: int
    predicate_id: str
    q_i: bool

    def to_json(self) -> dict:
        return {'C_v': self.C_v, 'X_i': self.X_i, 'kappa': self.kappa, 'D_i': self.D_i,
                'v': self.v, 'predicate_id': self.predicate_id, 'q_i': self.q_i}


@dataclass
class Witness:
    theta: dict
    r: bytes
    x: dict
    r_i: bytes
    a: dict


def relation_holds(stmt: PublicStatement, w: Witness) -> bool:
    """R of Eq. (5), evaluated with the witness in the clear."""
    try:
        if commit(crypto.encode({'v': stmt.v, 'theta': w.theta}), w.r) != stmt.C_v:
            return False
        if commit(crypto.encode({'kappa': stmt.kappa, 'x': w.x}), w.r_i) != stmt.X_i:
            return False
        if crypto.action_digest_hex(w.a) != stmt.D_i:
            return False
    except (ValueError, TypeError):   # an opening outside the canonical value space cannot satisfy R
        return False
    try:
        return evaluate(stmt.predicate_id, w.theta, w.x, w.a) == stmt.q_i
    except ValueError:   # off-schema witness: the guest panics, so no proof exists either
        return False


class Prover:
    """Trusted evaluator/prover holding the witness (Section VI-A)."""

    def __init__(self, pc: PolicyCommitment):
        self.pc = pc

    def statement(self, sc: SourceCommitment, action: dict) -> tuple[PublicStatement, Witness]:
        q = evaluate(self.pc.predicate_id, self.pc.theta, sc.x, action)
        stmt = PublicStatement(self.pc.C_v, sc.X_i, sc.kappa, crypto.action_digest_hex(action),
                               self.pc.version, self.pc.predicate_id, q)
        return stmt, Witness(self.pc.theta, self.pc.r, sc.x, sc.r_i, action)


class ZKBackend:
    """Interface for a zero-knowledge argument of R."""

    def prove(self, stmt: PublicStatement, w: Witness) -> bytes:
        raise NotImplementedError('the interface has no proof system; use RiscZeroBackend')

    def verify(self, stmt: PublicStatement, proof: bytes, program_id: str) -> bool:
        raise NotImplementedError('the interface has no proof system; use RiscZeroBackend')


DEFAULT_ZK_HOST = os.path.join(os.path.dirname(__file__), '..', 'zk', 'target', 'release', 'abd-zk-host')


class RiscZeroBackend(ZKBackend):
    """Proves R with the RISC Zero zkVM through the ``abd-zk-host`` program (see zk/).

    The guest program recomputes both commitments and the action digest from the
    witness, evaluates the predicate, and commits the canonical encoding of the
    public statement as its journal; nothing else leaves the prover.  Proving is
    local and in-process, since whoever runs the prover sees the witness."""

    def __init__(self, host: str = DEFAULT_ZK_HOST, timeout_s: int = 3600):
        self.host = os.path.abspath(host)
        self.timeout_s = timeout_s
        self.last_stats: dict | None = None

    def available(self) -> bool:
        return os.access(self.host, os.X_OK)

    # fake proofs, or proving outside this process (r0vm), are never requested
    _STRIPPED_ENV = ('RISC0_DEV_MODE', 'RISC0_PROVER', 'RISC0_SERVER_PATH')

    def _run(self, *args) -> dict:
        env = {k: v for k, v in os.environ.items() if k not in self._STRIPPED_ENV}
        out = subprocess.run([self.host, *args], capture_output=True, text=True, timeout=self.timeout_s, env=env)
        if out.returncode != 0:
            raise RuntimeError(f'abd-zk-host {args[0]} failed: {out.stderr.strip()[-500:]}')
        return json.loads(out.stdout)

    def soundness(self) -> dict:
        """Security levels (bits) from RISC Zero's own soundness calculator, per segment size and for recursion."""
        return self._run('soundness')

    def program_id(self) -> str:
        return self._run('image-id')['image_id']

    @staticmethod
    def witness_json(stmt: PublicStatement, w: Witness) -> dict:
        return {'v': stmt.v, 'predicate_id': stmt.predicate_id, 'theta': w.theta, 'r': w.r.hex(), 'x': w.x,
                'r_i': w.r_i.hex(), 'kappa': stmt.kappa, 'action': w.a}

    def _write_witness(self, d: str, stmt: PublicStatement, w: Witness) -> str:
        wpath = os.path.join(d, 'witness.json')
        with open(wpath, 'w') as fh:
            json.dump(self.witness_json(stmt, w), fh)
        return wpath

    def execute(self, stmt: PublicStatement, w: Witness) -> dict:
        """Runs the guest without proving; returns journal_hex, cycle counts and the segment count."""
        with tempfile.TemporaryDirectory(prefix='abd-zk-') as d:
            return self._run('execute', self._write_witness(d, stmt, w))

    def prove(self, stmt: PublicStatement, w: Witness) -> bytes:
        with tempfile.TemporaryDirectory(prefix='abd-zk-') as d:
            wpath, rpath = self._write_witness(d, stmt, w), os.path.join(d, 'receipt.bin')
            self.last_stats = self._run('prove', wpath, rpath)
            with open(rpath, 'rb') as fh:
                return fh.read()

    def verify(self, stmt: PublicStatement, proof: bytes, program_id: str) -> bool:
        """True iff the receipt verifies for ``program_id`` and its journal is exactly the public statement."""
        with tempfile.TemporaryDirectory(prefix='abd-zk-') as d:
            rpath = os.path.join(d, 'receipt.bin')
            with open(rpath, 'wb') as fh:
                fh.write(proof)
            try:
                res = self._run('verify', rpath, program_id)
            except RuntimeError:
                return False
        return res.get('verified') is True and bytes.fromhex(res['journal_hex']) == crypto.encode(stmt.to_json())


def verify_bound_statement(stmt: PublicStatement, registration: dict, sc_attestation: dict,
                           authorization: dict, trust: crypto.TrustConfig, now: int,
                           opening: Witness | None = None, proof: bytes | None = None,
                           backend: ZKBackend | None = None) -> tuple[bool, str]:
    """Verifier-side checks of Section VI-B.

    Checks: the policy registration is signed by the policy authority, current,
    and its commitment equals C_v; the source attestation is signed, fresh
    (within the smaller of its own limit and the registration's
    max_measurement_age_s) and its commitment equals X_i; kappa matches; the
    signed authorization (authorizer key trusted at its timestamp, schema
    authorization_v2, decision 'authorized') covers kappa's transaction and
    asset with target_config_digest == D_i; then either the zero-knowledge proof
    verifies for the registered predicate program (external verifier), or, if
    an opening is supplied (reviewer path), R holds.  Fails closed when neither
    is supplied.
    """
    ok, why = trust.verify_signed('policy_authority', registration, registration['statement'].get('timestamp'))
    if not ok:
        return False, f'registration: {why}'
    reg = registration['statement']
    if reg['commitment'] != stmt.C_v or reg['predicate_id'] != stmt.predicate_id or reg['version'] != stmt.v:
        return False, 'statement commitment/predicate/version not covered by registration'
    if not (reg['valid_from'] <= now <= reg['valid_to']):
        return False, 'registration not valid at this time'
    if stmt.kappa['asset_id'] not in reg['applicable_assets']:
        return False, 'asset not covered by registration'
    cap = reg.get('max_measurement_age_s')
    if not isinstance(cap, int) or isinstance(cap, bool) or cap < 0:
        return False, 'registration sets no maximum measurement age'
    ok, why = trust.verify_signed('source_observer', sc_attestation, sc_attestation['statement'].get('captured_at'))
    if not ok:
        return False, f'source attestation: {why}'
    att = sc_attestation['statement']
    if att['commitment'] != stmt.X_i or att['kappa'] != stmt.kappa:
        return False, 'source attestation does not bind X_i to kappa'
    if not (0 <= now - att['captured_at'] <= min(att['freshness_limit_s'], cap)):
        return False, 'source measurement stale or from the future'
    ok, why = trust.verify_signed('authorizer', authorization, authorization.get('statement', {}).get('timestamp'))
    if not ok:
        return False, f'authorization: {why}'
    auth = authorization['statement']
    if auth.get('schema') != 'authorization_v2':
        return False, f"authorization: unexpected schema {auth.get('schema')!r}"
    if auth.get('decision') != 'authorized':
        return False, f"authorization: decision is {auth.get('decision')!r}"
    if (auth.get('tx_id') != stmt.kappa['tx_id'] or auth.get('asset_id') != stmt.kappa['asset_id']
            or auth.get('target_config_digest') != stmt.D_i):
        return False, 'public statement not bound to the authorized action'
    if proof is not None:
        program_id = reg.get('predicate_program_id')
        if not program_id:
            return False, 'registration names no predicate program'
        if backend is None or not backend.verify(stmt, proof, program_id):
            return False, 'zero-knowledge proof rejected'
        return True, 'ok (zero-knowledge proof verified for the registered predicate program)'
    if opening is not None:
        if not relation_holds(stmt, opening):
            return False, 'relation R does not hold for the supplied opening'
        return True, 'ok (opening verified by reviewer)'
    return False, 'no proof or opening supplied: relation R not checked'
