"""Signing roles, digests, trust configuration and the ML-KEM fixture.

Signatures use ML-DSA-65 (FIPS 204) through liboqs.  Every signed statement is
the canonical encoding of a JSON object that carries its own ``schema`` and
``role`` labels; the signature covers the entire encoding.  Digests are SHA-384
and are domain separated by a purpose label so that a digest of an action can
never be confused with a digest of a statement or a chain link.
"""

import hashlib
import hmac
from dataclasses import dataclass, field

import oqs

from . import instrument
from .canonical import canonical_encode

SIG_ALG = 'ML-DSA-65'
KEM_ALG = 'ML-KEM-768'
HASH_ALG = 'sha384'
DIGEST_HEX_LEN = 96

ROLES = (
    'source_observer',
    'authorizer',
    'executor',
    'outcome_observer',
    'evidence_service',
    'checkpoint_witness',
    'policy_authority',
)

# Domain-separation labels (Section V-A / V-B).
DOMAIN_STATEMENT = b'ABD/v2/statement'
DOMAIN_ACTION = b'ABD/v2/action'
DOMAIN_CHAIN = b'ABD/v2/chain'
DOMAIN_COMMITMENT = b'ABD/v2/commitment'
DOMAIN_SNAPSHOT = b'ABD/v2/snapshot'
DOMAIN_TRANSCRIPT = b'ABD/v2/advisor-transcript'
DOMAIN_DOCUMENT = b'ABD/v2/context-document'


def _sha384(data: bytes) -> bytes:
    with instrument.span('hash'):
        return hashlib.sha384(data).digest()


def _hex(data: bytes) -> str:
    with instrument.span('hex'):
        return data.hex()


def encode(obj) -> bytes:
    with instrument.span('canonical'):
        return canonical_encode(obj)


def domain_digest_hex(domain: bytes, data: bytes) -> str:
    return _hex(_sha384(domain + b'\x00' + data))


def statement_digest_hex(statement_bytes: bytes) -> str:
    return domain_digest_hex(DOMAIN_STATEMENT, statement_bytes)


def action_digest_hex(action: dict) -> str:
    """D_i = H(Enc(action, a_i)) -- binds the exact proposed action."""
    return domain_digest_hex(DOMAIN_ACTION, encode(action))


def snapshot_digest_hex(snapshot: dict) -> str:
    return domain_digest_hex(DOMAIN_SNAPSHOT, encode(snapshot))


def chain_hash_hex(index: int, prev_hex: str, envelope_stmt: dict) -> str:
    """h_i = H(Enc(event, i, h_{i-1}, E_i)) -- Eq. (2), versioned and domain separated."""
    link = {'event': 'envelope', 'index': index, 'prev': prev_hex, 'envelope': envelope_stmt}
    return domain_digest_hex(DOMAIN_CHAIN, encode(link))


GENESIS_HEAD = '0' * DIGEST_HEX_LEN


class RoleSigner:
    """Holds one ML-DSA key pair for one logical role.

    The private key never leaves the liboqs object; ``public_entry`` exports
    only the public key.
    """

    def __init__(self, role: str, key_id: str | None = None):
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}")
        self.role = role
        self._signer = oqs.Signature(SIG_ALG)
        self.public_key = self._signer.generate_keypair()
        self.key_id = key_id or f"{role}-key-1"

    def sign_bytes(self, message: bytes) -> str:
        with instrument.span('sign'):
            sig = self._signer.sign(message)
        return _hex(sig)

    def sign_statement(self, statement: dict) -> dict:
        """Return {'statement', 'signature', 'digest', 'key_id'} for a statement.

        The statement must already carry ``schema`` and ``role`` labels that
        match this signer's role.
        """
        if statement.get('role') != self.role:
            raise ValueError(f"statement role {statement.get('role')!r} does not match signer role {self.role!r}")
        stmt_bytes = encode(statement)
        return {
            'statement': statement,
            'signature': self.sign_bytes(stmt_bytes),
            'digest': statement_digest_hex(stmt_bytes),
            'key_id': self.key_id,
        }

    def public_entry(self, valid_from: int = 0, valid_to: int | None = None) -> dict:
        return {
            'role': self.role,
            'key_id': self.key_id,
            'algorithm': SIG_ALG,
            'public_key_hex': self.public_key.hex(),
            'valid_from': valid_from,
            'valid_to': valid_to,
        }


def verify_bytes(public_key: bytes, message: bytes, sig_hex: str) -> bool:
    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    with instrument.span('verify'):
        try:
            return oqs.Signature(SIG_ALG).verify(message, sig, public_key)
        except Exception:
            return False


@dataclass
class TrustConfig:
    """Verifier-held trust material: role -> list of public keys with validity periods.

    This is an explicit verifier input.  It is never read from the archive
    under verification (Section VIII-C).
    """

    entries: dict = field(default_factory=dict)  # role -> [entry]

    @classmethod
    def from_signers(cls, signers: dict, valid_from: int = 0, valid_to: int | None = None) -> 'TrustConfig':
        tc = cls()
        for role, signer in signers.items():
            tc.add(signer.public_entry(valid_from, valid_to))
        return tc

    def add(self, entry: dict):
        self.entries.setdefault(entry['role'], []).append(dict(entry))

    def to_json(self) -> dict:
        return {'schema': 'trust_config_v2', 'entries': self.entries}

    @classmethod
    def from_json(cls, obj: dict) -> 'TrustConfig':
        tc = cls()
        for role, entries in obj['entries'].items():
            for e in entries:
                tc.add(e)
        return tc

    def key_for(self, role: str, key_id: str, at_time: int | None = None) -> bytes | None:
        for e in self.entries.get(role, ()):
            if e['key_id'] != key_id or e.get('algorithm') != SIG_ALG:
                continue
            if at_time is not None:
                if at_time < e.get('valid_from', 0):
                    continue
                if e.get('valid_to') is not None and at_time > e['valid_to']:
                    continue
            return bytes.fromhex(e['public_key_hex'])
        return None

    def verify_signed(self, role: str, signed: dict, at_time: int | None = None) -> tuple[bool, str]:
        """Check digest and signature of a signed entry against this trust configuration."""
        stmt = signed.get('statement')
        if not isinstance(stmt, dict):
            return False, 'missing statement'
        if stmt.get('role') != role:
            return False, f"statement role {stmt.get('role')!r} != expected {role!r}"
        try:
            stmt_bytes = encode(stmt)
        except Exception as exc:  # canonical error
            return False, f'non-canonical statement: {exc}'
        if statement_digest_hex(stmt_bytes) != signed.get('digest'):
            return False, 'statement digest mismatch'
        pk = self.key_for(role, signed.get('key_id', ''), at_time)
        if pk is None:
            return False, f"no trusted key {signed.get('key_id')!r} for role {role!r} at time {at_time}"
        if not verify_bytes(pk, stmt_bytes, signed.get('signature', '')):
            return False, 'signature invalid'
        return True, 'ok'


def generate_role_signers(roles=ROLES) -> dict:
    return {role: RoleSigner(role) for role in roles}


def kem_roundtrip() -> dict:
    """Executed ML-KEM-768 operation used as the fixture's controlled operation.

    Returns a description of the operation without key or shared-secret bytes.
    Raises if key agreement fails; it does not decide policy.
    """
    with instrument.span('kem'):
        with oqs.KeyEncapsulation(KEM_ALG) as receiver:
            pk = receiver.generate_keypair()
            with oqs.KeyEncapsulation(KEM_ALG) as sender:
                ciphertext, sender_secret = sender.encap_secret(pk)
            receiver_secret = receiver.decap_secret(ciphertext)
        if not hmac.compare_digest(sender_secret, receiver_secret):
            raise ValueError('KEM key agreement failed')
    return {
        'algorithm': KEM_ALG,
        'ciphertext_digest': _hex(_sha384(ciphertext)),
        'public_key_bytes': len(pk),
        'ciphertext_bytes': len(ciphertext),
        'shared_secret_bytes': len(sender_secret),
        'key_agreement': True,
    }
