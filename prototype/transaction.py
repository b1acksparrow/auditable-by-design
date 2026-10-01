"""
Full transaction pipeline implementing the 6-role signing model:
  1. Source observation
  2. Authorization
  3. Executor receipt (with ML-KEM-768)
  4. Outcome observation
  5. Audit envelope
  6. Checkpoint

Uses ML-DSA-65 for all signatures, SHA-384 for hashing,
and the paper's canonical JSON serialization.
"""

import hashlib
import time
import uuid
import oqs
from canonical_json import canonical_encode

HASH_ALG = 'sha384'
SIG_ALG = 'ML-DSA-65'
KEM_ALG = 'ML-KEM-768'

ROLES = [
    'source_observer',
    'authorizer',
    'executor',
    'outcome_observer',
    'audit_envelope',
    'checkpoint_witness',
]


def sha384_digest(data: bytes) -> bytes:
    return hashlib.sha384(data).digest()


def sha384_hex(data: bytes) -> str:
    return hashlib.sha384(data).hexdigest()


def generate_role_keys():
    keys = {}
    for role in ROLES:
        signer = oqs.Signature(SIG_ALG)
        pub = signer.generate_keypair()
        keys[role] = {
            'signer': signer,
            'public_key': pub,
        }
    return keys


def sign_statement(signer, statement_bytes: bytes) -> str:
    sig = signer.sign(statement_bytes)
    return sig.hex()


def verify_signature(public_key: bytes, message: bytes, sig_hex: str) -> bool:
    verifier = oqs.Signature(SIG_ALG)
    return verifier.verify(message, bytes.fromhex(sig_hex), public_key)


def kem_roundtrip():
    receiver = oqs.KeyEncapsulation(KEM_ALG)
    receiver_pk = receiver.generate_keypair()

    sender = oqs.KeyEncapsulation(KEM_ALG)
    ciphertext, shared_secret_sender = sender.encap_secret(receiver_pk)

    shared_secret_receiver = receiver.decap_secret(ciphertext)

    return {
        'algorithm': KEM_ALG,
        'ciphertext_digest': sha384_hex(ciphertext),
        'ciphertext_len': len(ciphertext),
        'shared_secret_len': len(shared_secret_sender),
        'agreement': shared_secret_sender == shared_secret_receiver,
    }


def create_transaction(role_keys, tx_id=None, prev_chain_hash=None, state_version=0):
    if tx_id is None:
        tx_id = str(uuid.uuid4())
    if prev_chain_hash is None:
        prev_chain_hash = '0' * 96

    asset_profile = {
        'asset_id': 'tls-endpoint-01',
        'current_cipher': 'TLS_AES_256_GCM_SHA384',
        'target_cipher': 'TLS_AES_256_GCM_SHA384_ML_KEM_768',
        'state_version': state_version,
    }

    # 1. Source observation
    source_stmt = {
        'schema': 'source_observation_v1',
        'role': 'source_observer',
        'tx_id': tx_id,
        'timestamp': int(time.time()),
        'asset_profile': asset_profile,
        'evidence_digest': sha384_hex(canonical_encode(asset_profile)),
    }
    source_bytes = canonical_encode(source_stmt)
    source_sig = sign_statement(role_keys['source_observer']['signer'], source_bytes)
    source_digest = sha384_hex(source_bytes)

    # 2. Authorization
    proposal = {
        'action': 'migrate_to_pqc',
        'target_algorithm': KEM_ALG,
        'policy_version': 1,
        'source_digest': source_digest,
    }
    auth_stmt = {
        'schema': 'authorization_v1',
        'role': 'authorizer',
        'tx_id': tx_id,
        'timestamp': int(time.time()),
        'proposal': proposal,
        'proposal_digest': sha384_hex(canonical_encode(proposal)),
        'source_record_digest': source_digest,
    }
    auth_bytes = canonical_encode(auth_stmt)
    auth_sig = sign_statement(role_keys['authorizer']['signer'], auth_bytes)
    auth_digest = sha384_hex(auth_bytes)

    # 3. Executor receipt (with KEM operation)
    kem_result = kem_roundtrip()
    exec_stmt = {
        'schema': 'executor_receipt_v1',
        'role': 'executor',
        'tx_id': tx_id,
        'timestamp': int(time.time()),
        'authorization_digest': auth_digest,
        'proposal_digest': sha384_hex(canonical_encode(proposal)),
        'state_version_before': state_version,
        'state_version_after': state_version + 1,
        'kem_result': kem_result,
    }
    exec_bytes = canonical_encode(exec_stmt)
    exec_sig = sign_statement(role_keys['executor']['signer'], exec_bytes)
    exec_digest = sha384_hex(exec_bytes)

    # 4. Outcome observation
    outcome_profile = dict(asset_profile)
    outcome_profile['current_cipher'] = asset_profile['target_cipher']
    outcome_profile['state_version'] = state_version + 1
    outcome_stmt = {
        'schema': 'outcome_observation_v1',
        'role': 'outcome_observer',
        'tx_id': tx_id,
        'timestamp': int(time.time()),
        'receipt_digest': exec_digest,
        'observed_profile': outcome_profile,
        'profile_digest': sha384_hex(canonical_encode(outcome_profile)),
    }
    outcome_bytes = canonical_encode(outcome_stmt)
    outcome_sig = sign_statement(role_keys['outcome_observer']['signer'], outcome_bytes)
    outcome_digest = sha384_hex(outcome_bytes)

    # 5. Audit envelope
    envelope_stmt = {
        'schema': 'audit_envelope_v1',
        'role': 'audit_envelope',
        'tx_id': tx_id,
        'timestamp': int(time.time()),
        'chain_prev': prev_chain_hash,
        'source_digest': source_digest,
        'authorization_digest': auth_digest,
        'executor_digest': exec_digest,
        'outcome_digest': outcome_digest,
    }
    envelope_bytes = canonical_encode(envelope_stmt)
    envelope_sig = sign_statement(role_keys['audit_envelope']['signer'], envelope_bytes)
    envelope_digest = sha384_hex(envelope_bytes)

    # 6. Checkpoint
    checkpoint_stmt = {
        'schema': 'checkpoint_v1',
        'role': 'checkpoint_witness',
        'tx_id': tx_id,
        'timestamp': int(time.time()),
        'log_identity': 'audit-log-001',
        'chain_length': state_version + 1,
        'witnessed_head': envelope_digest,
    }
    checkpoint_bytes = canonical_encode(checkpoint_stmt)
    checkpoint_sig = sign_statement(role_keys['checkpoint_witness']['signer'], checkpoint_bytes)
    checkpoint_digest = sha384_hex(checkpoint_bytes)

    record = {
        'tx_id': tx_id,
        'source': {'statement': source_stmt, 'signature': source_sig, 'digest': source_digest},
        'authorization': {'statement': auth_stmt, 'signature': auth_sig, 'digest': auth_digest},
        'executor': {'statement': exec_stmt, 'signature': exec_sig, 'digest': exec_digest},
        'outcome': {'statement': outcome_stmt, 'signature': outcome_sig, 'digest': outcome_digest},
        'envelope': {'statement': envelope_stmt, 'signature': envelope_sig, 'digest': envelope_digest},
        'checkpoint': {'statement': checkpoint_stmt, 'signature': checkpoint_sig, 'digest': checkpoint_digest},
    }
    return record


def verify_record(record, role_keys):
    checks = []
    role_map = {
        'source': 'source_observer',
        'authorization': 'authorizer',
        'executor': 'executor',
        'outcome': 'outcome_observer',
        'envelope': 'audit_envelope',
        'checkpoint': 'checkpoint_witness',
    }

    for section, role in role_map.items():
        entry = record[section]
        stmt_bytes = canonical_encode(entry['statement'])
        digest_ok = sha384_hex(stmt_bytes) == entry['digest']
        sig_ok = verify_signature(
            role_keys[role]['public_key'],
            stmt_bytes,
            entry['signature'],
        )
        checks.append({
            'section': section,
            'digest_valid': digest_ok,
            'signature_valid': sig_ok,
        })

    # Chain linkage checks
    checks.append({
        'section': 'chain_linkage',
        'auth_binds_source': record['authorization']['statement']['source_record_digest'] == record['source']['digest'],
        'exec_binds_auth': record['executor']['statement']['authorization_digest'] == record['authorization']['digest'],
        'outcome_binds_exec': record['outcome']['statement']['receipt_digest'] == record['executor']['digest'],
        'envelope_binds_all': (
            record['envelope']['statement']['source_digest'] == record['source']['digest']
            and record['envelope']['statement']['authorization_digest'] == record['authorization']['digest']
            and record['envelope']['statement']['executor_digest'] == record['executor']['digest']
            and record['envelope']['statement']['outcome_digest'] == record['outcome']['digest']
        ),
        'checkpoint_binds_envelope': record['checkpoint']['statement']['witnessed_head'] == record['envelope']['digest'],
    })

    # KEM agreement
    checks.append({
        'section': 'kem_agreement',
        'agreement': record['executor']['statement']['kem_result']['agreement'],
        'algorithm': record['executor']['statement']['kem_result']['algorithm'],
    })

    return checks
