"""Auditable by Design -- reference implementation of the migration transaction contract.

Modules
-------
canonical   deterministic JSON encoding (printable-ASCII subset of JCS)
crypto      ML-DSA-65 role signers, SHA-384 digests, trust configuration, ML-KEM-768 fixture
policy      migration profiles, policy versions and the policy gate (Eq. 1)
state       durable managed-state store: monotonic versions, compare-and-set, journal, one-time consumption
roles       source observer, scripted advisor, approver, executor, outcome observer, evidence service, witness
transaction transaction lifecycle, fault injection and reconciliation
verify      streaming semantic verifier of an evidence archive (Sections IV-V)
predicate   confidential-policy binding (Eq. 3-5): commitments, registration, bound statement, disclosed opening
"""

__version__ = "2.0.0"
