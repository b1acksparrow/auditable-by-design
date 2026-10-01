"""Shared fixture construction used by tests and benchmarks."""

import os
import tempfile

from . import crypto
from .policy import PolicyRegistry, default_policy
from .roles import TestClock
from .state import ManagedStateStore
from .transaction import MigrationSystem

ASSET = 'svc-internal-01'
CLASSICAL = 'tls13-x25519'
HYBRID = 'tls13-hybrid-x25519-mlkem768'
PQC = 'tls13-mlkem768'


def make_store(path: str | None = None, assets: int = 1) -> ManagedStateStore:
    if path is None:
        path = os.path.join(tempfile.mkdtemp(prefix='abd-'), 'state.sqlite')
    store = ManagedStateStore(path)
    policy = default_policy()
    classical = policy.allowlist[CLASSICAL].target_config()
    for k in range(assets):
        asset_id = ASSET if k == 0 else f'svc-internal-{k + 1:02d}'
        store.register_asset(
            asset_id,
            config=classical,
            peers={
                'peer-a': {'capabilities': ['kem:x25519', 'kem:x25519mlkem768', 'kem:mlkem768'], 'readiness': 'known'},
                'peer-b': {'capabilities': ['kem:x25519', 'kem:x25519mlkem768', 'kem:mlkem768'], 'readiness': 'known'},
                'peer-legacy': {'capabilities': ['kem:x25519'], 'readiness': 'known'},
                'peer-unknown': {'capabilities': [], 'readiness': 'unknown'},
            },
            implementations=['openssl-3.5', 'liboqs-0.16.0'],
        )
    return store


def make_system(store=None, clock=None, signers=None, registry=None, sink=None, delta_s=600, **kw) -> MigrationSystem:
    store = store or make_store()
    clock = clock or TestClock()
    signers = signers or crypto.generate_role_signers()
    if registry is None:
        registry = PolicyRegistry()
        registry.register(default_policy(1))
    return MigrationSystem(signers, store, registry, clock, sink=sink, delta_s=delta_s, **kw)


READY_ENDPOINTS = ['peer-a', 'peer-b']
