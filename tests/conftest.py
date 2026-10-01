import copy

import pytest

from abd import crypto
from abd.fixture import make_store, make_system
from abd.roles import TestClock
from abd.verify import verify_archive


@pytest.fixture
def clock():
    return TestClock()


@pytest.fixture
def store(tmp_path):
    return make_store(str(tmp_path / 'state.sqlite'))


@pytest.fixture
def signers():
    return crypto.generate_role_signers()


@pytest.fixture
def system(store, clock, signers):
    return make_system(store=store, clock=clock, signers=signers)


def verify(system, records=None, checkpoint='retained', now=None, delta_s=600, trust=None, registry=None,
           log_id=None, collect_all=False):
    """Run the verifier with explicit inputs taken from the system unless overridden."""
    if checkpoint == 'retained':
        checkpoint = system.retained_checkpoint()
    return verify_archive(
        records if records is not None else system.records,
        trust or system.trust,
        registry or system.registry,
        log_id or system.log_id,
        checkpoint,
        system.clock.now() if now is None else now,
        delta_s,
        collect_all=collect_all,
    )


def resign(signer, signed_entry, mutate=None):
    """Re-sign a statement with a legitimate role key after an optional mutation.

    Models an attacker who holds the role key: the signature is valid, so only
    semantic checks can reject the result."""
    stmt = copy.deepcopy(signed_entry['statement'])
    if mutate:
        mutate(stmt)
    return signer.sign_statement(stmt)


def failures_mention(result, token):
    return any(token in f for f in result.failures)
