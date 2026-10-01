"""Deployed-service observation by real TLS handshakes.

The service tests are opt-in: they need nginx and openssl and start a user-space
TLS service, so they run with ABD_TLS=1.  One service per module; the handshakes
take seconds.  The trace-parser tests use synthetic traces and always run.
"""

import os
import tempfile

import pytest

from abd import tls_probe as T

needs_tls = pytest.mark.skipif(not (T.tools_available() and os.environ.get('ABD_TLS') == '1'),
                               reason='set ABD_TLS=1 (needs nginx and openssl) to run the TLS observation tests')

BASE = 'SecP256r1MLKEM768:X25519MLKEM768:X25519:secp256r1'
SCENARIOS = {'A': 'X25519MLKEM768', 'B': 'SecP256r1MLKEM768'}   # scenario -> removed group
AFFECTED = {'A': 'x25519_hybrid', 'B': 'p256_hybrid'}


@pytest.fixture(scope='module')
def observed():
    """A service offering both hybrid groups, observed before and after each single-group removal."""
    obs = T.TlsOutcomeObserver()
    wd = tempfile.mkdtemp(prefix='abd-tls-test-')
    svc = T.TlsService(wd, groups=BASE)
    svc.start()
    after = {}
    try:
        before = obs.observe(svc)
        for name, removed in SCENARIOS.items():
            svc.reconfigure(groups=':'.join(g for g in BASE.split(':') if g != removed))
            after[name] = (obs.observe(svc), svc.config_valid())
    finally:
        svc.stop()
    return before, after


@needs_tls
def test_base_service_delivers_each_hybrid_group_to_its_own_class(observed):
    before, _ = observed
    assert before.per_client['x25519_hybrid']['negotiated_group'] == 'X25519MLKEM768'
    assert before.per_client['p256_hybrid']['negotiated_group'] == 'SecP256r1MLKEM768'
    assert before.delivered_class('x25519_hybrid') == before.delivered_class('p256_hybrid') == 'hybrid-pqc'
    assert before.delivered_class('legacy_classical') == 'classical'


@needs_tls
def test_served_peers_complete_the_handshake_and_get_http_200(observed):
    before, _ = observed
    for c in ('legacy_classical', 'x25519_hybrid', 'p256_hybrid'):
        r = before.per_client[c]
        assert r['returncode'] == 0 and r['handshake_completed'] and r['http_ok'] and before.served(c)


@needs_tls
def test_a_peer_without_a_shared_group_is_not_ok(observed):
    before, _ = observed
    r = before.per_client['pqc_strict']
    assert r['returncode'] != 0 and not r['handshake_ok'] and not r['http_ok']
    assert r['negotiated_group'] is None


@needs_tls
@pytest.mark.parametrize('scenario', SCENARIOS)
def test_each_edit_still_validates_and_serves(observed, scenario):
    before, after = observed
    obs, valid = after[scenario]
    assert valid                                     # the artifact-side check passes
    assert T.still_serves(before, obs)               # every served peer still gets HTTP 200
    assert T.downgrade_detected(before, obs)['hard_failed_clients'] == []


@needs_tls
@pytest.mark.parametrize('scenario', SCENARIOS)
def test_each_edit_silently_downgrades_only_its_own_hybrid_class(observed, scenario):
    before, after = observed
    obs, _ = after[scenario]
    hit = AFFECTED[scenario]
    d = T.downgrade_detected(before, obs)
    assert d['silent'] and d['downgraded'] == [{'client_class': hit, 'from': 'hybrid-pqc', 'to': 'classical'}]
    assert obs.per_client[hit]['handshake_ok'] and obs.per_client[hit]['hello_retry']   # fell back via HRR
    for c in T.REFERENCE_CLIENTS:
        assert d['per_class'][c] == {'before': before.delivered_class(c), 'after': obs.delivered_class(c)}
        assert d[f'single_peer_{c}_would_miss'] == (c != hit)


@needs_tls
def test_no_single_peer_detects_both_edits_but_the_panel_does(observed):
    before, after = observed
    p = T.panel_argument({n: T.downgrade_detected(before, obs) for n, (obs, _) in after.items()})
    assert p['panel_detects_all'] and p['single_peers_detecting_all'] == []
    assert p['no_single_peer_detects_all_but_panel_does']
    assert p['scenarios_detected_by_single_peer'] == {'legacy_classical': [], 'x25519_hybrid': ['A'],
                                                      'p256_hybrid': ['B'], 'pqc_strict': []}


# --- trace parser (synthetic s_client -trace output) ---------------------------

def _server_hello(random_hex: str, group: str) -> str:
    return ('Received TLS Record\nHeader:\n  Version = TLS 1.2 (0x303)\n'
            '    ServerHello, Length=118\n      server_version=0x303 (TLS 1.2)\n      Random:\n'
            f'        gmt_unix_time=0x{random_hex[:8]}\n        random_bytes (len=28): {random_hex[8:]}\n'
            '        extension_type=key_share(51), length=36\n'
            f'            NamedGroup: {group} (29)\n\n')


REAL = '659D42B9AD451CA71B4CA4BC9CB1CDA08B1A29274C5274309BC783CA0C436B6E'
COMPLETED = '---\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n'
DONE = 'Peer Temp Key: X25519, 253 bits\n' + COMPLETED


def test_parser_skips_the_hello_retry_request_and_uses_the_last_server_hello():
    out = _server_hello(T.HRR_RANDOM, 'secp256r1') + _server_hello(REAL, 'ecdh_x25519') + DONE
    r = T.parse_trace(out, 0)
    assert r['hello_retry'] and r['negotiated_group'] == 'ecdh_x25519' and r['handshake_ok']


def test_parser_requires_exit_zero_and_a_completed_handshake():
    out = _server_hello(REAL, 'ecdh_x25519') + DONE
    assert not T.parse_trace(out, 1)['handshake_ok']
    assert not T.parse_trace(out, None)['handshake_ok']
    assert not T.parse_trace(_server_hello(REAL, 'ecdh_x25519'), 0)['handshake_ok']
    assert not T.parse_trace(_server_hello(T.HRR_RANDOM, 'ecdh_x25519') + DONE, 0)['handshake_ok']


def test_parser_rejects_a_summary_that_disagrees_with_the_server_hello():
    out = _server_hello(REAL, 'X25519MLKEM768') + 'Negotiated TLS1.3 group: SecP256r1MLKEM768\n' + DONE
    assert not T.parse_trace(out, 0)['handshake_ok']
    agree = _server_hello(REAL, 'X25519MLKEM768') + 'Negotiated TLS1.3 group: X25519MLKEM768\n' + COMPLETED
    assert T.parse_trace(agree, 0)['negotiated_class'] == 'hybrid-pqc'


def test_http_200_is_found_mid_line_in_the_trace():
    out = _server_hello(REAL, 'ecdh_x25519') + DONE + '    0010 - d8 40 91 f9 b7 f5 90 HTTP/1.1 200 OK\nServer: nginx\n'
    assert T.parse_trace(out, 0)['http_ok']


def test_parser_requires_an_agreeing_summary_line():
    assert not T.parse_trace(_server_hello(REAL, 'X25519MLKEM768') + COMPLETED, 0)['handshake_ok']
    null_then_ptk = (_server_hello(REAL, 'X25519MLKEM768') + 'Negotiated TLS1.3 group: <NULL>\n'
                     + 'Peer Temp Key: X25519, 253 bits\n' + COMPLETED)
    assert not T.parse_trace(null_then_ptk, 0)['handshake_ok']


def test_panel_argument_needs_at_least_one_scenario():
    assert not T.panel_argument({})['no_single_peer_detects_all_but_panel_does']
