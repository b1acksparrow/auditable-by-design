"""Independent outcome observation by real TLS handshakes (Section VIII extension).

The contract's outcome observer reads the authoritative store; that is
independence from the receipt, not observation of a deployed service.  This
module closes that gap for the key-establishment surface: it runs a real TLS 1.3
service (nginx built on OpenSSL) whose key-exchange groups are the governed
configuration, and observes the *delivered* protection by completing handshakes
from a panel of reference clients, one per capability class, recording the group
each client actually negotiates.

It also addresses the objection of Han (arXiv:2609.07849): no single peer can
soundly gate post-quantum delivery, because shipped clients fall into
incomparable capability classes.  The panel holds two incomparable hybrid
classes (X25519- and P-256-based); withdrawing one hybrid group downgrades only
peers of that class, so the observer probes with every class and compares the
negotiated group per class, rather than pinning to one (see ``panel_argument``).

Requires ``nginx`` and ``openssl`` on PATH.  Everything runs in user space in a
working directory; no privilege, no system service, single host.
"""

import re
import shutil
import signal
import socket
import subprocess
import time
from dataclasses import dataclass, field

# Capability classes of reference clients (the panel), chosen to match the
# incomparable shipped-client classes of Han (arXiv:2609.07849).  The group each
# negotiates is what the service delivers to a peer of that class.
#   legacy_classical -- offers only X25519 (an old client)
#   x25519_hybrid    -- offers the X25519 hybrid, then X25519 (silently falls back)
#   p256_hybrid      -- offers the P-256 hybrid, then P-256 (silently falls back)
#   pqc_strict       -- offers only a PQ group (fails instead of downgrading)
# The two hybrid classes share no group, so each sees only its own hybrid group.
REFERENCE_CLIENTS = {
    'legacy_classical': ['X25519'],
    'x25519_hybrid': ['X25519MLKEM768', 'X25519'],
    'p256_hybrid': ['SecP256r1MLKEM768', 'secp256r1'],
    'pqc_strict': ['MLKEM768'],
}
# Security class of a negotiated group, keyed by OpenSSL trace and IANA names
# (matches abd.policy SECURITY_RANK labels).
GROUP_CLASS = {
    'X25519': 'classical', 'x25519': 'classical', 'ecdh_x25519': 'classical',
    'secp256r1': 'classical', 'prime256v1': 'classical', 'P-256': 'classical',
    'X25519MLKEM768': 'hybrid-pqc', 'SecP256r1MLKEM768': 'hybrid-pqc',
    'MLKEM768': 'pqc',
}
# Aliases used by the s_client summary lines, mapped to the trace names.
_TRACE_NAME = {'X25519': 'ecdh_x25519', 'x25519': 'ecdh_x25519', 'prime256v1': 'secp256r1', 'P-256': 'secp256r1'}

# RFC 8446 4.1.3: a HelloRetryRequest is a ServerHello whose random is SHA-256("HelloRetryRequest").
# OpenSSL 3.6 -trace labels it "ServerHello" and prints the random as gmt_unix_time + random_bytes.
HRR_RANDOM = 'CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C'
_SERVERHELLO = re.compile(r'^[ \t]+ServerHello, Length=\d+((?:\n[ \t]+.*)*)', re.M)
_RANDOM = re.compile(r'gmt_unix_time=0x([0-9A-Fa-f]{8})\s+random_bytes \(len=28\): ([0-9A-Fa-f]{56})')
_NAMED_GROUP = re.compile(r'NamedGroup:\s*([A-Za-z0-9_-]+)')
_NEGOTIATED = re.compile(r'Negotiated TLS1\.3 group: (\S+)')
_PEER_TEMP_KEY = re.compile(r'Peer Temp Key: (?:ECDH, )?([^,\s]+),')
_COMPLETED = re.compile(r'New, TLSv1\.3, Cipher is ')
_HTTP_200 = re.compile(r'HTTP/1\.[01] 200')


def tools_available() -> bool:
    return bool(shutil.which('nginx') and shutil.which('openssl'))


def free_port() -> int:
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_cert(workdir: str) -> tuple[str, str]:
    """A throwaway P-256 self-signed certificate for the local fixture service."""
    import os
    cert, key = os.path.join(workdir, 'cert.pem'), os.path.join(workdir, 'key.pem')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                    '-keyout', key, '-out', cert, '-days', '1', '-nodes', '-subj', '/CN=localhost'],
                   check=True, capture_output=True)
    return cert, key


NGINX_CONF = """worker_processes 1;
daemon off;
error_log stderr crit;
pid {pid};
events {{ worker_connections 64; }}
http {{
  access_log off;
  client_body_temp_path {tmp}/body;
  proxy_temp_path {tmp}/proxy;
  fastcgi_temp_path {tmp}/fastcgi;
  uwsgi_temp_path {tmp}/uwsgi;
  scgi_temp_path {tmp}/scgi;
  server {{
    listen 127.0.0.1:{port} ssl;
    ssl_certificate {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.3;
    ssl_ecdh_curve {groups};
    location / {{ return 200 "ok\\n"; }}
  }}
}}
"""


class TlsService:
    """A user-space nginx TLS 1.3 service whose key-exchange groups are governed configuration."""

    def __init__(self, workdir: str, groups: str, port: int | None = None):
        import os
        self.workdir = workdir
        self.groups = groups
        self.port = port or free_port()
        os.makedirs(os.path.join(workdir, 'tmp'), exist_ok=True)
        self.cert, self.key = make_cert(workdir)
        self.conf = os.path.join(workdir, 'nginx.conf')
        self.pid = os.path.join(workdir, 'nginx.pid')
        self._proc: subprocess.Popen | None = None
        self._write_conf(groups)

    def _write_conf(self, groups: str):
        with open(self.conf, 'w') as fh:
            fh.write(NGINX_CONF.format(pid=self.pid, tmp=self.workdir + '/tmp', port=self.port,
                                       cert=self.cert, key=self.key, groups=groups))
        self.groups = groups

    def config_valid(self) -> bool:
        r = subprocess.run(['nginx', '-t', '-c', self.conf, '-p', self.workdir], capture_output=True, text=True)
        return r.returncode == 0

    def start(self, timeout_s: float = 10.0):
        self._proc = subprocess.Popen(['nginx', '-c', self.conf, '-p', self.workdir],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                socket.create_connection(('127.0.0.1', self.port), timeout=0.5).close()
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError('nginx did not start listening')

    def reconfigure(self, groups: str):
        """Change the governed key-exchange groups: rewrite the config and restart the service.

        Models an administrative edit of the service configuration (as in Han's
        downgrade), including one that still validates and serves."""
        self.stop()
        self._write_conf(groups)
        self.start()

    def stop(self):
        if self._proc is not None:
            self._proc.send_signal(signal.SIGTERM)
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()


def parse_trace(out: str, returncode: int | None) -> dict:
    """Read the outcome of one ``s_client -trace`` run.

    The negotiated group is taken from the last real ServerHello key_share,
    skipping a HelloRetryRequest, and cross-checked against the summary line
    (``Negotiated TLS1.3 group:`` or ``Peer Temp Key:``) when present.  The
    handshake is ok only if s_client exited 0, printed a completed TLS 1.3
    session, a ServerHello group was found, and the cross-check agrees."""
    group, hello_retry = None, False
    for block in _SERVERHELLO.finditer(out):
        r = _RANDOM.search(block.group(1))
        if r and (r.group(1) + r.group(2)).upper() == HRR_RANDOM:
            hello_retry = True
            continue
        g = _NAMED_GROUP.search(block.group(1))
        group = g.group(1) if g else None
    # A summary line must be present and agree; '<NULL>' falls through to the Peer Temp Key line.
    names = [m.group(1) for m in (_NEGOTIATED.search(out), _PEER_TEMP_KEY.search(out)) if m and m.group(1) != '<NULL>']
    summary = names[0] if names else None
    completed = bool(_COMPLETED.search(out))
    agrees = summary is not None and _TRACE_NAME.get(summary, summary) == _TRACE_NAME.get(group, group)
    ok = returncode == 0 and completed and group is not None and agrees
    return {
        'returncode': returncode,
        'handshake_completed': completed,
        'hello_retry': hello_retry,
        'serverhello_group': group,
        'summary_group': summary,
        'handshake_ok': ok,
        'http_ok': bool(_HTTP_200.search(out)),
        'negotiated_group': group if ok else None,
        'negotiated_class': GROUP_CLASS.get(group) if ok else None,
    }


def handshake(port: int, client_groups: list, timeout_s: float = 15.0) -> dict:
    """Complete a real TLS 1.3 handshake offering only ``client_groups``, then send an HTTP GET.

    The HTTP response is matched anywhere in the output: s_client writes it to the
    stdout descriptor directly, so it can land mid-line in the buffered trace."""
    cmd = ['openssl', 's_client', '-connect', f'127.0.0.1:{port}', '-groups', ':'.join(client_groups),
           '-tls1_3', '-trace', '-ign_eof']
    try:
        r = subprocess.run(cmd, input='GET / HTTP/1.0\r\n\r\n', capture_output=True, text=True,
                           timeout=timeout_s)
        out, rc = r.stdout, r.returncode
    except subprocess.TimeoutExpired:
        out, rc = '', None
    return {'offered': list(client_groups), **parse_trace(out, rc)}


@dataclass
class TlsObservation:
    port: int
    groups_configured: str
    per_client: dict = field(default_factory=dict)     # class -> handshake result

    def delivered_class(self, client_class: str) -> str | None:
        r = self.per_client.get(client_class)
        return r['negotiated_class'] if r and r['handshake_ok'] else None

    def served(self, client_class: str) -> bool:
        """The peer completed a handshake and received an HTTP 200."""
        r = self.per_client.get(client_class)
        return bool(r and r['handshake_ok'] and r['http_ok'])

    def to_json(self) -> dict:
        return {'port': self.port, 'groups_configured': self.groups_configured, 'per_client': self.per_client}


class TlsOutcomeObserver:
    """Observes delivered protection by handshaking with every reference client class.

    This is an independent measurement of the deployed service, not of a receipt
    or of the service's own configuration self-report."""

    def __init__(self, panel: dict = REFERENCE_CLIENTS):
        self.panel = panel

    def observe(self, service: TlsService) -> TlsObservation:
        obs = TlsObservation(port=service.port, groups_configured=service.groups)
        for name, groups in self.panel.items():
            obs.per_client[name] = handshake(service.port, groups)
        return obs


def still_serves(before: TlsObservation, after: TlsObservation) -> bool:
    """Every peer served (handshake and HTTP 200) before the change is still served after it."""
    served = [name for name in before.per_client if before.served(name)]
    return bool(served) and all(after.served(name) for name in served)


def downgrade_detected(before: TlsObservation, after: TlsObservation) -> dict:
    """Compare two observations for a withdrawal of post-quantum delivery to any client class.

    Records every class's delivered class before and after, which classes lost
    protection while still completing a handshake (a silent downgrade), and, for
    every class, whether a monitor pinned to that single peer would miss it: a
    peer observes only its own delivered class, so it detects only its own loss."""
    from .policy import SECURITY_RANK
    per_class, lost = {}, []
    for name in before.per_client:
        b, a = before.delivered_class(name), after.delivered_class(name)
        per_class[name] = {'before': b, 'after': a}
        if b and a and SECURITY_RANK.get(a, 0) < SECURITY_RANK.get(b, 0):
            lost.append({'client_class': name, 'from': b, 'to': a})
    lost_names = {d['client_class'] for d in lost}
    # A peer that hard-fails after the change signals a break, not a silent downgrade.
    broke = [name for name in before.per_client
             if before.delivered_class(name) and after.delivered_class(name) is None]
    result = {'per_class': per_class, 'downgraded': lost, 'any': bool(lost), 'silent': bool(lost),
              'hard_failed_clients': broke}
    for name in before.per_client:
        result[f'single_peer_{name}_would_miss'] = bool(lost) and name not in lost_names
    return result


def panel_argument(detections: dict) -> dict:
    """Across scenarios (name -> ``downgrade_detected`` result), which single peer detects which.

    ``no_single_peer_detects_all_but_panel_does`` holds when the panel detects every
    scenario while no single peer class detects all of them."""
    classes = list(dict.fromkeys(k[len('single_peer_'):-len('_would_miss')] for d in detections.values()
                                 for k in d if k.startswith('single_peer_')))
    detected_by = {c: [s for s, d in detections.items() if d['any'] and not d[f'single_peer_{c}_would_miss']]
                   for c in classes}
    panel_all = bool(detections) and all(d['any'] for d in detections.values())
    single_all = [c for c in classes if len(detected_by[c]) == len(detections)]
    return {'scenarios_detected_by_single_peer': detected_by,
            'panel_detects_all': panel_all,
            'single_peers_detecting_all': single_all,
            'no_single_peer_detects_all_but_panel_does': panel_all and not single_all}
