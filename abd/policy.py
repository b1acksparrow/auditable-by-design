"""Migration profiles, policy versions and the policy gate (Section IV, Eq. 1).

    b_i = Fresh(x_i, s_i) AND Allowed_v(a_i) AND Compatible(a_i, x_i) AND Authorized(u_i, a_i, s_i, v_i)

Each conjunct is evaluated by a separate function that returns a structured
reason, so that a denial names the failed conjunct rather than a score.
"""

from dataclasses import dataclass, field

from . import crypto

# Ordinal security-floor ranks for the fixture.  Higher is stronger.
SECURITY_RANK = {
    'classical': 1,
    'hybrid-pqc': 2,
    'pqc': 3,
}

# Recovery by service isolation: always permitted, used when no allowlisted
# profile that satisfies the security floor can be restored (Section IV-D).
RECOVERY_ISOLATE = 'isolate'


@dataclass(frozen=True)
class Profile:
    profile_id: str
    protocol: str                  # e.g. "TLS1.3"
    kem: str                       # e.g. "ML-KEM-768" or "X25519"
    cipher_label: str              # synthetic fixture label
    security_class: str            # key of SECURITY_RANK
    required_peer_capability: str  # capability a peer must advertise
    implementation: str            # e.g. "liboqs-0.16.0"

    def to_json(self) -> dict:
        return {
            'profile_id': self.profile_id,
            'protocol': self.protocol,
            'kem': self.kem,
            'cipher_label': self.cipher_label,
            'security_class': self.security_class,
            'required_peer_capability': self.required_peer_capability,
            'implementation': self.implementation,
        }

    def target_config(self) -> dict:
        """The exact configuration the executor would apply."""
        return {'profile_id': self.profile_id, 'kem': self.kem,
                'cipher_label': self.cipher_label, 'protocol': self.protocol}


@dataclass
class PolicyVersion:
    version: int
    allowlist: dict = field(default_factory=dict)     # profile_id -> Profile
    freshness_limit_s: int = 300
    approval_ttl_s: int = 3600
    security_floor: str = 'hybrid-pqc'                # minimum class for any recovery target
    permitted_actions: tuple = ('migrate_profile',)
    automation_scope: tuple = ()                      # asset_id patterns approvable by rule

    def to_json(self) -> dict:
        return {
            'schema': 'policy_version_v2',
            'version': self.version,
            'allowlist': {k: v.to_json() for k, v in sorted(self.allowlist.items())},
            'freshness_limit_s': self.freshness_limit_s,
            'approval_ttl_s': self.approval_ttl_s,
            'security_floor': self.security_floor,
            'permitted_actions': list(self.permitted_actions),
            'automation_scope': list(self.automation_scope),
        }

    def digest(self) -> str:
        return crypto.domain_digest_hex(crypto.DOMAIN_STATEMENT, crypto.encode(self.to_json()))


class PolicyRegistry:
    """Versioned, public part of the policy.  Verifiers hold a copy."""

    def __init__(self):
        self._versions: dict[int, PolicyVersion] = {}
        self.active_version: int | None = None

    def register(self, pv: PolicyVersion, activate: bool = True):
        self._versions[pv.version] = pv
        if activate:
            self.active_version = pv.version

    def get(self, version: int) -> PolicyVersion | None:
        return self._versions.get(version)

    @property
    def active(self) -> PolicyVersion:
        return self._versions[self.active_version]

    def to_json(self) -> dict:
        return {'schema': 'policy_registry_v2',
                'active_version': self.active_version,
                'versions': {str(v): pv.to_json() for v, pv in sorted(self._versions.items())}}


def default_policy(version: int = 1) -> PolicyVersion:
    profiles = [
        Profile('tls13-x25519', 'TLS1.3', 'X25519', 'TLS_AES_256_GCM_SHA384', 'classical',
                'kem:x25519', 'openssl-3.5'),
        Profile('tls13-hybrid-x25519-mlkem768', 'TLS1.3', 'X25519MLKEM768',
                'TLS_AES_256_GCM_SHA384+X25519MLKEM768', 'hybrid-pqc', 'kem:x25519mlkem768', 'liboqs-0.16.0'),
        Profile('tls13-mlkem768', 'TLS1.3', 'ML-KEM-768', 'TLS_AES_256_GCM_SHA384+MLKEM768', 'pqc',
                'kem:mlkem768', 'liboqs-0.16.0'),
    ]
    pv = PolicyVersion(version=version, allowlist={p.profile_id: p for p in profiles})
    return pv


def meets_floor(profile: Profile, policy: PolicyVersion) -> bool:
    return SECURITY_RANK[profile.security_class] >= SECURITY_RANK[policy.security_floor]


def recovery_permitted(policy: PolicyVersion, recovery) -> tuple[bool, str]:
    """A recovery target is service isolation or an allowlisted profile at or above the security floor."""
    if recovery == RECOVERY_ISOLATE:
        return True, 'recovery by service isolation'
    prof = policy.allowlist.get(recovery)
    if prof is None:
        return False, f'recovery profile {recovery!r} not on allowlist v{policy.version}'
    if not meets_floor(prof, policy):
        return False, f'recovery profile class {prof.security_class} below security floor {policy.security_floor}'
    return True, f'recovery to {recovery} permitted'


def compatibility(profile: Profile, snapshot: dict, endpoints: list) -> tuple[bool, str]:
    """Compatible(a_i, x_i) over an observed snapshot; shared by the gate and the archive verifier."""
    peers = snapshot['peers']
    for ep in endpoints:
        caps = peers.get(ep)
        if caps is None:
            return False, f'peer {ep!r} is not in the observed inventory'
        if caps.get('readiness') != 'known':
            return False, f'peer {ep!r} readiness is {caps.get("readiness")!r}, not known'
        if profile.required_peer_capability not in caps.get('capabilities', []):
            return False, f'peer {ep!r} lacks capability {profile.required_peer_capability!r}'
    if profile.implementation not in snapshot.get('implementations', []):
        return False, f'implementation {profile.implementation!r} not present on asset'
    return True, f'{len(endpoints)} endpoint(s) support {profile.required_peer_capability}'


@dataclass
class Conjunct:
    name: str
    ok: bool
    reason: str

    def to_json(self) -> dict:
        return {'name': self.name, 'ok': self.ok, 'reason': self.reason}


@dataclass
class GateDecision:
    permitted: bool
    conjuncts: list

    def to_json(self) -> dict:
        return {'permitted': self.permitted, 'conjuncts': [c.to_json() for c in self.conjuncts]}

    def failed(self) -> list:
        return [c.name for c in self.conjuncts if not c.ok]


class PolicyGate:
    """Evaluates Eq. (1).  ``Authorized`` is evaluated separately at execution time
    (see ``check_authorized``) because the approval is produced after the first
    three conjuncts pass; the executor re-evaluates all four before acting."""

    def __init__(self, registry: PolicyRegistry, clock):
        self.registry = registry
        self.clock = clock

    # --- Fresh(x_i, s_i) -------------------------------------------------
    def check_fresh(self, observation_stmt: dict, current_state: dict, policy: PolicyVersion) -> Conjunct:
        snap = observation_stmt['snapshot']
        age = self.clock.now() - observation_stmt['captured_at']
        # The policy bounds freshness; an observation may declare a tighter limit but never a looser one.
        limit = min(observation_stmt['freshness_limit_s'], policy.freshness_limit_s)
        if age > limit:
            return Conjunct('Fresh', False, f'observation age {age}s exceeds freshness limit {limit}s')
        if age < 0:
            return Conjunct('Fresh', False, 'observation captured in the future')
        if current_state.get('pending_reconciliation'):
            return Conjunct('Fresh', False, 'asset has an execution attempt pending reconciliation')
        if snap['state_version'] != current_state['state_version']:
            return Conjunct('Fresh', False,
                            f"observed state version {snap['state_version']} != current {current_state['state_version']}")
        if snap['config'] != current_state['config']:
            return Conjunct('Fresh', False, 'observed configuration differs from current configuration')
        if snap['peers'] != current_state['peers'] or snap['implementations'] != current_state['implementations']:
            return Conjunct('Fresh', False, 'observed dependencies (peer capabilities or implementations) differ from current state')
        return Conjunct('Fresh', True, f'observation age {age}s within {limit}s; version, configuration and dependencies match')

    # --- Allowed_v(a_i) --------------------------------------------------
    def check_allowed(self, proposal: dict, policy: PolicyVersion) -> Conjunct:
        if proposal['policy_version'] != policy.version:
            return Conjunct('Allowed', False,
                            f"proposal policy version {proposal['policy_version']} != active {policy.version}")
        if proposal['action'] not in policy.permitted_actions:
            return Conjunct('Allowed', False, f"action {proposal['action']!r} not permitted")
        prof = policy.allowlist.get(proposal['target_profile_id'])
        if prof is None:
            return Conjunct('Allowed', False, f"profile {proposal['target_profile_id']!r} not on allowlist v{policy.version}")
        if proposal['target_config'] != prof.target_config():
            return Conjunct('Allowed', False, 'proposed target configuration does not equal the allowlisted profile configuration')
        if not meets_floor(prof, policy):
            return Conjunct('Allowed', False, f"profile class {prof.security_class} below security floor {policy.security_floor}")
        return Conjunct('Allowed', True, f"profile {prof.profile_id} on allowlist v{policy.version}")

    # --- Compatible(a_i, x_i) -------------------------------------------
    def check_compatible(self, proposal: dict, observation_stmt: dict, policy: PolicyVersion) -> Conjunct:
        prof = policy.allowlist.get(proposal['target_profile_id'])
        if prof is None:
            return Conjunct('Compatible', False, 'no profile to assess')
        snap = observation_stmt['snapshot']
        if snap['asset_id'] != proposal['asset_id']:
            return Conjunct('Compatible', False, 'proposal asset does not match observed asset')
        ok, why = compatibility(prof, snap, proposal['endpoints'])
        return Conjunct('Compatible', ok, why)

    # --- Authorized(u_i, a_i, s_i, v_i) ---------------------------------
    def check_authorized(self, auth_signed: dict, proposal: dict, current_state: dict,
                         policy: PolicyVersion, trust: crypto.TrustConfig, observation: dict) -> Conjunct:
        ok, why = trust.verify_signed('authorizer', auth_signed, auth_signed['statement'].get('timestamp'))
        if not ok:
            return Conjunct('Authorized', False, f'authorization signature: {why}')
        a = auth_signed['statement']
        if a.get('decision') != 'authorized':
            return Conjunct('Authorized', False, f"decision is {a.get('decision')!r}")
        # The approval covers one signed observation: execution against any other (a re-observation,
        # a substituted or unsigned one) is refused, so Fresh is judged on what the approver saw.
        obs_stmt = observation.get('statement', {}) if isinstance(observation, dict) else {}
        ok, why = trust.verify_signed('source_observer', observation, obs_stmt.get('captured_at'))
        if not ok:
            return Conjunct('Authorized', False, f'observation signature: {why}')
        if a.get('source_record_digest') != observation.get('digest') or obs_stmt.get('tx_id') != proposal['tx_id']:
            return Conjunct('Authorized', False, 'authorization does not bind this observation')
        if a['tx_id'] != proposal['tx_id']:
            return Conjunct('Authorized', False, 'authorization transaction id differs from proposal')
        if a['asset_id'] != proposal['asset_id']:
            return Conjunct('Authorized', False, 'authorization asset differs from proposal')
        if a['target_config_digest'] != crypto.action_digest_hex(proposal):
            return Conjunct('Authorized', False, 'authorization does not cover this exact proposal')
        if a['policy_version'] != policy.version:
            return Conjunct('Authorized', False, f"authorization policy version {a['policy_version']} != active {policy.version}")
        if a.get('policy_digest') != policy.digest():
            return Conjunct('Authorized', False, 'authorization cites different content for this policy version')
        if a['expected_state_version'] != current_state['state_version']:
            return Conjunct('Authorized', False,
                            f"expected state version {a['expected_state_version']} != current {current_state['state_version']}")
        now = self.clock.now()
        if a['timestamp'] > now:
            return Conjunct('Authorized', False, f"authorization issued in the future ({a['timestamp']} > now {now})")
        if now > a['expires_at']:
            return Conjunct('Authorized', False, f"authorization expired at {a['expires_at']} (now {now})")
        lifetime = a['expires_at'] - a['timestamp']
        if lifetime > policy.approval_ttl_s:
            return Conjunct('Authorized', False,
                            f'authorization lifetime {lifetime}s exceeds policy approval TTL {policy.approval_ttl_s}s')
        if trust.key_for('authorizer', auth_signed.get('key_id', ''), now) is None:
            return Conjunct('Authorized', False, 'authorizer key is not valid at execution time')
        ok, why = recovery_permitted(policy, a.get('permitted_recovery'))
        if not ok:
            return Conjunct('Authorized', False, f'permitted recovery: {why}')
        return Conjunct('Authorized', True, f"approval {a['approval_basis']} covers tx {a['tx_id']}")

    def evaluate_pre_approval(self, observation_stmt: dict, proposal: dict, current_state: dict) -> GateDecision:
        policy = self.registry.active
        conj = [
            self.check_fresh(observation_stmt, current_state, policy),
            self.check_allowed(proposal, policy),
            self.check_compatible(proposal, observation_stmt, policy),
        ]
        return GateDecision(all(c.ok for c in conj), conj)

    def evaluate_full(self, observation: dict, proposal: dict, current_state: dict,
                      auth_signed: dict, trust: crypto.TrustConfig) -> GateDecision:
        """All four conjuncts at execution time; ``observation`` is the signed source observation."""
        policy = self.registry.active
        observation_stmt = observation['statement']
        conj = [
            self.check_fresh(observation_stmt, current_state, policy),
            self.check_allowed(proposal, policy),
            self.check_compatible(proposal, observation_stmt, policy),
            self.check_authorized(auth_signed, proposal, current_state, policy, trust, observation),
        ]
        return GateDecision(all(c.ok for c in conj), conj)
