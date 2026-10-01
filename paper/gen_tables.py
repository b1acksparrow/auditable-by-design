"""Render the measurement tables of Section VIII from results/v2/*.json."""

import json
import os
import re
import statistics
import sys

SRC = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(SRC, '..', 'results', 'v2')
# Generated files go next to this script unless an output directory is given (python3 gen_tables.py [OUTDIR]).
HERE = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else SRC
NUMBER_WORDS = {1: 'one', 2: 'two', 3: 'three', 4: 'four', 5: 'five', 6: 'six', 7: 'seven', 8: 'eight', 9: 'nine'}


def word(n):
    """IEEE style: numbers below ten are spelled out in running text."""
    return NUMBER_WORDS.get(n, f'{n:,}')


def timing():
    d = json.load(open(os.path.join(RES, 'timing_summary.json')))
    dur, nos = d['instrumented_durable'], d['instrumented_nosync']
    def calls(k, noun='call'):   # number of calls per transaction, from the timing summary
        c = dur[k].get('calls_per_tx')
        if c is None:
            raise KeyError(f"timing_summary.json: no calls_per_tx for '{k}'")
        word = NUMBER_WORDS.get(c, str(c))
        return f"{word} {noun}{'' if c == 1 else 's'}" if noun else word
    rows = [
        (f"ML-DSA-65 signing ({calls('sign')})", 'sign'),
        (f"ML-DSA-65 verification ({calls('verify')})", 'verify'),
        ('Canonical serialization', 'canonical'),
        ('Hashing (SHA-384)', 'hash'),
        ('Hexadecimal encoding', 'hex'),
        ('ML-KEM-768 operation', 'kem'),
        (f"Durable store commits ({calls('sqlite', None)})", 'sqlite'),
        ('Everything else', 'residual'),
    ]
    out = []
    for label, k in rows:
        out.append(f"{label} & {dur[k]['median_ms']:.3f} & {dur[k]['p95_ms']:.3f} & {dur[k]['share_of_median_total_pct']:.1f} "
                   f"& {nos[k]['median_ms']:.3f} & {nos[k]['p95_ms']:.3f} & {nos[k]['share_of_median_total_pct']:.1f} \\\\")
    out.append('\\midrule')
    out.append(f"Instrumented total & {dur['total']['median_ms']:.3f} & {dur['total']['p95_ms']:.3f} & 100.0 "
               f"& {nos['total']['median_ms']:.3f} & {nos['total']['p95_ms']:.3f} & 100.0 \\\\")
    u = d['uninstrumented_durable_total']
    out.append(f"Uninstrumented construction & {u['median_ms']:.3f} & {u['p95_ms']:.3f} & --- & --- & --- & --- \\\\")
    out.append('\\bottomrule')
    open(os.path.join(HERE, 'tab_timing.tex'), 'w').write('\n'.join(out) + '%\n')
    macros = [
        f"\\newcommand{{\\TimDurTotal}}{{{dur['total']['median_ms']:.2f}}}",
        f"\\newcommand{{\\TimDurSqlite}}{{{dur['sqlite']['median_ms']:.2f}}}",
        f"\\newcommand{{\\TimDurSqlitePct}}{{{dur['sqlite']['share_of_median_total_pct']:.1f}}}",
        f"\\newcommand{{\\TimDurSign}}{{{dur['sign']['median_ms']:.3f}}}",
        f"\\newcommand{{\\TimNoTotal}}{{{nos['total']['median_ms']:.2f}}}",
        f"\\newcommand{{\\TimNoSign}}{{{nos['sign']['median_ms']:.3f}}}",
        f"\\newcommand{{\\TimNoSignPct}}{{{nos['sign']['share_of_median_total_pct']:.1f}}}",
        f"\\newcommand{{\\TimNoCanon}}{{{nos['canonical']['median_ms']:.3f}}}",
        f"\\newcommand{{\\TimNoCanonPct}}{{{nos['canonical']['share_of_median_total_pct']:.1f}}}",
        f"\\newcommand{{\\RecordBytes}}{{{d['record_bytes_json']:,}}}",
        f"\\newcommand{{\\TimDurPNinetyFiveInst}}{{{dur['total']['p95_ms']:.2f}}}",
        f"\\newcommand{{\\TimDurPNinetyFiveUninst}}{{{u['p95_ms']:.2f}}}",
        f"\\newcommand{{\\TimNoCanonPctR}}{{{nos['canonical']['share_of_median_total_pct']:.0f}}}",
        f"\\newcommand{{\\TimDurSqlitePctR}}{{{dur['sqlite']['share_of_median_total_pct']:.0f}}}",
        f"\\newcommand{{\\TimDurSignPct}}{{{dur['sign']['share_of_median_total_pct']:.1f}}}",
        f"\\newcommand{{\\TimWarmup}}{{{d['protocol'].split()[0]}}}",
        f"\\newcommand{{\\TimTimed}}{{{d['protocol'].split()[3]}}}",   # '300 warm-up + 200 timed ...'
        f"\\newcommand{{\\TimWalPages}}{{{d.get('wal_autocheckpoint_pages', 1000):,}}}",
    ]
    cs = d.get('cold_start_first_warmup_tx', {})
    if cs:
        macros.append(f"\\newcommand{{\\TimColdStart}}{{{cs['instrumented_durable']['median_ms']:.1f}}}")
        macros.append(f"\\newcommand{{\\TimColdStartN}}{{{cs['instrumented_durable']['transactions']}}}")
        macros.append(f"\\newcommand{{\\TimColdRatio}}{{{cs['instrumented_durable']['median_ms'] / dur['total']['median_ms']:.1f}}}")
    return macros


def scaling():
    p = os.path.join(RES, 'scaling_results.json')
    if not os.path.exists(p):
        return []
    d = json.load(open(p))
    out = []
    macros = []
    for r in d['results']:
        n = r['transactions']
        st = r['streaming']
        im = r.get('in_memory')
        p95 = f"{st['p95_s']:.4f}" if st['p95_s'] is not None else '---'
        im_med = f"{im['median_s']:.4f}" if im else '---'
        rss = r['fresh_process_streaming']['peak_rss_mib']
        out.append(f"{n:,} & {r['archive_mib']:,.2f} & {st['median_s']:.4f} & {p95} & {im_med} & {rss:.1f} & {r['warmup']} & {r['timed']} \\\\")
        tag = {10: 'Ten', 100: 'Hundred', 1000: 'Thousand', 10000: 'TenK', 100000: 'HundredK'}[n]
        macros.append(f"\\newcommand{{\\Scal{tag}Med}}{{{st['median_s']:.3f}}}")
        macros.append(f"\\newcommand{{\\Scal{tag}Rss}}{{{rss:.0f}}}")
        macros.append(f"\\newcommand{{\\Scal{tag}PerTx}}{{{1000 * st['median_s'] / n:.3f}}}")
        macros.append(f"\\newcommand{{\\Scal{tag}Mib}}{{{r['archive_mib']:,.0f}}}")
        macros.append(f"\\newcommand{{\\Scal{tag}MedR}}{{{st['median_s']:.1f}}}")
    out.append('\\bottomrule')
    open(os.path.join(HERE, 'tab_scaling.tex'), 'w').write('\n'.join(out) + '%\n')
    return macros


def environment():
    e = json.load(open(os.path.join(RES, 'environment.json')))
    compiler = re.sub(r'^GCC: \(.*\) ', 'GCC ', e['compiler'])   # 'GCC: (Debian 15.2.0-17) 15.2.0' -> 'GCC 15.2.0'
    return [
        f"\\newcommand{{\\EnvCpu}}{{{e['cpu_model'].replace('(R)', '').replace('(TM)', '')}}}",
        f"\\newcommand{{\\EnvMem}}{{{e['mem_total_mib'] / 1024:.1f}}}",
        f"\\newcommand{{\\EnvPython}}{{{e['python']}}}",
        f"\\newcommand{{\\EnvKernel}}{{{e['kernel']}}}",
        f"\\newcommand{{\\EnvLiboqs}}{{{e['liboqs']}}}",
        f"\\newcommand{{\\EnvCompiler}}{{{compiler}}}",
        f"\\newcommand{{\\EnvSqlite}}{{{e['sqlite']}}}",
        f"\\newcommand{{\\EnvDate}}{{{e['timestamp_utc'][:10]}}}",
    ]


def tests():
    import xml.etree.ElementTree as ET
    p = os.path.join(RES, 'junit.xml')
    if not os.path.exists(p):
        return []
    root = ET.parse(p).getroot()
    suites = root.findall('testsuite') if root.tag == 'testsuites' else [root]
    total = sum(int(s.get('tests', 0)) for s in suites)
    bad = sum(int(s.get('failures', 0)) + int(s.get('errors', 0)) + int(s.get('skipped', 0)) for s in suites)
    return [f"\\newcommand{{\\NumTests}}{{{total}}}", f"\\newcommand{{\\NumTestsPassed}}{{{total - bad}}}"]


ADVISOR_ROWS = [
    ('A1_off_allowlist', 'A1 off-allowlist profile'),
    ('A2_downgrade_classical', 'A2 below-floor profile'),
    ('A3_incompatible_peer', 'A3 incompatible peer'),
    ('A4_config_tamper', 'A4 tampered configuration'),
    ('A5_action_substitution', 'A5 unpermitted action'),
    ('A6_exclude_ready_peer', 'A6 omit a ready peer$^\\dagger$'),
    ('A7_weaker_profile', 'A7 weaker allowed profile$^\\dagger$'),
]
CONDITIONS = (('hardened', 'Hard', 'Hardened'), ('naive', 'Naive', 'Naive'), ('compromised', 'Comp', 'Compromised'))


def _advisor(condition):
    p = os.path.join(RES, f'advisor-{condition}', 'summary.json')
    return json.load(open(p)) if os.path.exists(p) else None


def _frac(cell):
    return f"{cell['k']}/{cell['n']}" if cell and cell.get('n') else '---'


def _get(d, *path):
    for k in path:
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


def _executed_cell(row, model):
    """Executed k/n; for a model condition the number followed is appended in parentheses when it differs."""
    if not row:
        return '---'
    ex, fo = row.get('attack_executed'), row.get('attack_followed_by_model')
    cell = _frac(ex)
    if model and ex and fo and fo['k'] != ex['k']:
        cell += f" ({fo['k']})"
    return cell


def advisor():
    """Tables and macros for the language-model advisor evaluation (three paired conditions).

    tab_advisor.tex        main-text table: attacks executed per condition, benign quality, archives verified;
    tab_advisor_detail.tex supplementary table: within-policy attacks and the A2 true-downgrade subset by
                           placement and at scenario level."""
    runs = {c: _advisor(c) for c, _, _ in CONDITIONS}
    if not any(runs.values()):
        return []
    by = {c: (r['by_kind'] if r else {}) for c, r in runs.items()}

    out = []
    for kind, label in ADVISOR_ROWS:
        cells = [_executed_cell(by[c].get(kind), c != 'compromised') for c, _, _ in CONDITIONS]
        out.append(f"{label} & " + ' & '.join(cells) + ' \\\\')
    out.append('\\midrule')
    for key, label in (('exact_correct', 'Benign: matches oracle'), ('executed', 'Benign: executed')):
        cells = [_frac(_get(by[c], 'benign', key)) for c, _, _ in CONDITIONS]
        out.append(f"{label} & " + ' & '.join(cells) + ' \\\\')
    cells = []
    for c, _, _ in CONDITIONS:
        v = [r['archive_verified'] for r in by[c].values()]
        cells.append(f"{sum(x['k'] for x in v)}/{sum(x['n'] for x in v)}" if v else '---')
    out.append('Archives verified & ' + ' & '.join(cells) + ' \\\\')
    out.append('\\bottomrule')
    open(os.path.join(HERE, 'tab_advisor.tex'), 'w').write('\n'.join(out) + '%\n')

    detail = []
    for kind, label, sub in (('A6_exclude_ready_peer', 'A6 omit a ready peer', None),
                             ('A7_weaker_profile', 'A7 weaker allowed profile', None),
                             ('A2_downgrade_classical', 'A2, current profile hybrid', 'true_downgrade_subset')):
        first = True
        for c, _, name in CONDITIONS:
            row = by[c].get(kind)
            if not row:
                continue
            if sub:
                row = row.get(sub)
                if not row:
                    continue
            fo = _frac(row.get('attack_followed_by_model')) if c != 'compromised' else '---'
            doc = _frac(_get(row, 'by_placement', 'document', 'attack_executed'))
            note = _frac(_get(row, 'by_placement', 'inventory_note', 'attack_executed'))
            any_rep = _frac(_get(row, 'scenario_level', 'attack_executed', 'any_rep'))
            all_reps = _frac(_get(row, 'scenario_level', 'attack_executed', 'all_reps'))
            detail.append(f"{label if first else ''} & {name} & {fo} & {_frac(row.get('attack_executed'))} & {doc} "
                          f"& {note} & {any_rep} & {all_reps} \\\\")
            first = False
        detail.append('\\midrule')
    if detail and detail[-1] == '\\midrule':
        detail.pop()
    detail.append('\\bottomrule')
    open(os.path.join(HERE, 'tab_advisor_detail.tex'), 'w').write('\n'.join(detail) + '%\n')

    def total(cond, key, violating):
        k = n = 0
        for kind, _ in ADVISOR_ROWS:
            row = by[cond].get(kind)
            if row and row['policy_violating_class'] == violating and row.get(key):
                k += row[key]['k']
                n += row[key]['n']
        return f'{k}/{n}' if n else '---'

    macros = []
    for cond, tag, _ in CONDITIONS:
        if not runs[cond]:
            continue
        macros.append(f"\\newcommand{{\\Adv{tag}ViolFollowed}}{{{total(cond, 'attack_followed_by_model', True)}}}")
        macros.append(f"\\newcommand{{\\Adv{tag}ViolExecuted}}{{{total(cond, 'attack_executed', True)}}}")
        macros.append(f"\\newcommand{{\\Adv{tag}InPolicyFollowed}}{{{total(cond, 'attack_followed_by_model', False)}}}")
        macros.append(f"\\newcommand{{\\Adv{tag}InPolicyExecuted}}{{{total(cond, 'attack_executed', False)}}}")
        viol = sum(r['executed_policy_violations'] for r in by[cond].values())
        macros.append(f"\\newcommand{{\\Adv{tag}ExecutedViolations}}{{{viol}}}")
        verified = [r['archive_verified'] for r in by[cond].values()]
        macros.append(f"\\newcommand{{\\Adv{tag}Verified}}{{{sum(v['k'] for v in verified)}/{sum(v['n'] for v in verified)}}}")
        macros.append(f"\\newcommand{{\\Adv{tag}NoProposal}}{{{sum(r.get('no_proposal', 0) for r in by[cond].values())}}}")
        benign = by[cond].get('benign')
        if benign:
            macros.append(f"\\newcommand{{\\Adv{tag}BenignExact}}{{{_frac(benign['exact_correct'])}}}")
            macros.append(f"\\newcommand{{\\Adv{tag}BenignExecuted}}{{{_frac(benign['executed'])}}}")
            macros.append(f"\\newcommand{{\\Adv{tag}BenignSuboptimal}}{{{benign['executed_suboptimal']}}}")
            macros.append(f"\\newcommand{{\\Adv{tag}BenignWrongDenied}}{{{benign['correct_but_denied']}}}")
            macros.append(f"\\newcommand{{\\Adv{tag}BenignNoProposal}}{{{benign['no_proposal']}}}")
            macros.append(f"\\newcommand{{\\Adv{tag}MedianLatency}}{{{benign['median_wall_ms'] / 1000:.1f}}}")
            macros.append(f"\\newcommand{{\\Adv{tag}BenignScen}}{{{benign['scenario_level']['scenarios']}}}")
            # benign trials refused per gate conjunct (a trial refused by two conjuncts counts under both)
            den = benign.get('denials_by_conjunct') or {}
            macros.append(f"\\newcommand{{\\Adv{tag}BenignDeniedAllowed}}{{{den.get('Allowed', 0)}}}")
            macros.append(f"\\newcommand{{\\Adv{tag}BenignDeniedCompatible}}{{{den.get('Compatible', 0)}}}")
        # within-policy attacks by placement and at scenario level; A2 true-downgrade subset
        for kind, ktag in (('A6_exclude_ready_peer', 'ASix'), ('A7_weaker_profile', 'ASeven')):
            row = by[cond].get(kind)
            if not row:
                continue
            macros.append(f"\\newcommand{{\\Adv{tag}{ktag}Exec}}{{{_frac(row.get('attack_executed'))}}}")
            macros.append(f"\\newcommand{{\\Adv{tag}{ktag}Doc}}{{{_frac(_get(row, 'by_placement', 'document', 'attack_executed'))}}}")
            macros.append(f"\\newcommand{{\\Adv{tag}{ktag}Note}}{{{_frac(_get(row, 'by_placement', 'inventory_note', 'attack_executed'))}}}")
            macros.append(f"\\newcommand{{\\Adv{tag}{ktag}ScenAny}}{{{_frac(_get(row, 'scenario_level', 'attack_executed', 'any_rep'))}}}")
            macros.append(f"\\newcommand{{\\Adv{tag}{ktag}ScenAll}}{{{_frac(_get(row, 'scenario_level', 'attack_executed', 'all_reps'))}}}")
            macros.append(f"\\newcommand{{\\Adv{tag}{ktag}Scen}}{{{_get(row, 'scenario_level', 'scenarios')}}}")
            if 'profile_switched' in row:   # executed A6 proposals that also changed the target profile
                macros.append(f"\\newcommand{{\\Adv{tag}{ktag}Switched}}{{{row['profile_switched'].get('executed', 0)}}}")
        td = _get(by[cond], 'A2_downgrade_classical', 'true_downgrade_subset')
        if td:
            macros.append(f"\\newcommand{{\\Adv{tag}ATwoTrueFollowed}}{{{_frac(td.get('attack_followed_by_model'))}}}")
            macros.append(f"\\newcommand{{\\Adv{tag}ATwoTrueExecuted}}{{{_frac(td.get('attack_executed'))}}}")
        mc = runs[cond].get('model_calls') or {}
        if mc.get('calls'):
            retried = sum(v for t, v in mc.get('num_turns', {}).items() if int(t) > 2)
            macros.append(f"\\newcommand{{\\Adv{tag}Calls}}{{{mc['calls']}}}")
            macros.append(f"\\newcommand{{\\Adv{tag}CallsRetried}}{{{retried}}}")
            macros.append(f"\\newcommand{{\\Adv{tag}CallsThinking}}{{{mc.get('with_thinking', 0)}}}")
        macros.append(f"\\newcommand{{\\Adv{tag}Trials}}{{{runs[cond]['config']['trials_total']}}}")
    cfg = (runs['hardened'] or runs['naive'] or {}).get('config', {})
    if cfg.get('model_interface'):
        mi = cfg['model_interface']
        macros.append(f"\\newcommand{{\\AdvModel}}{{{mi['name']}}}")
        macros.append(f"\\newcommand{{\\AdvInterface}}{{Claude Code {mi['interface_version'].split()[0]}}}")
        macros.append(f"\\newcommand{{\\AdvReps}}{{{cfg['reps']}}}")
        macros.append(f"\\newcommand{{\\AdvRepsWord}}{{{word(cfg['reps'])}}}")
        macros.append(f"\\newcommand{{\\AdvSeed}}{{{cfg['seed']}}}")
        macros.append(f"\\newcommand{{\\AdvPerAttack}}{{{cfg['per_attack']}}}")
    for cond, tag, _ in CONDITIONS:
        if runs[cond]:
            macros.append(f"\\newcommand{{\\Adv{tag}Reps}}{{{runs[cond]['config']['reps']}}}")
    # attack pool offset (recorded by the runs made after the fixed offset was introduced)
    offsets = {r['config']['attack_pool_offset'] for r in runs.values() if r and 'attack_pool_offset' in r['config']}
    if offsets:
        assert len(offsets) == 1, offsets
        macros.append(f"\\newcommand{{\\AdvAttackOffset}}{{{offsets.pop()}}}")
    return macros


def zk():
    """Macros for the RISC Zero instantiation of relation R (bench/bench_zk.py)."""
    p = os.path.join(RES, 'zk', 'zk_results.json')
    if not os.path.exists(p):
        return []
    d = json.load(open(p))
    s = d['summary']
    # The measured execution length is the lift program named by the receipt's control id (lift_po2);
    # segment_po2 is only the configured segment limit.
    if s['segments'] == 1:
        assert s['total_cycles'] == 2 ** s['lift_po2'], (s['total_cycles'], s['lift_po2'])
    return [
        f"\\newcommand{{\\ZkVersion}}{{{d['risc0_version']}}}",
        f"\\newcommand{{\\ZkProveMed}}{{{s['prove_s_median']:.1f}}}",
        f"\\newcommand{{\\ZkVerifyMs}}{{{s['verify_ms_median']:.1f}}}",
        f"\\newcommand{{\\ZkReceiptKiB}}{{{s['receipt_bytes'] / 1024:.0f}}}",
        f"\\newcommand{{\\ZkPeakGiB}}{{{s['peak_rss_kib_max'] / 2**20:.1f}}}",
        f"\\newcommand{{\\ZkCycles}}{{{s['total_cycles']:,}}}",
        f"\\newcommand{{\\ZkUserCycles}}{{{s['user_cycles']:,}}}",
        f"\\newcommand{{\\ZkSegments}}{{{s['segments']}}}",
        f"\\newcommand{{\\ZkSegmentsWord}}{{{word(s['segments'])}}}",
        f"\\newcommand{{\\ZkPo}}{{{s['lift_po2']}}}",
        f"\\newcommand{{\\ZkRuns}}{{{s['runs']}}}",
        f"\\newcommand{{\\ZkRunsWord}}{{{word(s['runs'])}}}",
        f"\\newcommand{{\\ZkActionBytes}}{{{s['action_bytes']}}}",
    ] + ([
        f"\\newcommand{{\\ZkMaxPo}}{{{s['soundness']['max_accepted_po2']}}}",
        f"\\newcommand{{\\ZkSegBits}}{{{s['soundness']['segment_toy_model_bits']:.1f}}}",
        f"\\newcommand{{\\ZkRecBits}}{{{s['soundness']['recursion_toy_model_bits']:.1f}}}",
        f"\\newcommand{{\\ZkEndBits}}{{{s['soundness']['end_to_end_toy_model_bits']:.1f}}}",
        f"\\newcommand{{\\ZkStrictBits}}{{{s['soundness']['end_to_end_conjectured_strict_bits']:.1f}}}",
        f"\\newcommand{{\\ZkProvenBits}}{{{s['soundness']['end_to_end_proven_bits']:.1f}}}",
    ] if s.get('soundness') else [])


def tls():
    """Table and macros for the deployed-service observation (bench/bench_tls.py)."""
    p = os.path.join(RES, 'tls', 'tls_results.json')
    if not os.path.exists(p):
        return []
    d = json.load(open(p))
    if 'scenarios' not in d:
        return []
    display = {'ecdh_x25519': 'X25519', 'x25519': 'X25519', 'prime256v1': 'secp256r1'}   # trace -> IANA names
    labels = {'legacy_classical': 'Legacy', 'x25519_hybrid': 'X25519 hybrid',
              'p256_hybrid': 'P-256 hybrid', 'pqc_strict': 'ML-KEM only'}

    def cell(obs, cls):
        r = obs['per_client'].get(cls, {})
        if not r.get('handshake_ok'):
            return 'fails'
        g = display.get(r['negotiated_group'], r['negotiated_group'])
        return g.replace('_', '\\_')
    names = sorted(d['scenarios'])
    out = []
    for cls in d['reference_clients']:
        cells = [cell(d['base'], cls)] + [cell(d['scenarios'][n]['after'], cls) for n in names]
        out.append(f"{labels.get(cls, cls)} & " + ' & '.join(cells) + ' \\\\')
    out.append('\\bottomrule')
    open(os.path.join(HERE, 'tab_tls.tex'), 'w').write('\n'.join(out) + '%\n')
    wall = d['probe_wall_time']
    hy = wall['per_class'].get('x25519_hybrid', {})
    probe_n = {v['n'] for v in wall['per_class'].values() if v.get('ok')}   # classes that complete a handshake
    assert len(probe_n) == 1, probe_n
    macros = [
        f"\\newcommand{{\\TlsNginx}}{{{d['tools']['nginx'].split('/')[-1]}}}",
        f"\\newcommand{{\\TlsOpenssl}}{{{d['tools']['openssl'].split()[1]}}}",
        f"\\newcommand{{\\TlsBaseConfig}}{{{d['base_config']}}}",
        f"\\newcommand{{\\TlsProbeMs}}{{{hy.get('median_probe_wall_ms_incl_process_start', 0):.1f}}}",
        f"\\newcommand{{\\TlsBaselineMs}}{{{wall['process_start_baseline']['median_ms']:.1f}}}",
        f"\\newcommand{{\\TlsProbeNetMs}}{{{hy.get('median_probe_minus_baseline_ms', 0):.1f}}}",
        f"\\newcommand{{\\TlsProbeN}}{{{probe_n.pop()}}}",
        f"\\newcommand{{\\TlsBaselineN}}{{{wall['process_start_baseline']['n']}}}",
        f"\\newcommand{{\\TlsPanelHolds}}{{{'yes' if d['panel']['no_single_peer_detects_all_but_panel_does'] else 'no'}}}",
    ]
    for n, tag in zip(names, 'AB'):
        sc = d['scenarios'][n]
        macros.append(f"\\newcommand{{\\TlsRemoved{tag}}}{{{sc['removed_group']}}}")
        hit = [x['client_class'] for x in sc['detection']['downgraded']]
        macros.append(f"\\newcommand{{\\TlsHit{tag}}}{{{labels.get(hit[0], hit[0]) if hit else 'none'}}}")
        macros.append(f"\\newcommand{{\\TlsStillServes{tag}}}{{{'yes' if sc['config_still_valid_and_serves'] else 'no'}}}")
    return macros


def memory_slope():
    """Verifier memory growth per transaction between the two largest sizes (VmHWM)."""
    p = os.path.join(RES, 'scaling_results.json')
    if not os.path.exists(p):
        return []
    rows = {r['transactions']: r['fresh_process_streaming']['peak_rss_mib'] for r in json.load(open(p))['results']}
    if 10_000 not in rows or 100_000 not in rows:
        return []
    kib = (rows[100_000] - rows[10_000]) * 1024 / 90_000
    return [f"\\newcommand{{\\ScalKiBPerTx}}{{{kib:.1f}}}"]


def wal_onset(totals_ms, window=20, factor=0.5):
    """0-based index of the first steady-state transaction: the first transaction faster than factor x the
    median of the first ten whose window of `window` transactions, starting with it, also has a median below
    that level.  (bench_wal.first_steady returns the start of the first such window, which can lie several
    transactions before the first fast one, so its first_steady_tx field is not used.)"""
    level = factor * statistics.median(totals_ms[:10])
    for i in range(len(totals_ms) - window):
        if totals_ms[i] < level and statistics.median(totals_ms[i:i + window]) < level:
            return i
    return None


def wal():
    """Macros for the wal_autocheckpoint sweep (bench/bench_wal.py), computed from the per-transaction times."""
    p = os.path.join(RES, 'wal', 'wal_results.json')
    if not os.path.exists(p):
        return []
    names = {250: 'A', 1000: 'B', 4000: 'C'}
    out = []
    counts = set()
    for r in json.load(open(p))['results']:
        t = names.get(r['wal_autocheckpoint_pages'])
        tot = r['totals_ms']
        i = wal_onset(tot)
        if t is None or not i:
            continue
        counts.add(r['transactions'])
        out.append(f"\\newcommand{{\\WalPages{t}}}{{{r['wal_autocheckpoint_pages']:,}}}")
        out.append(f"\\newcommand{{\\WalSteady{t}}}{{{i + 1}}}")          # 1-based transaction number
        out.append(f"\\newcommand{{\\WalBefore{t}}}{{{statistics.median(tot[:i]):.1f}}}")
        out.append(f"\\newcommand{{\\WalAfter{t}}}{{{statistics.median(tot[i:]):.1f}}}")
    if len(counts) == 1:
        out.append(f"\\newcommand{{\\WalTx}}{{{counts.pop()}}}")
    return out


def oldchecker():
    """Like-for-like memory comparison with the earlier checker (bench/bench_oldchecker.py)."""
    p = os.path.join(RES, 'oldchecker', 'oldchecker_results.json')
    sp = os.path.join(RES, 'scaling_results.json')
    if not (os.path.exists(p) and os.path.exists(sp)):
        return []
    new = {r['transactions']: r['fresh_process_streaming']['peak_rss_mib'] for r in json.load(open(sp))['results']}
    tags = {1000: 'Thousand', 10000: 'TenK', 100000: 'HundredK'}
    out = []
    for r in json.load(open(p))['results']:
        tag = tags.get(r['transactions'])
        if tag is None:
            continue
        if r.get('completed') and r.get('verified'):
            out.append(f"\\newcommand{{\\Old{tag}Rss}}{{{r['peak_rss_mib']:,.0f}}}")
            out.append(f"\\newcommand{{\\Old{tag}GiB}}{{{r['peak_rss_mib'] / 1024:.1f}}}")
            out.append(f"\\newcommand{{\\Old{tag}ArchiveMiB}}{{{r['archive_mib']:,.0f}}}")
            out.append(f"\\newcommand{{\\Old{tag}Wall}}{{{r['wall_s_load_and_verify']:.1f}}}")
            if r['transactions'] in new:
                ratio = r['peak_rss_mib'] / new[r['transactions']]
                out.append(f"\\newcommand{{\\Old{tag}Ratio}}{{{ratio:.1f}}}" if ratio < 10 else
                           f"\\newcommand{{\\Old{tag}Ratio}}{{{ratio:.0f}}}")
        else:
            out.append(f"\\newcommand{{\\Old{tag}Rss}}{{>{r['address_space_limit_gib']:.0f}\\,GiB}}")
    limits = {r['address_space_limit_gib'] for r in json.load(open(p))['results']}
    if len(limits) == 1:
        out.append(f"\\newcommand{{\\OldAsLimitGiB}}{{{limits.pop():.0f}}}")
    done = {r['transactions']: r['peak_rss_mib'] for r in json.load(open(p))['results']
            if r.get('completed') and r.get('verified')}
    if 10_000 in done and 100_000 in done:   # growth per transaction between the two largest sizes
        out.append(f"\\newcommand{{\\OldKiBPerTx}}{{{(done[100_000] - done[10_000]) * 1024 / 90_000:.0f}}}")
    return out


def ratio():
    # 11.2 GiB was the earlier prototype's whole-process peak, which included archive construction and a full
    # serialization; it is not a checker measurement.  No ratio is derived from it: the like-for-like
    # comparison is oldchecker() (Table S-IX).
    return ["\\newcommand{\\ScalOldPeakGiB}{11.2}"]


if __name__ == '__main__':
    macros = (timing() + scaling() + environment() + tests() + ratio() + memory_slope() + wal() + oldchecker()
              + advisor() + zk() + tls())
    open(os.path.join(HERE, 'results_macros.tex'), 'w').write('\n'.join(macros) + '\n')
    print('\n'.join(macros))
