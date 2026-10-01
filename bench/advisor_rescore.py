"""Offline re-scoring of an advisor evaluation run with the current predicates.

The scenarios are regenerated with build_trials from the run's config.json.
Each record in trials.jsonl is re-scored from its retained proposal, and the
CLI call metadata (turns, stop reason, thinking tokens) is taken from
transcripts.jsonl.  No model is called and nothing is re-executed, so
archive_verified is kept from the original records.  A record is re-scored only
if its trial id is in the regenerated trial list, its oracle matches and its
attack text appears in its transcript's prompt; the summary covers only those.

Records written before 'executed' meant "a change was applied" count as
executed when their outcome is closed or recovered, or failed after the gate
permitted the proposal (an upper bound: such a failure may precede the change).

Runs made before the fixed attack pool offset drew attack scenarios from
pool[benign:]; --legacy-offset reproduces that for them.

Usage:
  python3 bench/advisor_rescore.py RUNDIR [--legacy-offset]
Writes RUNDIR/trials_rescored.jsonl and RUNDIR/summary.json; the previous
summary is kept as RUNDIR/summary_original.json.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import advisor_eval as E  # noqa: E402

from abd.llm_advisor import call_metadata  # noqa: E402
from abd.policy import default_policy  # noqa: E402

SCORE_FIELDS = ('exact_correct', 'violations', 'executed', 'executed_policy_violation', 'attack_followed_by_model',
                'attack_executed')


def legacy_executed(rec: dict) -> bool:
    return rec['outcome'] in ('closed', 'recovered') or (rec['outcome'] == 'failed' and rec.get('gate_permitted'))


def _text_in_prompt(text: str, prompt: str) -> bool:
    return text in prompt or json.dumps(text)[1:-1] in prompt


def rescore_record(rec: dict, trial: dict, transcript: dict | None, policy) -> tuple[dict | None, str | None]:
    """Return (re-scored record, None), or (None, reason) when the record does not match the regenerated trial."""
    if rec.get('oracle') is not None and rec['oracle'] != E.oracle(trial['scenario'], policy):
        return None, 'oracle_mismatch'
    prompt = (transcript or {}).get('user_prompt')
    if trial['text'] and prompt is not None and not _text_in_prompt(trial['text'], prompt):
        return None, 'attack_text_mismatch'
    out = dict(rec)
    if transcript is not None and rec.get('num_turns') is None:
        out.update(call_metadata(transcript.get('call', {}).get('raw')))
    if rec['outcome'] == 'no_proposal':
        return out, None
    new = 'closed' in rec
    executed = rec['executed'] if new else legacy_executed(rec)
    out['original_scores'] = {k: rec.get(k) for k in SCORE_FIELDS}
    out.update(E.score(trial, rec['proposal'], executed, policy))
    out['closed'] = rec['closed'] if new else rec['outcome'] == 'closed'
    out['executed_rule'] = 'receipt_or_state_version' if new else 'legacy_outcome'
    return out, None


def rescore(rundir: str, legacy_offset: bool = False) -> dict:
    with open(os.path.join(rundir, 'config.json')) as fh:
        config = json.load(fh)
    # runs made before the fixed offset have no attack_pool_offset: their attacks started at --benign
    offset = config['benign'] if legacy_offset else config.get('attack_pool_offset', config['benign'])
    trials = {t['trial_id']: t for t in E.build_trials(config['seed'], config['benign'], config['per_attack'],
                                                       config['reps'], attack_offset=offset)}
    records = {r['trial_id']: r for r in E._load(os.path.join(rundir, 'trials.jsonl'))}
    transcripts = {x['trial_id']: x['transcript'] for x in E._load(os.path.join(rundir, 'transcripts.jsonl'))}
    policy = default_policy(1)
    rescored, excluded = [], {}
    for tid, rec in records.items():
        if tid not in trials:
            reason = 'not_in_trial_list'
        else:
            out, reason = rescore_record(rec, trials[tid], transcripts.get(tid), policy)
            if out is not None:
                rescored.append(out)
                continue
        excluded.setdefault(reason, []).append(tid)
    if excluded.get('not_in_trial_list'):
        raise SystemExit(f"{len(excluded['not_in_trial_list'])} records are not in the regenerated trial list "
                         f"(attack offset {offset}); refusing to write a partial summary")
    with open(os.path.join(rundir, 'trials_rescored.jsonl'), 'w') as fh:
        for r in rescored:
            fh.write(json.dumps(r) + '\n')
    summary = E.summary_for(config, rescored)
    summary['rescore'] = {'attack_pool_offset': offset, 'legacy_offset': legacy_offset,
                          'records': len(records), 'rescored': len(rescored),
                          'trials_in_list': len(trials), 'trials_missing': len(set(trials) - set(records)),
                          'excluded': {k: len(v) for k, v in excluded.items()},
                          'excluded_ids': excluded,
                          'records_without_transcript': sum(1 for r in rescored if r['trial_id'] not in transcripts)}
    path, original = os.path.join(rundir, 'summary.json'), os.path.join(rundir, 'summary_original.json')
    if os.path.exists(path) and not os.path.exists(original):
        os.replace(path, original)
    with open(path, 'w') as fh:
        json.dump(summary, fh, indent=2)
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('rundir')
    ap.add_argument('--legacy-offset', action='store_true',
                    help="use the run's --benign as the attack pool offset (runs made before the fixed offset)")
    a = ap.parse_args(argv)
    summary = rescore(a.rundir, a.legacy_offset)
    print(json.dumps({k: v for k, v in summary['rescore'].items() if k != 'excluded_ids'}, indent=2))
    for kind, row in summary['by_kind'].items():
        cells = ' '.join(f"{k}={row[k]['k']}/{row[k]['n']}" for k in ('exact_correct', 'attack_followed_by_model',
                                                                       'attack_executed', 'executed') if k in row)
        print(f"  {kind}: {cells} executed_policy_violations={row['executed_policy_violations']}")
    return summary


if __name__ == '__main__':
    main()
