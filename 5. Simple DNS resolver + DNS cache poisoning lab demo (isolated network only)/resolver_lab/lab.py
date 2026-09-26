"""Lab orchestrator: builds the isolated world, runs scenarios, scores verdicts.

Replaces container orchestration with an in-process world (ADR-001). The tripwire
(net.dropped) is checked after every trial; any out-of-prefix packet flips the verdict.
"""

import random

from . import config
from .attacker import Attacker
from .auth_server import AuthServer
from .packets import TYPE_A, TYPE_NS, msg_label
from .resolver import Resolver
from .scenarios import SCENARIOS, DEFAULT_DEFENSES, case_bits
from .transport import SimNetwork

TRUTH = config.TRUTH


def build_world(seed, defenses):
    rng = random.Random(seed)
    net = SimNetwork(safe=True)
    for ip, spec in config.zone_tables().items():
        AuthServer(ip, net, spec)
    zones_map = {
        config.ROOT_IP: '.',
        config.TLD_IP: 'local.',
        config.AUTH_IP: 'lab.local.',
        config.ATTACKER_IP: 'lab.local.',
    }
    resolver = Resolver(config.RESOLVER_IP, net, config.ROOT_IP, zones_map, defenses, rng=rng)
    return net, resolver, rng


def effective_defenses(scenario, overrides):
    d = dict(DEFAULT_DEFENSES)
    d.update(scenario.get('force_defenses', {}))
    d.update({k: v for k, v in (overrides or {}).items() if v is not None})
    return d


def entropy_bits(defenses, victim_name):
    bits = (16 if defenses.get('random_id') else 0) + (16 if defenses.get('random_port') else 0)
    if defenses.get('use_0x20'):
        bits += min(case_bits(victim_name), 12)
    return bits


def forged_rows(cache_rows):
    forged = []
    for row in cache_rows:
        name = row['name'].lower()
        if row['kind'] in ('answer', 'glue'):
            truth = TRUTH.get(name)
            if row['kind'] == 'answer':
                ok = truth is not None and list(row['rdata']) == list(truth[1])
            else:
                ok = row['name'].lower() == 'ns1.lab.local.'
            if not ok:
                row['forged'] = True
                forged.append(row)
        elif row['kind'] == 'delegation' and config.EVIL_NS in row['rdata']:
            row['forged'] = True
            forged.append(row)
    return forged


def _defens_attack_place(scenario, defenses, attacker, victim):
    ent = entropy_bits(defenses, victim['name'])
    win, prob = attacker.arm(
        victim['name'], attempts=scenario.get('attempts', 1),
        entropy_bits=ent,
    )
    return {'entropy_bits': ent, 'prob': round(prob, 6), 'win': win, 'attempts': scenario.get('attempts', 1)}


def _finish(net, resolver, scenario_id, seed, defenses, mode, victim, verdict,
            got, from_cache, probe=None, proton_fc=False, race=None, labels_tried=None,
            deleg_hit=None, notes=None):
    rows = resolver.cache.dump()
    forged = forged_rows(rows)
    timeline = []
    for p in net.packets[-600:]:
        timeline.append([p.seq, p.t, p.src[0], p.dst[0], msg_label(p.data)])
    return {
        'scenario': scenario_id,
        'seed': seed,
        'defenses': dict(defenses),
        'mode': mode,
        'victim': victim['name'],
        'verdict': verdict,
        'got': list(got),
        'from_cache': bool(from_cache),
        'probe': probe,
        'probe_got': list(proton_fc[0]) if probe else [],
        'race': race or {},
        'labels_tried': labels_tried,
        'deleg_hit': deleg_hit,
        'forged': forged,
        'cache': rows,
        'timeline': timeline,
        'notes': list(notes or []),
        'tripwire': len(net.dropped),
        'packets_total': net.packet_count(),
    }


def run_simple(scenario_id, seed, overrides=None, scenario=None):
    scenario = scenario if scenario is not None else SCENARIOS[scenario_id]
    sid = scenario_id
    name, qtype = scenario['victim']['name'], scenario['victim']['qtype']
    defenses = effective_defenses(scenario, overrides)
    net, resolver, rng = build_world(seed, defenses)
    attacker = Attacker(config.ATTACKER_IP, net, mode=scenario['attacker_mode'],
                        spoof_ip=scenario['spoof_ip'], payload=scenario['payload'], rng=rng)
    race = _defens_attack_place(scenario, defenses, attacker, scenario['victim'])
    rds, from_cache = resolver.resolve(name, qtype)

    probe = scenario.get('probe')
    probe_rds, probe_fc = ([], False)
    if probe:
        probe_rds, probe_fc = resolver.resolve(probe['name'], probe['qtype'])

    if scenario.get('probe'):
        poisoned = config.EVIL_A in probe_rds
        expected = config.EVIL_A if poisoned else 'clean/nxdomain'
        verdict = 'poisoned' if poisoned else 'blocked'
        got = probe_rds
        from_cache = probe_fc
    else:
        poisoned = config.EVIL_A in rds
        verdict = 'poisoned' if poisoned else 'blocked'
        expected = config.TRUTH.get(name.lower(), (None, ['—']))[1] if not poisoned else config.EVIL_A
        got = rds

    notes = list(resolver.events) + _attacker_notes(attacker, race)
    res = _finish(net, resolver, sid, seed, defenses, scenario['attacker_mode'],
                  scenario['victim'], verdict, got, from_cache, probe,
                  (probe_rds, probe_fc) if probe else None, race, notes=notes)
    res['expected'] = expected
    res['title'] = scenario['title']
    res['describe'] = scenario.get('describe', '')
    return res


def _attacker_notes(attacker, race):
    return [f'race prob={race["prob"]:.6f} win={race["win"]} attempts={race["attempts"]}',
            f'attacker stats: {attacker.stats}']


def run_kaminsky(scenario_id, seed, overrides=None, stop_event=None):
    scenario = SCENARIOS[scenario_id]
    defenses = effective_defenses(scenario, overrides)
    net, resolver, rng = build_world(seed, defenses)
    attacker = Attacker(config.ATTACKER_IP, net, mode='blind',
                        spoof_ip=scenario['spoof_ip'], payload=scenario['payload'], rng=rng)
    base = scenario['labels_base']
    max_labels = scenario.get('max_labels', 60)
    attempts = scenario.get('attempts', 150)
    labels = []
    deleg_hit = None
    last_race = {}

    for i in range(1, max_labels + 1):
        if stop_event and stop_event.is_set():
            break
        label = f'rr{i}.{base}'
        labels.append(label)
        ent = entropy_bits(defenses, label)
        win, prob = attacker.arm(label, attempts=attempts, entropy_bits=ent)
        last_race = {'entropy_bits': ent, 'prob': round(prob, 6), 'win': win, 'attempts': attempts}
        resolver.resolve(label, TYPE_A)
        if _deleg_poisoned(resolver.cache):
            deleg_hit = label
            break

    poisoned = deleg_hit is not None
    probe_rds, probe_fc = [], False
    if poisoned:
        attacker.clear()
        attacker.arm_serve_zone(config.EVIL_ZONE)
        probe_rds, probe_fc = resolver.resolve('www.lab.local.', TYPE_A)
    verdict = 'poisoned' if (poisoned and config.EVIL_A in probe_rds) else 'blocked'

    res = _finish(net, resolver, scenario_id, seed, defenses, 'blind', scenario['victim'],
                  verdict, probe_rds, probe_fc,
                  probe={'name': scenario['victim']['name'], 'qtype': TYPE_A},
                  proton_fc=(probe_rds, probe_fc),
                  race=last_race, labels_tried=len(labels), deleg_hit=deleg_hit,
                  notes=list(resolver.events) + [f'labels tried: {len(labels)}'])
    res['expected'] = config.EVIL_A if poisoned else config.TRUTH['www.lab.local.'][1]
    res['title'] = scenario['title']
    res['describe'] = scenario.get('describe', '')
    return res


def _deleg_poisoned(cache):
    for row in cache.dump():
        if row['kind'] == 'delegation' and config.EVIL_NS in row['rdata']:
            return True
    return False


def run_compare(scenario_id, seed, overrides=None):
    scenario = SCENARIOS[scenario_id]
    rows = []
    defenses = effective_defenses(scenario, overrides)
    for idx, combo in enumerate(scenario['combos']):
        combo_def = dict(defenses)
        combo_def.update(combo['defenses'])
        sub = dict(scenario)
        sub_id = f'{scenario_id}.{idx + 1}'
        res = run_simple(sub_id, seed + idx, overrides=combo_def, scenario=sub)
        res['combo'] = combo['label']
        rows.append(res)
    big = {
        'scenario': scenario_id,
        'title': scenario['title'],
        'describe': scenario.get('describe', ''),
        'seed': seed,
        'verdict': 'table',
        'comparison': rows,
        'forged': [],
        'timeline': [],
    }
    return big


def run_trial(scenario_id, seed, overrides=None, stop_event=None):
    scenario = SCENARIOS[scenario_id]
    if scenario_id == '03_kaminsky':
        return run_kaminsky(scenario_id, seed, overrides, stop_event)
    if scenario_id == '05_defense_compare':
        return run_compare(scenario_id, seed, overrides)
    return run_simple(scenario_id, seed, overrides)


def run_legit_check(seed=1, defenses=None):
    """Legitimacy invariant: with no attacker, the resolver returns the truth zone."""
    merged = dict(DEFAULT_DEFENSES)
    merged.update(defenses or {})
    defenses = merged
    net, resolver, _ = build_world(seed, defenses)
    results = {}
    for name, (qtype, rdatas) in TRUTH.items():
        rds, fc = resolver.resolve(name, TYPE_A)
        results[name] = (rds, fc, rds == rdatas)
    return results, net