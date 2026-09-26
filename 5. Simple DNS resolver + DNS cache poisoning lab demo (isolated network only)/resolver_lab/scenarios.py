"""Scenario catalogue and payload builders (architecture.md section 9, 13).

Each scenario declares: the attacker knowledge model, the victim query, the spoofed
source server, the injection payload, entropy assumptions, and the verdict probe.
Entropy bits are computed from the *effective* resolver defenses at run time so the
attacker's race model and the resolver's behavior always agree.
"""

from . import config
from .packets import TYPE_A, TYPE_NS

PAYLOAD_POISON_ANSWER = [
    {'section': 'answer', 'name': 'demosrv.lab.local.', 'rtype': TYPE_A,
     'ttl': config.EVIL_TTL, 'rdata': config.EVIL_A},
]

PAYLOAD_BAILIWICK = [
    {'section': 'answer', 'name': 'www.lab.local.', 'rtype': TYPE_A,
     'ttl': config.DEFAULT_TTL, 'rdata': config.TRUTH['www.lab.local.'][1][0]},
    {'section': 'additional', 'name': config.OTHER_ZONE_NAME, 'rtype': TYPE_A,
     'ttl': config.EVIL_TTL, 'rdata': config.EVIL_A},
]

PAYLOAD_KAMINSKY = [
    {'section': 'authority', 'name': 'lab.local.', 'rtype': TYPE_NS,
     'ttl': config.EVIL_TTL, 'rdata': config.EVIL_NS},
    {'section': 'additional', 'name': config.EVIL_NS, 'rtype': TYPE_A,
     'ttl': config.EVIL_TTL, 'rdata': config.EVIL_GLUE_ADDR},
]

SCENARIOS = {
    '01_static_id': {
        'title': 'Static transaction-ID spoofing',
        'attacker_mode': 'blind',
        'spoof_ip': config.AUTH_IP,
        'victim': {'name': 'demosrv.lab.local.', 'qtype': TYPE_A},
        'payload': PAYLOAD_POISON_ANSWER,
        'attempts': 2,
        'force_defenses': {'random_id': False, 'random_port': False, 'use_0x20': False},
        'has_serve': False,
        'describe': 'The resolver uses a predictable (static) transaction ID. The '
                    'attacker knows the algorithm, so its spoofed answer wins the race '
                    'almost certainly.',
    },
    '02_id_guess': {
        'title': 'Random-ID guessing race',
        'attacker_mode': 'blind',
        'spoof_ip': config.AUTH_IP,
        'victim': {'name': 'demosrv.lab.local.', 'qtype': TYPE_A},
        'payload': PAYLOAD_POISON_ANSWER,
        'attempts': 21000,
        'force_defenses': {},
        'has_serve': False,
        'describe': 'The resolver randomizes the 16-bit ID. The blind attacker floods '
                    'guesses; each has probability ~1/65536, so a busy flood still wins '
                    'a few per cent of the time (Kaminsky-era entropy). Run the same '
                    'seed a few times: it sometimes poisons, sometimes misses.',
    },
    '03_kaminsky': {
        'title': 'Kaminsky-style zone delegation poisoning',
        'attacker_mode': 'blind',
        'spoof_ip': config.TLD_IP,
        'victim': {'name': 'rr1.lab.local.', 'qtype': TYPE_A},
        'payload': PAYLOAD_KAMINSKY,
        'attempts': 150,
        'force_defenses': {'random_id': False, 'random_port': False, 'use_0x20': False},
        'has_serve': True,
        'max_labels': 60,
        'labels_base': 'lab.local.',
        'describe': 'Each fresh random subdomain label forces a new query. The attacker '
                    'floods replies claiming to be the TLD and injects a poisoned '
                    'delegation for the whole zone (bailiwick-compatible by design!). '
                    'Only entropy (ID/port/0x20) stops it.',
    },
    '04_bailiwick': {
        'title': 'Out-of-zone (bailiwick violation) glue injection',
        'attacker_mode': 'eavesdrop',
        'spoof_ip': config.AUTH_IP,
        'victim': {'name': 'www.lab.local.', 'qtype': TYPE_A},
        'payload': PAYLOAD_BAILIWICK,
        'attempts': 1,
        'force_defenses': {},
        'has_serve': False,
        'probe': {'name': config.OTHER_ZONE_NAME, 'qtype': TYPE_A},
        'describe': 'The on-path attacker answers a query it can see and stuffs an '
                    'out-of-zone additional record into the response. With the '
                    'bailiwick check ON that record is refused; with it OFF it is '
                    'cached and the probe resolves to the attacker address.',
    },
    '05_defense_compare': {
        'title': 'Defense comparison (entropy budget)',
        'attacker_mode': 'blind',
        'spoof_ip': config.AUTH_IP,
        'victim': {'name': 'demosrv.lab.local.', 'qtype': TYPE_A},
        'payload': PAYLOAD_POISON_ANSWER,
        'attempts': 21000,
        'force_defenses': {},
        'has_serve': False,
        'combos': [
            {'label': 'base (random ID only)', 'defenses': {}},
            {'label': '+ random source port', 'defenses': {'random_port': True}},
            {'label': '+ 0x20 case encoding', 'defenses': {'use_0x20': True}},
            {'label': '+ both', 'defenses': {'random_port': True, 'use_0x20': True}},
        ],
        'describe': 'Runs the ID-guess race with increasing defense entropy and reports '
                    'the modelled single-trial poison probability for each combination.',
    },
}

DEFAULT_DEFENSES = {
    'random_id': True,
    'random_port': False,
    'use_0x20': False,
    'bailiwick_check': True,
    'ttl_floor': 0,
}


def case_bits(name):
    """Number of case-variable characters; 0x20 adds 2**k to the guess space."""
    return sum(1 for ch in name if ch.isalpha())