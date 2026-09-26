import re

from .packets import TYPE_A

LAB_PREFIX = '172.16.238.'

RESOLVER_IP = '172.16.238.20'
CLIENT_IP = '172.16.238.10'
ATTACKER_IP = '172.16.238.30'
ROOT_IP = '172.16.238.40'
TLD_IP = '172.16.238.50'
AUTH_IP = '172.16.238.60'
PORT = 53

SERVICE_IPS = [RESOLVER_IP, ATTACKER_IP, ROOT_IP, TLD_IP, AUTH_IP, CLIENT_IP]

LEGIT_LATENCY = 1

ALL_IPS = set(SERVICE_IPS)

TRUTH = {
    'www.lab.local.': (TYPE_A, ['172.16.238.62']),
    'demosrv.lab.local.': (TYPE_A, ['172.16.238.61']),
    'api.lab.local.': (TYPE_A, ['172.16.238.63']),
}

DEFAULT_TTL = 300
NEG_TTL = 30

EVIL_ZONE = 'lab.local.'
EVIL_NS = 'ns1.evil.lab.local.'
EVIL_GLUE_ADDR = ATTACKER_IP
EVIL_A = '203.0.113.66'
OTHER_ZONE_NAME = 'api.otherlab.local.'
EVIL_TTL = 60

NAME_RE = re.compile(r'^[a-zA-Z0-9_.-]{1,253}$')


def valid_name(name):
    return bool(name) and bool(NAME_RE.match(name))


def fqdn(name):
    if not name or name == '.':
        return '.'
    return name if name.endswith('.') else name + '.'


def zone_tables():
    soa = {
        '.': 'ns.local. hostmaster.local. 1 3600 600 86400 30',
        'local.': 'ns.lab.local. hostmaster.lab.local. 2 3600 7200 86400 30',
        'lab.local.': 'ns1.lab.local. hostmaster.lab.local. 3 3600 3600 604800 30',
    }
    root = {
        'zone': '.',
        'records': {},
        'delegations': {'local.': {'ns': ['ns.local.'], 'glue': {'ns.local.': [TLD_IP]}}},
        'soa': soa['.'],
    }
    tld = {
        'zone': 'local.',
        'records': {},
        'delegations': {'lab.local.': {'ns': ['ns1.lab.local.'], 'glue': {'ns1.lab.local.': [AUTH_IP]}}},
        'soa': soa['local.'],
    }
    auth = {
        'zone': 'lab.local.',
        'records': dict(TRUTH),
        'delegations': {},
        'soa': soa['lab.local.'],
    }
    return {ROOT_IP: root, TLD_IP: tld, AUTH_IP: auth}


def zone_of(ip):
    tables = zone_tables()
    return tables[ip]['zone']


def is_subdomain(name, zone):
    name = fqdn(name).lower()
    zone = fqdn(zone).lower()
    if zone == '.':
        return True
    if not name.endswith(zone):
        return False
    if len(name) == len(zone):
        return True
    return name[-len(zone) - 1] == '.'