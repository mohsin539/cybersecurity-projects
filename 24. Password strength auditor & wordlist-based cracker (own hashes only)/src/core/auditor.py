import math
import re

GUESS_RATES = {
    "NTLM": 1_000_000_000,
    "MD5": 1_000_000_000,
    "SHA1": 700_000_000,
    "SHA224": 500_000_000,
    "SHA256": 500_000_000,
    "SHA384": 300_000_000,
    "SHA512": 300_000_000,
    "bcrypt": 200,
    "argon2": 50,
}

_LOWER = set("abcdefghijklmnopqrstuvwxyz")
_UPPER = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_DIGIT = set("0123456789")
_SYMBOL = set("!@#$%^&*()_+-=[]{};:,.<>/?~`")

_SEQUENCE_FRAGS = (
    "abc", "bcd", "cde", "def", "efg", "fgh", "ghi", "hij", "ijk", "jkl",
    "klm", "lmn", "mno", "nop", "opq", "pqr", "qrs", "rst", "stu", "tuv",
    "uvw", "vwx", "wxy", "xyz",
    "qwe", "wer", "ert", "rty", "tyu", "yui", "uio", "iop",
    "asd", "sdf", "dfg", "fgh", "ghj", "hjk", "jkl",
    "zxc", "xcv", "cvb", "vbn", "bnm",
    "012", "123", "234", "345", "456", "567", "678", "789", "890",
)

_REPEAT4 = re.compile(r"(.)\1{3,}")


def pool_size(pw):
    size = 0
    chars = set(pw)
    if chars & _LOWER:
        size += 26
    if chars & _UPPER:
        size += 26
    if chars & _DIGIT:
        size += 10
    if chars & _SYMBOL:
        size += 33
    if any(ord(c) > 127 for c in pw):
        size += 50
    return max(size, 1)


def char_classes(pw):
    count = 0
    chars = set(pw)
    for group in (_LOWER, _UPPER, _DIGIT, _SYMBOL):
        if chars & group:
            count += 1
    if any(ord(c) > 127 for c in pw):
        count += 1
    return count


def penalty_bits(pw):
    low = pw.lower()
    p = 0
    for frag in _SEQUENCE_FRAGS:
        if frag in low:
            p += 3
    runs = _REPEAT4.findall(low)
    p += 4 * len(runs)
    if len(pw) >= 4 and low == low[::-1]:
        p += 4
    return p


def estimate_bits(pw):
    raw = len(pw) * math.log2(pool_size(pw))
    return max(0.0, raw - penalty_bits(pw))


def strength_label(bits, blocked=False):
    if blocked:
        return "Blocklisted (weak)"
    if bits < 28:
        return "Very weak"
    if bits < 36:
        return "Weak"
    if bits < 60:
        return "Fair"
    if bits < 80:
        return "Strong"
    return "Very strong"


def score_of(bits, blocked=False):
    if blocked:
        return 5
    if bits < 28:
        return 10
    if bits < 36:
        return 30
    if bits < 60:
        return 60
    if bits < 80:
        return 80
    return 95


def crack_time_seconds(bits, algo="MD5", rates=None):
    rates = rates or GUESS_RATES
    rate = rates.get(algo, rates.get("MD5", 1e9))
    return (2 ** bits) / rate


def format_duration(seconds):
    if seconds is None:
        return "unknown"
    if seconds < 0.001:
        return "instant (<1 ms)"
    if seconds < 1:
        return "{:.1f} ms".format(seconds * 1000)
    units = (
        (1, "s"),
        (60, "min"),
        (3600, "h"),
        (86400, "d"),
        (31557600, "y"),
    )
    value = seconds
    label = "s"
    for unit, name in units:
        if seconds < unit:
            break
        value = seconds / unit
        label = name
    if value >= 1000:
        return "{:,}".format(int(value)) + " " + label
    return "{:.1f} {}".format(value, label)


def nist_checks(pw, blocklist=None):
    low = pw.lower()
    blocked = bool(blocklist) and low in blocklist
    checks = []
    checks.append(("Length >= 8 (NIST SP 800-63B minimum)", len(pw) >= 8))
    checks.append(("Length >= 15 (recommended for strong passphrases)", len(pw) >= 15))
    checks.append(("Not a known/breach-listed common password", not blocked))
    checks.append(("Uses 3+ character classes", char_classes(pw) >= 3))
    checks.append(("No repeated character runs (4+)", not _REPEAT4.search(low)))
    checks.append(
        ("No obvious sequence/keyboard pattern", not any(f in low for f in _SEQUENCE_FRAGS))
    )
    return checks


def analyze(password, blocklist=None, algo="MD5", rates=None):
    blocked = bool(blocklist) and password.lower() in blocklist
    bits = estimate_bits(password)
    score = score_of(bits, blocked=blocked)
    label = strength_label(bits, blocked=blocked)
    checks = nist_checks(password, blocklist=blocklist)
    estimates = {}
    for name in ("MD5", "NTLM", "SHA1", "SHA256", "SHA512", "bcrypt", "argon2"):
        estimates[name] = format_duration(crack_time_seconds(bits, name, rates=rates))
    return {
        "password": password,
        "length": len(password),
        "classes": char_classes(password),
        "raw_bits": round(len(password) * math.log2(pool_size(password)), 1),
        "penalty": penalty_bits(password),
        "bits": round(bits, 1),
        "score": score,
        "label": label,
        "blocked": blocked,
        "checks": checks,
        "passes": sum(1 for _, ok in checks if ok),
        "total_checks": len(checks),
        "estimates": estimates,
    }