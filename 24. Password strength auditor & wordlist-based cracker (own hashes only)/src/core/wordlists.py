import hashlib
import os

_BUILTIN_COMMON = (
    "123456 123456789 qwerty password 12345 qwerty123 1q2w3e 12345678 111111 "
    "1234567890 123123 abc123 1234567 password1 1234 qwertyuiop iloveyou "
    "000000 123654 dwang88 master letmein monkey dragon football letmein1 "
    "admin login princess welcome solo abcdef shadow sunshine 654321 password! "
    "trustno1 superman michael batman charlie ashley mustang qazwsx ranger "
    "killer hannah summer samantha harley 1q2w3e4r computer 121212 money "
    "asdfghjkl asdfgh 888888 3rjs1la7qe woaini 147852369 zhang198822 8625957890 "
    "abc123456 00000000 1q2w3e1231q3w3e iloveyou! baidu uiop saodou qq163.com "
    "qq123456 3463273122 1234qwer freedom highschool taylor password123 "
    "9999998888 775852159 dododog56 azsxdcfv111 wow classic pikachu cowboy "
    "ggbond kiss1234 qqmv6wq2 wow10 12190709 super123987 jordan23 nigger "
    "mynoob shadow1 asdf123 oosoon sparky krasotka welcome1 philip q1w2e3r4t5y6"
)
_BLOCKLIST = frozenset(_BUILTIN_COMMON.split())


def _valid_line(raw):
    return "\x00" not in raw and len(raw) <= 1024


def load_wordlist(path, max_bytes=25 * 1024 * 1024, max_lines=2_000_000):
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    size = os.path.getsize(path)
    if size > max_bytes:
        raise ValueError(
            "wordlist exceeds {} MB (possible zip-bomb / DoS); use a smaller list".format(
                max_bytes // (1024 * 1024)
            )
        )
    seen = set()
    words = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if len(words) >= max_lines:
                break
            word = line.rstrip("\r\n")
            if not word or not _valid_line(word):
                continue
            if word in seen:
                continue
            seen.add(word)
            words.append(word)
    return words


def fingerprint(path=None, words=None):
    if path:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    digest = hashlib.sha256()
    for w in words or []:
        digest.update(w.encode("utf-8"))
    return digest.hexdigest()


def common_blocklist():
    return set(_BLOCKLIST)