import itertools
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import hashes

_OFFLINE_ALGOS = ("MD5", "NTLM", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512")
_SUPPORTED = set(_OFFLINE_ALGOS)

MAX_MASK_GUARD = 1_000_000_000_000
_CHUNK = 512


def _leet(w):
    table = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"})
    return w.translate(table)


def rule_variants(word):
    seen = {word}
    out = [word]
    lower = word.lower()
    for v in (lower, word.upper(), word.capitalize(), word.title()):
        if v not in seen:
            seen.add(v)
            out.append(v)
    leet = _leet(word)
    for v in (leet, leet.capitalize()):
        if v not in seen:
            seen.add(v)
            out.append(v)
    for n in range(10):
        for v in ("{}{}".format(word, n), "{}{}".format(lower, n), "{}{}".format(word.capitalize(), n)):
            if v not in seen:
                seen.add(v)
                out.append(v)
    for year in range(2000, 2027):
        for v in ("{}{}".format(word, year), "{}{}".format(word.capitalize(), year)):
            if v not in seen:
                seen.add(v)
                out.append(v)
    return out


def mask_scan(charset, min_len, max_len):
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


def mask_keyspace(charset, min_len, max_len):
    return sum(len(charset) ** n for n in range(min_len, max_len + 1))


class Cracker:
    def __init__(self, targets, workers=4):
        self.workers = max(1, min(workers, 16))
        self.targets = [t for t in targets if t]
        self.unsalted = {}
        self.salted = []
        self.token_map = {}
        for t in self.targets:
            token = t["token"].strip().lower()
            self.token_map[token] = t
            if t.get("salt"):
                self.salted.append(t)
                continue
            for algo in t.get("algos") or []:
                if algo in _SUPPORTED:
                    self.unsalted.setdefault(algo, set()).add(token)
        self.remaining = set(self.token_map)
        self.found = {}
        self.tried = 0
        self._stop = threading.Event()
        self.started_at = time.time()

    def stop(self):
        self._stop.set()

    @property
    def running(self):
        return not self._stop.is_set()

    def candidates(self, mode, words=None, charset=None, min_len=4, max_len=4):
        if mode == "wordlist":
            for w in words or []:
                yield w
        elif mode == "rules":
            for w in words or []:
                for v in rule_variants(w):
                    yield v
        elif mode == "mask":
            for c in mask_scan(charset, min_len, max_len):
                yield c
        else:
            raise ValueError("unknown mode: {}".format(mode))

    def _try_batch(self, batch):
        hits = []
        for cand in batch:
            if self._stop.is_set():
                break
            for t in self.salted:
                token = t["token"]
                if token in self.remaining:
                    for algo in t.get("algos") or []:
                        if algo in _SUPPORTED:
                            if hashes.compute(algo, cand, salt=t["salt"]) == token:
                                hits.append((token, cand, algo))
                                break
            for algo, hset in self.unsalted.items():
                h = hashes.compute(algo, cand)
                if h in hset and h in self.remaining:
                    hits.append((h, cand, algo))
        return hits

    def run(self, mode, words=None, charset="abcdefghijklmnopqrstuvwxyz0123456789",
            min_len=4, max_len=4, progress=None, audit=None):
        try:
            if mode == "mask":
                keyspace = mask_keyspace(charset, min_len, max_len)
                if keyspace > MAX_MASK_GUARD:
                    return {
                        "error": "mask keyspace {:,} exceeds safety guard {:,}".format(
                            keyspace, MAX_MASK_GUARD
                        )
                    }
            gen = self.candidates(mode, words=words, charset=charset, min_len=min_len, max_len=max_len)
        except ValueError as exc:
            return {"error": str(exc)}
        self.started_at = time.time()
        stats = self._run_chunked(gen, progress)
        stats.update(
            {
                "mode": mode,
                "workers": self.workers,
                "params": {
                    "wordlist_words": len(words) if words is not None else 0,
                    "charset": charset,
                    "min_len": min_len,
                    "max_len": max_len,
                },
            }
        )
        return stats

    def _run_chunked(self, gen, progress):
        last_tick = time.time()
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            for batch in _batch_iter(gen, _CHUNK):
                if self._stop.is_set():
                    break
                results = pool.map(self._try_batch, _batch_iter(batch, max(1, self.workers * 4)))
                for hits in results:
                    for token, cand, algo in hits:
                        self.found[token] = {"candidate": cand, "algo": algo}
                        self.remaining.discard(token)
                self.tried += len(batch)
                now = time.time()
                if now - last_tick >= 0.25 or not self.remaining:
                    self._emit(progress)
                    last_tick = now
                if not self.remaining:
                    break
        self._emit(progress)
        elapsed = time.time() - self.started_at
        rate = self.tried / elapsed if elapsed > 0 else 0.0
        return {
            "attempted": self.tried,
            "found": len(self.found),
            "remaining": len(self.remaining),
            "total": len(self.targets),
            "elapsed_s": elapsed,
            "rate": rate,
            "found_map": dict(self.found),
        }

    def _emit(self, progress):
        if not progress:
            return
        elapsed = time.time() - self.started_at
        rate = self.tried / elapsed if elapsed > 0 else 0.0
        progress(
            {
                "tried": self.tried,
                "rate": rate,
                "found": len(self.found),
                "remaining": len(self.remaining),
                "total": len(self.targets),
                "elapsed_s": elapsed,
                "found_map": dict(self.found),
            }
        )


def _batch_iter(iterable, size):
    batch = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch