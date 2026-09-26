
from app.engine.contexts import Context, CTX_INDEX, CONTEXT_SPECS
from app.engine.payloads import build_candidates


def _make(limits=(400, 0)):
    return build_candidates(
        context_kinds=[Context.HTML, Context.ATTR, Context.SCRIPT, Context.URL, Context.DOM],
        base_url="http://localhost:5001/html?name={q}",
        beacon_base="http://localhost:8000/api/collect/sc",
        max_payloads=limits[0],
    )


def test_generates_bounded_candidate_set():
    cands = _make()
    assert 0 < len(cands) <= 400


def test_candidates_are_unique():
    cands = _make()
    ids = [c.id for c in cands]
    assert len(set(ids)) == len(ids)


def test_every_candidate_has_token():
    for c in _make():
        if c.beacon:
            assert "xtok_" in c.payload or "xtok_" in (c.token or "")
        assert c.token
        assert c.context.name in CTX_INDEX


def test_beacon_vectors_get_unique_urls():
    cands = [c for c in _make() if c.beacon]
    assert cands
    urls = [c.payload for c in cands]
    # beacon urls embed per-candidate id
    assert any(f"/{c.id}" in p for c, p in zip(cands, urls))


def test_all_context_specs_resolvable():
    for kind, specs in CONTEXT_SPECS.items():
        assert specs
        for spec in specs:
            assert spec.name in CTX_INDEX
            assert CTX_INDEX[spec.name] is spec


def test_proof_url_appends_distinct_params():
    a = build_candidates([Context.HTML], "http://localhost:5001/html", max_payloads=5)
    assert a
    urls = [c.proof_url for c in a]
    assert len(set(urls)) == len(urls)