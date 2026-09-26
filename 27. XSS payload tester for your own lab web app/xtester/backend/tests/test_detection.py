from app.engine.detection import BeaconRegistry, ProbeResult, classify


def _probe(beacon=False, dialogs=None, dom=False, errors=None):
    return ProbeResult(
        candidate_id="c1",
        beacon_hit=beacon,
        dialogs=dialogs or [],
        dom_contains_token=dom,
        errors=errors or [],
        status_code=200,
    )


def test_beacon_registry_roundtrip():
    reg = BeaconRegistry()
    reg.record("s1", "c1")
    assert reg.pop_hit("s1", "c1") is True
    assert reg.pop_hit("s1", "c1") is False


def test_beacon_hit_is_executed():
    p = _probe(beacon=True)
    assert classify(p) == "EXECUTED"
    assert p.confidence >= 0.9


def test_dialog_with_sentinel_is_executed():
    p = _probe(dialogs=["xtok_deadbeef"], dom=True)
    assert classify(p) == "EXECUTED"


def test_dom_token_and_error_is_likely():
    p = _probe(dom=True, errors=["ReferenceError: xtok_deadbeef is not defined"])
    assert classify(p) == "LIKELY"
    assert 0.6 <= p.confidence < 0.9


def test_rendered_but_no_signal_is_suspicious():
    p = _probe(dom=True)
    assert classify(p) == "SUSPICIOUS"


def test_nothing_is_clean():
    p = _probe()
    assert classify(p) == "CLEAN"
    assert p.confidence == 0.0


def test_http_500_lowers_confidence():
    p = _probe(dom=True)
    p.status_code = 500
    classify(p, min_confidence=0.6)
    assert p.verdict in ("SUSPICIOUS", "CLEAN")