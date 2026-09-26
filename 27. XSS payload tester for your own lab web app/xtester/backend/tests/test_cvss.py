from app.engine.cvss import Cvss


def test_baseline_reflected_xss_score():
    cvss = Cvss()
    score = cvss.base_score()
    # Reflected XSS with scope change is typically ~6.1
    assert 5.0 <= score <= 7.0
    assert score == 6.1 or abs(score - 6.1) < 0.1


def test_known_vector():
    known = Cvss(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert known.base_score() == 9.8
    assert known.severity() == "critical"


def test_scope_unchanged_lower():
    lower = Cvss(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N")
    assert lower.base_score() < Cvss().base_score()


def test_for_context_produces_valid_severity():
    for ctx in ("html", "attribute", "script", "url", "dom"):
        c = Cvss.for_context(ctx, True)
        assert c.severity() in ("info", "low", "medium", "high", "critical")
        assert c.vector.startswith("CVSS:3.1")


def test_zero_impact_scores_zero():
    n = Cvss(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:N")
    assert n.base_score() == 0.0
    assert n.severity() == "info"