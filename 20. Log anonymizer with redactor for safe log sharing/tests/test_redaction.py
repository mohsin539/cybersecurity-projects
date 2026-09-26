"""Tests for redaction strategies."""

from anonymizer.core.models import DataClassification, RedactionStrategy, SensitiveEntity
from anonymizer.redaction import RedactionContext, Redactor


def make_entity(
    value, start, end, strategy, entity_type="EMAIL", classification=DataClassification.MEDIUM
):
    return SensitiveEntity(
        entity_type=entity_type,
        value=value,
        start=start,
        end=end,
        classification=classification,
        strategy=strategy,
    )


def test_full_redact():
    red = Redactor()
    line = "user email a@b.co logged in"
    ent = make_entity("a@b.co", 11, 17, RedactionStrategy.FULL_REDACT)
    assert red.redact(line, [ent]) == "user email [REDACTED] logged in"


def test_partial_mask():
    red = Redactor(RedactionContext(keep_last_chars=4))
    line = "card 4539665131016828 ok"
    ent = make_entity(
        "4539665131016828", 5, 21, RedactionStrategy.PARTIAL_MASK, entity_type="CREDIT_CARD"
    )
    output = red.redact(line, [ent])
    assert output == "card ************6828 ok"
    assert "4539665131016828" not in output


def test_tokenize():
    red = Redactor(RedactionContext(token_salt="tenant-a"))
    line = "mail to a@b.co now"
    ent = make_entity("a@b.co", 8, 14, RedactionStrategy.TOKENIZE)
    output = red.redact(line, [ent])
    assert output.startswith("mail to TOK_")
    assert "a@b.co" not in output


def test_tokenize_deterministic_with_salt():
    ctx = RedactionContext(token_salt="s1")
    r1 = Redactor(ctx)
    r2 = Redactor(RedactionContext(token_salt="s1"))
    e1 = make_entity("user@x.io", 0, 10, RedactionStrategy.TOKENIZE)
    e2 = make_entity("user@x.io", 0, 10, RedactionStrategy.TOKENIZE)
    assert r1.redact("user@x.io xx", [e1]) == r2.redact("user@x.io xx", [e2])


def test_pseudonymize():
    red = Redactor(RedactionContext(token_salt="s"))
    line = "from 192.168.0.5 request"
    ent = make_entity(
        "192.168.0.5",
        5,
        16,
        RedactionStrategy.PSEUDONYMIZE,
        entity_type="IP_ADDRESS",
        classification=DataClassification.MEDIUM,
    )
    output = red.redact(line, [ent])
    assert output.startswith("from P-")
    assert "192.168.0.5" not in output


def test_generalize_numeric():
    red = Redactor(RedactionContext())
    ent = make_entity("95000", 0, 5, RedactionStrategy.GENERALIZE)
    # Bucketed range never exposes the exact boundary value
    assert red.redact("95000 salary", [ent]) == "90000-94999 salary"


def test_generalize_coordinates():
    red = Redactor(RedactionContext())
    ent = make_entity(
        "37.7749, -122.4194", 0, 19, RedactionStrategy.GENERALIZE, entity_type="COORDINATES"
    )
    output = red.redact("37.7749, -122.4194 loc", [ent])
    assert "37.7749" not in output
    assert "-" in output


def test_date_shift():
    red = Redactor(RedactionContext(date_shift_days=7))
    from anonymizer.core.models import SensitiveEntity

    ent = SensitiveEntity(
        entity_type="DATE_OF_BIRTH",
        value="1990-01-15",
        start=0,
        end=10,
        classification=DataClassification.MEDIUM,
        strategy=RedactionStrategy.DATE_SHIFT,
    )
    assert red.redact("1990-01-15 dob", [ent]) == "1990-01-22 dob"


def test_contextual():
    red = Redactor(RedactionContext())
    ent = make_entity("4567", 15, 19, RedactionStrategy.CONTEXTUAL)
    ent.context_key = "user_id"
    assert red.redact("GET /api/users/4567", [ent]) == "GET /api/users/user_id"


def test_multiple_entities_right_to_left():
    red = Redactor()
    line = "e a@b.co ssn 123-45-6789"
    ents = [
        make_entity("a@b.co", 2, 8, RedactionStrategy.TOKENIZE),
        make_entity(
            "123-45-6789",
            13,
            23,
            RedactionStrategy.FULL_REDACT,
            entity_type="SSN",
            classification=DataClassification.CRITICAL,
        ),
    ]
    out = red.redact(line, ents)
    assert out.startswith("e TOK_")
    assert "[REDACTED]" in out
    assert "a@b.co" not in out and "123-45-6789" not in out


def test_merge_overlapping_prefers_high_confidence():
    red = Redactor()
    line = "secret=abcdef123456"
    low = SensitiveEntity(
        "IP_ADDRESS",
        "abcdef123456",
        7,
        19,
        classification=DataClassification.MEDIUM,
        strategy=RedactionStrategy.FULL_REDACT,
        confidence=0.5,
    )
    high = SensitiveEntity(
        "PASSWORD_SUSPECT",
        "abcdef123456",
        7,
        19,
        classification=DataClassification.CRITICAL,
        strategy=RedactionStrategy.FULL_REDACT,
        confidence=0.99,
    )
    out = red.redact_many(line, [low, high])
    assert out == "secret=[REDACTED]"
