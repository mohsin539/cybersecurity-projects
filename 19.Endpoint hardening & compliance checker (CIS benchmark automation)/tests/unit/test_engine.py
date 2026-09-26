"""Unit tests: evaluator, scoring, parsers, catalog integrity."""

from __future__ import annotations

import pytest

from cisguard.domain.catalog import CONTROLS, CONTROLS_BY_ID, CATEGORIES
from cisguard.domain.evaluator import evaluate
from cisguard.domain.models import Category, Control, Evidence, Severity, Status
from cisguard.domain.scoring import weighted_score
from cisguard.infrastructure.parsers import parse


# -- Catalog integrity ------------------------------------------------------------

def test_catalog_ids_unique_and_sorted():
    ids = [c.control_id for c in CONTROLS]
    assert len(ids) == len(set(ids))
    assert ids == sorted(ids, key=lambda x: [int(p) for p in x.split(".")])


def test_catalog_categories_valid_and_complete_spec():
    for c in CONTROLS:
        assert c.category in CATEGORIES
        assert c.audit_type in {"registry", "service", "command", "auditpol", "defender"}
        assert c.rationale and c.recommendation and c.title
        if c.audit_type == "registry":
            assert c.audit_spec["hive"] in {"HKLM", "HKCU"}
            assert c.audit_spec["missing"] in {"pass", "fail", "na"}


# -- Evaluator ---------------------------------------------------------------------

def _ctrl(op_expected, audit_type="registry"):
    return Control("t.0.1", "test control", Category.REGISTRY, 1, Severity.MEDIUM,
                   "r", "rec", audit_type, {"expect": op_expected})


def test_evaluator_gte_pass_fail():
    ev = Evidence("src", "24")
    assert evaluate(_ctrl(["gte", 24]), ev, "gte", 24).status == Status.PASS
    assert evaluate(_ctrl(["gte", 25]), Evidence("src", "12"), "gte", 25).status == Status.FAIL


def test_evaluator_lte_and_eq():
    assert evaluate(_ctrl(["lte", 5]), Evidence("s", "5"), "lte", 5).status == Status.PASS
    assert evaluate(_ctrl(["eq", 1]), Evidence("s", "1"), "eq", 1).status == Status.PASS
    assert evaluate(_ctrl(["eq", 0]), Evidence("s", 1), "eq", 0).status == Status.FAIL


def test_evaluator_in_not_in():
    assert evaluate(_ctrl(["in", ["Stopped", "NotFound"]]), Evidence("s", "Stopped"),
                    "in", ["Stopped", "NotFound"]).status == Status.PASS
    assert evaluate(_ctrl(["not_in", ["Disabled"]]), Evidence("s", "Running"),
                    "not_in", ["Disabled"]).status == Status.PASS
    assert evaluate(_ctrl(["not_in", ["Disabled"]]), Evidence("s", "Disabled"),
                    "not_in", ["Disabled"]).status == Status.FAIL


def test_evaluator_type_mismatch_is_not_crash():
    res = evaluate(_ctrl(["gte", 10]), Evidence("s", "not-a-number"), "gte", 10)
    assert res.status == Status.FAIL  # unparseable => fail, not exception


# -- Scoring -------------------------------------------------------------------------

def _res(cid, status):
    from cisguard.domain.models import Evidence, Result

    return Result(cid, status, "o", "e", Evidence("s", "o"))


def _ctrls():
    return {
        "a": Control("a", "A", Category.REGISTRY, 1, Severity.CRITICAL, "r", "c", "registry", {}),
        "b": Control("b", "B", Category.REGISTRY, 1, Severity.LOW, "r", "c", "registry", {}),
    }


def test_score_full_pass():
    assert weighted_score([_res("a", Status.PASS), _res("b", Status.PASS)], _ctrls()) == 100.0


def test_score_critical_fail_dominates():
    # critical (10) fails, low (1) passes -> 1/11 = 9.1
    assert weighted_score([_res("a", Status.FAIL), _res("b", Status.PASS)], _ctrls()) == 9.1


def test_score_errors_excluded_from_denominator():
    assert weighted_score([_res("a", Status.ERROR), _res("b", Status.PASS)], _ctrls()) == 100.0


# -- Parsers ---------------------------------------------------------------------------

NET_ACCOUNTS = """User accounts for \\\\TEST-HOST

-----------------------------------------------------------------------
Password history length:              24
Maximum password age (days):          42
Minimum password length:              14
Lockout threshold:                    5
Lockout duration (minutes):           30
Lockout observation window (minutes): 30
Store passwords using reversible encryption: No
Password complexity requirements:     Yes
The command completed successfully."""


def test_parser_net_accounts_fields():
    assert parse("password_hist_len", NET_ACCOUNTS) == "24"
    assert parse("min_pass_len", NET_ACCOUNTS) == "14"
    assert parse("max_pass_age", NET_ACCOUNTS) == "42"
    assert parse("lockout_threshold", NET_ACCOUNTS) == "5"
    assert parse("lockout_reset", NET_ACCOUNTS) == "30"
    assert parse("complexity", NET_ACCOUNTS) == "Yes"
    assert parse("reversible", NET_ACCOUNTS) == "No"


def test_parser_missing_field_returns_sentinel():
    assert parse("min_pass_len", "garbage") == "(not found)"
