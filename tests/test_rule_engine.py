from __future__ import annotations

import pytest

from backend.rules import RuleDefinition, RuleEngine, RuleSyntaxError


def _engine(condition: str, threshold: float = 3, weight: float = 1.0) -> RuleEngine:
    engine = RuleEngine()
    engine.add_rule(
        RuleDefinition(
            rule_id="test_rule",
            name="Repeated failures",
            description="Detect repeated authentication failures",
            enabled=True,
            condition=condition,
            threshold=threshold,
            severity="High",
            weight=weight,
        )
    )
    return engine


def test_rule_engine_matches_and_scores() -> None:
    engine = _engine("failed_login_count >= 3")
    context = {
        "failed_login_count": 4,
        "source_file": "auth.log",
        "message": "multiple failed login attempts",
    }
    matches = engine.evaluate(context)
    assert len(matches) == 1
    assert matches[0].rule_id == "test_rule"
    assert matches[0].matched is True
    assert matches[0].severity == "High"


@pytest.mark.parametrize(
    "condition,context,expected",
    [
        ("failed_login_count >= 3", {"failed_login_count": 3}, True),
        ("failed_login_count >= 3", {"failed_login_count": 2}, False),
        ("failed_login_count <= 3", {"failed_login_count": 3}, True),
        ("failed_login_count != 3", {"failed_login_count": 4}, True),
        ("failed_login_count == 4", {"failed_login_count": 4}, True),
        ("request_rate > threshold", {"request_rate": 120.0, "threshold": 100.0}, True),
        ("request_rate > threshold", {"request_rate": 50.0, "threshold": 100.0}, False),
        ("error_rate > threshold", {"error_rate": 0.6, "threshold": 0.5}, True),
        ("failed_login_count >= 3 and request_rate > threshold", {"failed_login_count": 4, "request_rate": 1000.0, "threshold": 100.0}, True),
        ("failed_login_count >= 3 and request_rate > threshold", {"failed_login_count": 4, "request_rate": 50.0, "threshold": 100.0}, False),
        ("not (failed_login_count >= 3)", {"failed_login_count": 2}, True),
        ("abs(request_rate) > threshold", {"request_rate": -200.0, "threshold": 100.0}, True),
        ("message in ['auth fail', 'denied'] or failed_login_count >= 3", {"message": "denied", "failed_login_count": 1}, True),
        ("min(failed_login_count, message_word_count) >= 3", {"failed_login_count": 5, "message_word_count": 2}, False),
    ],
)
def test_rule_operators(condition: str, context: dict, expected: bool) -> None:
    engine = _engine(condition, threshold=context.get("threshold", 100))
    matches = engine.evaluate(context)
    assert [match.matched for match in matches] == ([True] if expected else [])


def test_rule_no_match_below_threshold() -> None:
    engine = _engine("failed_login_count >= 3")
    assert engine.evaluate({"failed_login_count": 2, "source_file": "auth.log", "message": "x"}) == []


def test_disabled_rule_is_skipped() -> None:
    engine = RuleEngine()
    engine.add_rule(
        RuleDefinition(
            rule_id="off",
            name="Disabled",
            description="Should never fire",
            enabled=False,
            condition="failed_login_count >= 3",
            threshold=3,
            severity="High",
            weight=1.0,
        )
    )
    assert engine.evaluate({"failed_login_count": 10}) == []


@pytest.mark.parametrize(
    "condition",
    [
        "failed_login_count >= 3; delete from alerts",
        "__import__('os').system('id')",
        "failed_login_count = 3",  # single '=' must be rejected as syntax, not coerced
        "globals()",
        "getattr(failed_login_count, '__class__')",
        "",
    ],
)
def test_unsafe_or_invalid_conditions_rejected(condition: str) -> None:
    engine = RuleEngine()
    with pytest.raises(RuleSyntaxError):
        engine.add_rule(
            RuleDefinition(
                rule_id="bad",
                name="Bad",
                description="",
                enabled=True,
                condition=condition,
                threshold=3,
                severity="High",
                weight=1.0,
            )
        )


def test_single_equals_never_mangles_comparators() -> None:
    engine = _engine("failed_login_count >= 3")
    context = {"failed_login_count": 4, "threshold": 3}
    assert len(engine.evaluate(context)) == 1