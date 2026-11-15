from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from typing import Any

import numpy as np
import pandas as pd

_ALLOWED_FUNCTIONS = {"abs", "min", "max", "round", "len", "int", "float", "bool"}


@dataclass
class RuleDefinition:
    rule_id: str
    name: str
    description: str
    enabled: bool
    condition: str
    threshold: float
    severity: str
    weight: float = 1.0


@dataclass
class RuleMatch:
    rule_id: str
    name: str
    severity: str
    weight: float
    matched: bool
    explanation: str


class RuleSyntaxError(ValueError):
    """Raised when a rule condition cannot be parsed safely."""


def _safe_arity(name: str, call: ast.Call) -> None:
    allowed_args: dict[str, tuple[int | None, int | None]] = {
        "abs": (1, 1),
        "len": (1, 1),
        "min": (1, None),
        "max": (1, None),
        "round": (1, 2),
        "int": (1, 2),
        "float": (1, 1),
        "bool": (1, 1),
    }
    minimum, maximum = allowed_args[name]
    if len(call.args) < minimum or (maximum is not None and len(call.args) > maximum):
        raise RuleSyntaxError(f"Function {name!r} called with an unsupported number of arguments.")
    if call.keywords:
        raise RuleSyntaxError(f"Keyword arguments are not allowed in rule conditions ({name}).")


class _Evaluator(ast.NodeVisitor):
    """Restricted AST evaluator. Never calls Python eval()."""

    def __init__(self, context: dict[str, Any]) -> None:
        self.context = context

    def visit_Expression(self, node: ast.Expression) -> Any:
        return self.visit(node.body)

    def visit_Constant(self, node: ast.Constant) -> Any:
        if isinstance(node.value, (int, float, bool, str)) or node.value is None:
            return node.value
        raise RuleSyntaxError("Unsupported constant type in rule condition.")

    def visit_Name(self, node: ast.Name) -> Any:
        if node.id not in self.context:
            raise KeyError(node.id)
        return self.context[node.id]

    def visit_UnaryOp(self, node: ast.UnaryOp) -> Any:
        value = self.visit(node.operand)
        if isinstance(node.op, ast.USub):
            return -value
        if isinstance(node.op, ast.UAdd):
            return +value
        if isinstance(node.op, ast.Not):
            return not value
        raise RuleSyntaxError("Unsupported unary operator.")

    def visit_BinOp(self, node: ast.BinOp) -> Any:
        left = self.visit(node.left)
        right = self.visit(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div):
            return left / right
        if isinstance(node.op, ast.FloorDiv):
            return left // right
        if isinstance(node.op, ast.Mod):
            return left % right
        if isinstance(node.op, ast.Pow):
            return left ** right
        raise RuleSyntaxError("Unsupported binary operator.")

    def visit_Compare(self, node: ast.Compare) -> Any:
        left: Any = self.visit(node.left)
        for operator, comparator in zip(node.ops, node.comparators):
            right: Any = self.visit(comparator)
            if not _compare(operator, left, right):
                return False
            left = right
        return True

    def visit_BoolOp(self, node: ast.BoolOp) -> Any:
        if isinstance(node.op, ast.And):
            result = True
            for value in node.values:
                result = self.visit(value)
                if not result:
                    return False
            return bool(result)
        result = False
        for value in node.values:
            result = self.visit(value)
            if result:
                return True
        return bool(result)

    def visit_Not(self, node: ast.Not) -> Any:
        return not self.visit(node.operand)

    def visit_Call(self, node: ast.Call) -> Any:
        if isinstance(node.func, ast.Name) and node.func.id in _ALLOWED_FUNCTIONS:
            _safe_arity(node.func.id, node)
            args = [self.visit(arg) for arg in node.args]
            return self._apply(node.func.id, args)
        raise RuleSyntaxError(f"Function calls are not allowed in rule conditions: {ast.dump(node.func)}")

    def _apply(self, name: str, args: list[Any]) -> Any:
        builtins_map: dict[str, Any] = {
            "abs": abs,
            "min": min,
            "max": max,
            "round": round,
            "len": len,
            "int": int,
            "float": float,
            "bool": bool,
        }
        return builtins_map[name](*args)

    def visit_List(self, node: ast.List) -> Any:
        return [self.visit(element) for element in node.elts]

    def visit_Tuple(self, node: ast.Tuple) -> Any:
        return tuple(self.visit(element) for element in node.elts)

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        raise RuleSyntaxError("Attribute access is not allowed in rule conditions.")

    def generic_visit(self, node: ast.AST) -> Any:
        raise RuleSyntaxError(f"Unsupported expression node: {type(node).__name__}")


class _VectorEvaluator(ast.NodeVisitor):
    """Vectorized sibling of ``_Evaluator`` operating on whole DataFrame columns.

    Supports the same grammar (comparisons, boolean logic, arithmetic and the
    allow-listed functions) and never calls Python eval(). Any construct it
    cannot vectorize raises ``RuleSyntaxError`` so the caller can fall back to
    the scalar evaluator.
    """

    def __init__(self, frame: pd.DataFrame, extra: dict[str, Any]) -> None:
        self.frame = frame
        self.extra = extra

    def visit_Expression(self, node: ast.Expression) -> Any:
        return self.visit(node.body)

    def visit_Constant(self, node: ast.Constant) -> Any:
        if isinstance(node.value, (int, float, bool, str)) or node.value is None:
            return node.value
        raise RuleSyntaxError("Unsupported constant type in rule condition.")

    def visit_Name(self, node: ast.Name) -> Any:
        if node.id in self.extra:
            return self.extra[node.id]
        if node.id not in self.frame.columns:
            raise KeyError(node.id)
        return self.frame[node.id].to_numpy()

    def visit_UnaryOp(self, node: ast.UnaryOp) -> Any:
        value = self.visit(node.operand)
        if isinstance(node.op, ast.USub):
            return -value
        if isinstance(node.op, ast.UAdd):
            return +value
        if isinstance(node.op, ast.Not):
            return np.logical_not(value)
        raise RuleSyntaxError("Unsupported unary operator.")

    def visit_BinOp(self, node: ast.BinOp) -> Any:
        left, right = self.visit(node.left), self.visit(node.right)
        ops = {ast.Add: np.add, ast.Sub: np.subtract, ast.Mult: np.multiply, ast.Div: np.true_divide,
               ast.FloorDiv: np.floor_divide, ast.Mod: np.mod, ast.Pow: np.power}
        func = ops.get(type(node.op))
        if func is None:
            raise RuleSyntaxError("Unsupported binary operator.")
        with np.errstate(all="ignore"):
            return func(left, right)

    def visit_Compare(self, node: ast.Compare) -> Any:
        left = self.visit(node.left)
        result: Any = True
        for operator, comparator in zip(node.ops, node.comparators):
            right = self.visit(comparator)
            table = {ast.Eq: np.equal, ast.NotEq: np.not_equal, ast.Lt: np.less, ast.LtE: np.less_equal,
                     ast.Gt: np.greater, ast.GtE: np.greater_equal}
            func = table.get(type(operator))
            if func is None:
                raise RuleSyntaxError("Comparison operator is not vectorizable.")
            result = np.logical_and(result, func(left, right))
            left = right
        return result

    def visit_BoolOp(self, node: ast.BoolOp) -> Any:
        values = [self.visit(value) for value in node.values]
        combine = np.logical_and if isinstance(node.op, ast.And) else np.logical_or
        result = values[0]
        for value in values[1:]:
            result = combine(result, value)
        return result

    def visit_Call(self, node: ast.Call) -> Any:
        if not (isinstance(node.func, ast.Name) and node.func.id in _ALLOWED_FUNCTIONS):
            raise RuleSyntaxError("Function call is not allowed in rule conditions.")
        _safe_arity(node.func.id, node)
        args = [self.visit(arg) for arg in node.args]
        name = node.func.id
        if name == "abs":
            return np.abs(args[0])
        if name == "min" and len(args) >= 2:
            return np.minimum.reduce(args)
        if name == "max" and len(args) >= 2:
            return np.maximum.reduce(args)
        if name == "round":
            return np.round(args[0], int(args[1]) if len(args) > 1 else 0)
        if name == "float":
            return np.asarray(args[0], dtype=float)
        if name == "bool":
            return np.asarray(args[0], dtype=bool)
        raise RuleSyntaxError(f"Function {name!r} is not vectorizable.")

    def generic_visit(self, node: ast.AST) -> Any:
        raise RuleSyntaxError(f"Expression node {type(node).__name__} is not vectorizable.")


def _compare(operator: ast.cmpop, left: Any, right: Any) -> bool:
    if isinstance(operator, ast.Eq):
        return left == right
    if isinstance(operator, ast.NotEq):
        return left != right
    if isinstance(operator, ast.Lt):
        return left < right
    if isinstance(operator, ast.LtE):
        return left <= right
    if isinstance(operator, ast.Gt):
        return left > right
    if isinstance(operator, ast.GtE):
        return left >= right
    if isinstance(operator, ast.In):
        return left in right
    if isinstance(operator, ast.NotIn):
        return left not in right
    raise RuleSyntaxError("Unsupported comparison operator.")


_FORBIDDEN_NODES = (ast.Attribute, ast.Subscript, ast.Lambda, ast.NamedExpr, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.Starred, ast.Await, ast.Slice)


def _validate_tree(tree: ast.Expression) -> None:
    """Reject constructs that are never allowed in rule expressions at compile
    time, so unsafe conditions fail fast during rule registration."""
    for node in ast.walk(tree):
        if isinstance(node, _FORBIDDEN_NODES):
            raise RuleSyntaxError(f"Expression construct {type(node).__name__} is not allowed in rule conditions.")
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in _ALLOWED_FUNCTIONS:
                raise RuleSyntaxError(
                    f"Function call {node.func.id if isinstance(node.func, ast.Name) else 'expression'} is not allowed in rule conditions."
                )
        if isinstance(node, ast.Name):
            if node.id.startswith("__"):
                raise RuleSyntaxError(f"Name {node.id!r} is not allowed in rule conditions.")


def _compile_condition(condition: str) -> ast.Expression:
    text = condition.strip()
    if not text:
        raise RuleSyntaxError("Rule condition cannot be empty.")
    try:
        tree = ast.parse(text, mode="eval")
    except SyntaxError as exc:
        raise RuleSyntaxError(f"Invalid rule condition {condition!r}: {exc}") from exc
    if not isinstance(tree, ast.Expression):
        raise RuleSyntaxError("A rule condition must be a single expression.")
    _validate_tree(tree)
    return tree


def _required_names(tree: ast.Expression) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id not in _ALLOWED_FUNCTIONS and isinstance(getattr(node, "ctx", None), ast.Load):
            names.add(node.id)
    return names


class RuleEngine:
    """Safe, declarative rule engine.

    Conditions are Python-comparison expressions evaluated with a restricted
    AST walker. Python eval() is never used.
    """

    def __init__(self) -> None:
        self._rules: list[RuleDefinition] = []
        self._compiled: dict[str, ast.Expression] = {}
        self._names: dict[str, set[str]] = {}

    def add_rule(self, rule: RuleDefinition) -> None:
        compiled = _compile_condition(rule.condition)
        self._rules.append(rule)
        self._compiled[rule.rule_id] = compiled
        self._names[rule.rule_id] = _required_names(compiled)

    def required_names(self, rule_id: str | None = None) -> set[str]:
        if rule_id is not None:
            return set(self._names.get(rule_id, set()))
        required: set[str] = set()
        for rule_names in self._names.values():
            required |= rule_names
        return required

    def evaluate_rule(self, rule: RuleDefinition, context: dict[str, Any]) -> bool:
        if not rule.enabled:
            return False
        compiled = self._compiled.get(rule.rule_id)
        if compiled is None:
            return False
        try:
            value = _Evaluator(context).visit(compiled.body)
        except (KeyError, TypeError, ZeroDivisionError, ValueError, RuleSyntaxError):
            return False
        return bool(value)

    def evaluate_frame(self, frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        """Evaluate every enabled rule over a whole frame.

        Returns ``(match_count, weight_sum)`` arrays aligned to ``frame``. A
        rule is skipped when the frame lacks a column it needs, mirroring the
        per-event behavior. Rules that cannot be vectorized fall back to the
        scalar evaluator for that rule only.
        """
        count = np.zeros(len(frame), dtype=int)
        weight = np.zeros(len(frame), dtype=float)
        columns = set(frame.columns)
        for rule in self._rules:
            if not rule.enabled:
                continue
            required = self._names.get(rule.rule_id, set())
            if not (required - {"threshold"}).issubset(columns):
                continue
            compiled = self._compiled.get(rule.rule_id)
            if compiled is None:
                continue
            try:
                mask = _VectorEvaluator(frame, {"threshold": rule.threshold}).visit(compiled.body)
                mask = np.broadcast_to(np.asarray(mask, dtype=bool), (len(frame),))
            except (KeyError, TypeError, ValueError, RuleSyntaxError):
                mask = np.zeros(len(frame), dtype=bool)
                names = sorted(required - {"threshold"})
                data = {name: frame[name].tolist() for name in names}
                for position in range(len(frame)):
                    context = {name: data[name][position] for name in names}
                    context.setdefault("threshold", rule.threshold)
                    mask[position] = self.evaluate_rule(rule, context)
            count += mask.astype(int)
            weight += mask * rule.weight
        return count, np.minimum(1.0, weight)

    def evaluate(self, context: dict[str, Any]) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        for rule in self._rules:
            if not rule.enabled:
                continue
            if self.evaluate_rule(rule, context):
                matches.append(
                    RuleMatch(
                        rule_id=rule.rule_id,
                        name=rule.name,
                        severity=rule.severity,
                        weight=rule.weight,
                        matched=True,
                        explanation=f"Rule '{rule.name}' matched: {rule.condition}",
                    )
                )
        return matches

    def to_dict(self) -> list[dict[str, Any]]:
        return [asdict(rule) for rule in self._rules]

    @property
    def rules(self) -> list[RuleDefinition]:
        return list(self._rules)