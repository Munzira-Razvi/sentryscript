import os
from dataclasses import dataclass, field
from lark import Lark, Transformer
from lark.exceptions import UnexpectedInput, VisitError

LEVELS = ("low", "medium", "high", "critical")

@dataclass
class Alert:
    message: str

@dataclass
class Block:
    field: str
    seconds: int

@dataclass
class Severity:
    level: str

@dataclass
class Rule:
    name: str
    severity: str
    event: str
    actions: list
    kind: str = "count"       # "count" or "time"
    group_by: str = None
    threshold: int = 0
    window: int = 0           # seconds
    start: int = 0            # minutes since midnight
    end: int = 0
    negate: bool = False

class ToAST(Transformer):
    def start(self, rules):
        return list(rules)

    def duration(self, items):
        n, unit = items
        return int(n) * {"s": 1, "m": 60, "h": 3600}[str(unit)]

    def severity(self, items):
        level = str(items[0]).lower()
        if level not in LEVELS:
            raise ValueError(f"Unknown severity '{level}'. Use one of: {', '.join(LEVELS)}")
        return Severity(level)

    def count_when(self, items):
        event, group, n, window = items
        return dict(kind="count", event=str(event), group_by=str(group),
                    threshold=int(n), window=window)

    def negate(self, items):
        return True

    def time_when(self, items):
        event = str(items[0])
        negate = any(isinstance(i, bool) for i in items[1:])
        times = [i for i in items[1:] if not isinstance(i, bool)]

        def minutes(t):
            h, m = str(t).split(":")
            return int(h) * 60 + int(m)

        return dict(kind="time", event=event, negate=negate,
                    start=minutes(times[0]), end=minutes(times[1]))

    def alert_action(self, items):
        return Alert(str(items[0])[1:-1])     # remove the quotes

    def block_action(self, items):
        return Block(str(items[0]), items[1])

    def then_clause(self, items):
        return list(items)

    def rule(self, items):
        name = str(items[0])
        severity, when, actions = "medium", None, []
        for it in items[1:]:
            if isinstance(it, Severity):
                severity = it.level
            elif isinstance(it, dict):
                when = it
            else:
                actions = it
        return Rule(name=name, severity=severity, actions=actions, **when)

class SentryError(Exception):
    """A problem in a rule file, with a message safe to show to users."""

GRAMMAR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "grammar.lark")

def load_rules(path):
    with open(GRAMMAR) as f:
        parser = Lark(f.read(), parser="lalr")
    with open(path) as f:
        text = f.read()
    try:
        tree = parser.parse(text)
        return ToAST().transform(tree)
    except UnexpectedInput as e:
        expected = getattr(e, "expected", None) or getattr(e, "allowed", None)
        hint = f"\nExpected one of: {', '.join(sorted(expected))}" if expected else ""
        raise SentryError(
            f"Syntax error in {path}, line {e.line}, column {e.column}:\n"
            f"{e.get_context(text)}{hint}"
        )
    except VisitError as e:
        raise SentryError(f"Problem in {path}: {e.orig_exc}")

if __name__ == "__main__":
    for r in load_rules("rules.sentry"):
        print(r)