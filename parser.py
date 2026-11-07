import os
from dataclasses import dataclass, field
from lark import Lark, Transformer
from lark.exceptions import UnexpectedInput, VisitError

LEVELS = ("low", "medium", "high", "critical")

class SentryError(Exception):
    """A problem in a rule file, with a message safe to show to users."""

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
class Filter:
    field: str
    op: str          # "==" or "!="
    value: object

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
    filters: list = field(default_factory=list)

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

    def filter(self, items):
        name, op, val = items
        value = str(val)[1:-1] if val.type == "ESCAPED_STRING" else int(val)
        return Filter(str(name), str(op), value)

    def filters(self, items):
        return list(items)

    def count_when(self, items):
        event, group, n, window, filters = items
        return dict(kind="count", event=str(event), group_by=str(group),
                    threshold=int(n), window=window, filters=filters)

    def negate(self, items):
        return True

    def time_when(self, items):
        event = str(items[0])
        filters = items[-1]
        middle = items[1:-1]
        negate = any(isinstance(i, bool) for i in middle)
        times = [i for i in middle if not isinstance(i, bool)]

        def minutes(t):
            h, m = str(t).split(":")
            return int(h) * 60 + int(m)

        return dict(kind="time", event=event, negate=negate,
                    start=minutes(times[0]), end=minutes(times[1]),
                    filters=filters)

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

GRAMMAR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "grammar.lark")

def parse_rules(text, name="rules"):
    with open(GRAMMAR) as f:
        parser = Lark(f.read(), parser="lalr")
    try:
        tree = parser.parse(text)
        return ToAST().transform(tree)
    except UnexpectedInput as e:
        expected = getattr(e, "expected", None) or getattr(e, "allowed", None)
        hint = f"\nExpected one of: {', '.join(sorted(expected))}" if expected else ""
        raise SentryError(
            f"Syntax error in {name}, line {e.line}, column {e.column}:\n"
            f"{e.get_context(text)}{hint}"
        )
    except VisitError as e:
        raise SentryError(f"Problem in {name}: {e.orig_exc}")

def load_rules(path):
    with open(path) as f:
        return parse_rules(f.read(), path)

if __name__ == "__main__":
    for r in load_rules("rules.sentry"):
        print(r)