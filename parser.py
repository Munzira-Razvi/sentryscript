import os
from dataclasses import dataclass, field
from lark import Lark, Token, Transformer
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
    op: str          # "==", "!=", "in" or "not in"
    value: object    # text or a number, or a list for "in" / "not in"

@dataclass
class ListRef:
    name: str        # a reference to a list defined with "let"

@dataclass
class LetStmt:
    name: str
    values: list

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
    def start(self, items):
        lists, rules = {}, []
        for item in items:
            if isinstance(item, LetStmt):
                if item.name in lists:
                    raise ValueError(f"The list '{item.name}' is defined twice")
                lists[item.name] = item.values
            else:
                rules.append(item)
        # Replace list names inside filters with the lists themselves
        for rule in rules:
            for f in rule.filters:
                if isinstance(f.value, ListRef):
                    name = f.value.name
                    if name not in lists:
                        raise ValueError(
                            f"Rule '{rule.name}' uses the list '{name}', but it is "
                            f'not defined. Add a line like: let {name} = ["..."]')
                    f.value = lists[name]
        return rules

    def duration(self, items):
        n, unit = items
        return int(n) * {"s": 1, "m": 60, "h": 3600}[str(unit)]

    def severity(self, items):
        level = str(items[0]).lower()
        if level not in LEVELS:
            raise ValueError(f"Unknown severity '{level}'. Use one of: {', '.join(LEVELS)}")
        return Severity(level)

    def value(self, items):
        tok = items[0]
        return str(tok)[1:-1] if tok.type == "ESCAPED_STRING" else int(tok)

    def list_lit(self, items):
        return list(items)

    def let_stmt(self, items):
        name, values = items
        return LetStmt(str(name), values)

    def membership(self, items):
        m = items[0]
        return ListRef(str(m)) if isinstance(m, Token) else m

    def compare_filter(self, items):
        name, op, value = items
        return Filter(str(name), str(op), value)

    def in_filter(self, items):
        name, members = items
        return Filter(str(name), "in", members)

    def not_in_filter(self, items):
        name, members = items
        return Filter(str(name), "not in", members)

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
    with open(path, encoding="utf-8") as f:
        return parse_rules(f.read(), path)

if __name__ == "__main__":
    for r in load_rules("rules.sentry"):
        print(r)