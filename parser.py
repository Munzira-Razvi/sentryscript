from dataclasses import dataclass, field
from lark import Lark, Transformer

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
    group_by: str
    threshold: int
    window: int          # seconds
    actions: list = field(default_factory=list)

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

    def when_clause(self, items):
        event, group, n, window = items
        return dict(event=str(event), group_by=str(group),
                    threshold=int(n), window=window)

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

def load_rules(path):
    with open("grammar.lark") as f:
        parser = Lark(f.read(), parser="lalr")
    with open(path) as f:
        tree = parser.parse(f.read())
    return ToAST().transform(tree)

if __name__ == "__main__":
    for r in load_rules("rules.sentry"):
        print(r)