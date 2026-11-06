from dataclasses import dataclass
from lark import Lark, Transformer

@dataclass
class Rule:
    name: str
    event: str
    group_by: str
    threshold: int
    window: int      # seconds
    message: str

class ToAST(Transformer):
    def start(self, rules):
        return list(rules)

    def duration(self, items):
        n, unit = items
        return int(n) * {"s": 1, "m": 60, "h": 3600}[str(unit)]

    def when_clause(self, items):
        event, group, n, window = items
        return dict(event=str(event), group_by=str(group),
                    threshold=int(n), window=window)

    def then_clause(self, items):
        return str(items[0])[1:-1]   # remove the quotes

    def rule(self, items):
        name, when, message = items
        return Rule(name=str(name), message=message, **when)

def load_rules(path):
    with open("grammar.lark") as f:
        parser = Lark(f.read(), parser="lalr")
    with open(path) as f:
        tree = parser.parse(f.read())
    return ToAST().transform(tree)

if __name__ == "__main__":
    for r in load_rules("rules.sentry"):
        print(r)