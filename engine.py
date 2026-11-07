import json
from collections import defaultdict, deque
from datetime import datetime
from parser import load_rules, Alert, Block, SentryError

COLORS = {"low": "\033[36m", "medium": "\033[33m",
          "high": "\033[31m", "critical": "\033[1;41m"}
RESET = "\033[0m"

def fmt_duration(seconds):
    for unit, size in (("h", 3600), ("m", 60)):
        if seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"

def parse_events(text):
    events = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
            e["_ts"] = datetime.fromisoformat(e["time"]).timestamp()
        except (ValueError, KeyError, TypeError) as err:
            raise SentryError(f"Bad event on line {n} of the log: {err}")
        events.append(e)
    events.sort(key=lambda e: e["_ts"])
    return events

def load_events(path):
    with open(path) as f:
        return parse_events(f.read())

def make_results(rule, event):
    results = []
    for action in rule.actions:
        if isinstance(action, Alert):
            results.append(("alert", action.message.format_map(event)))
        elif isinstance(action, Block):
            target = event.get(action.field)
            results.append(("block", f"{target} for "
                            f"{fmt_duration(action.seconds)} (simulated)"))
    return results

def in_range(minute, start, end):
    if start <= end:
        return start <= minute <= end
    return minute >= start or minute <= end    # range crosses midnight

def passes(rule, event):
    for f in rule.filters:
        actual = event.get(f.field)
        if f.op == "==" and actual != f.value:
            return False
        if f.op == "!=" and actual == f.value:
            return False
    return True

def run(rules, events):
    alerts = []
    windows = {r.name: defaultdict(deque) for r in rules}

    for event in events:
        for rule in rules:
            if event["type"] != rule.event:
                continue
            if not passes(rule, event):
                continue

            if rule.kind == "count":
                key = event.get(rule.group_by)
                if key is None:
                    continue
                window = windows[rule.name][key]
                window.append(event)
                while window and event["_ts"] - window[0]["_ts"] > rule.window:
                    window.popleft()
                if len(window) >= rule.threshold:
                    alerts.append({
                        "rule": rule.name, "severity": rule.severity,
                        "time": event["time"],
                        "actions": make_results(rule, event),
                        "evidence": list(window),
                    })
                    window.clear()

            elif rule.kind == "time":
                dt = datetime.fromisoformat(event["time"])
                inside = in_range(dt.hour * 60 + dt.minute, rule.start, rule.end)
                if inside != rule.negate:
                    alerts.append({
                        "rule": rule.name, "severity": rule.severity,
                        "time": event["time"],
                        "actions": make_results(rule, event),
                        "evidence": [event],
                    })
    return alerts