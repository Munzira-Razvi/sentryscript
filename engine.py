import json
from collections import defaultdict, deque
from datetime import datetime
from parser import load_rules, Alert, Block

COLORS = {"low": "\033[36m", "medium": "\033[33m",
          "high": "\033[31m", "critical": "\033[1;41m"}
RESET = "\033[0m"

def fmt_duration(seconds):
    for unit, size in (("h", 3600), ("m", 60)):
        if seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"

def load_events(path):
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                e = json.loads(line)
                e["_ts"] = datetime.fromisoformat(e["time"]).timestamp()
                events.append(e)
    events.sort(key=lambda e: e["_ts"])
    return events

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

def run(rules, events):
    alerts = []
    windows = {r.name: defaultdict(deque) for r in rules}

    for event in events:
        for rule in rules:
            if event["type"] != rule.event:
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