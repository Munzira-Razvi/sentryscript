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

def run(rules, events):
    alerts = []
    windows = {r.name: defaultdict(deque) for r in rules}

    for event in events:
        for rule in rules:
            if event["type"] != rule.event:
                continue
            key = event.get(rule.group_by)
            if key is None:
                continue

            window = windows[rule.name][key]
            window.append(event)

            while window and event["_ts"] - window[0]["_ts"] > rule.window:
                window.popleft()

            if len(window) >= rule.threshold:
                results = []
                for action in rule.actions:
                    if isinstance(action, Alert):
                        results.append(("alert", action.message.format_map(event)))
                    elif isinstance(action, Block):
                        target = event.get(action.field)
                        results.append(("block", f"{target} for "
                                        f"{fmt_duration(action.seconds)} (simulated)"))
                alerts.append({
                    "rule": rule.name,
                    "severity": rule.severity,
                    "time": event["time"],
                    "actions": results,
                    "evidence": list(window),
                })
                window.clear()
    return alerts

if __name__ == "__main__":
    rules = load_rules("rules.sentry")
    events = load_events("events.jsonl")
    alerts = run(rules, events)

    print(f"Processed {len(events)} events with {len(rules)} rule(s)\n")
    for a in alerts:
        color = COLORS[a["severity"]]
        print(f"{color}[{a['severity'].upper()}]{RESET} {a['rule']} at {a['time']}")
        for kind, text in a["actions"]:
            print(f"  {kind}: {text}")
        print(f"  triggered by {len(a['evidence'])} events\n")
    if not alerts:
        print("No alerts.")