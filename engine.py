import json
from collections import defaultdict, deque
from datetime import datetime
from parser import load_rules

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
    # For each rule: a separate sliding window of timestamps per group (e.g. per IP)
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

            # Slide the window: drop events older than the time limit
            while window and event["_ts"] - window[0]["_ts"] > rule.window:
                window.popleft()

            # Threshold reached: fire the alert
            if len(window) >= rule.threshold:
                alerts.append({
                    "rule": rule.name,
                    "time": event["time"],
                    "message": rule.message.format_map(event),
                    "evidence": list(window),
                })
                window.clear()  # avoid repeating the same alert

    return alerts

if __name__ == "__main__":
    rules = load_rules("rules.sentry")
    events = load_events("events.jsonl")
    alerts = run(rules, events)

    print(f"Processed {len(events)} events with {len(rules)} rule(s)\n")
    for a in alerts:
        print(f"[ALERT] {a['rule']} at {a['time']}")
        print(f"        {a['message']}")
        print(f"        triggered by {len(a['evidence'])} events\n")
    if not alerts:
        print("No alerts.")