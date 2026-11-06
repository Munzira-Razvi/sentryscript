import json, random
from datetime import datetime, timedelta

random.seed(42)  # same data every run, so results are predictable
start = datetime(2026, 11, 6, 10, 0, 0)
events = []

# Normal traffic: each user occasionally mistypes a password once or twice
normal_ips = [f"192.168.1.{i}" for i in range(10, 30)]
for ip in normal_ips:
    t = start + timedelta(seconds=random.randint(0, 600))
    events.append({"time": t.isoformat(), "type": "failed_login",
                   "ip": ip, "user": f"user{ip[-2:]}"})
    events.append({"time": (t + timedelta(seconds=20)).isoformat(),
                   "type": "login", "ip": ip, "user": f"user{ip[-2:]}"})

# The attack: 6 failed logins from one IP within 30 seconds
attacker = "10.0.0.99"
attack_start = start + timedelta(minutes=5)
for i in range(6):
    t = attack_start + timedelta(seconds=i * 5)
    events.append({"time": t.isoformat(), "type": "failed_login",
                   "ip": attacker, "user": "admin"})

events.sort(key=lambda e: e["time"])

with open("events.jsonl", "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")

print(f"Wrote {len(events)} events to events.jsonl")