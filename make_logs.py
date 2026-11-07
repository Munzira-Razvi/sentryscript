import json, random
from datetime import datetime, timedelta

random.seed(42)
start = datetime(2026, 11, 6, 10, 0, 0)
events = []

def add(t, type_, ip, user, country):
    events.append({"time": t.isoformat(), "type": type_,
                   "ip": ip, "user": user, "country": country})

# Normal traffic: each user mistypes a password once, then logs in
for i in range(10, 30):
    ip = f"192.168.1.{i}"
    user = f"user{i}"
    t = start + timedelta(seconds=random.randint(0, 600))
    add(t, "failed_login", ip, user, "PK")
    add(t + timedelta(seconds=20), "login", ip, user, "PK")

# Attacker 1: fast, 6 failures in 30 seconds
for i in range(6):
    add(start + timedelta(minutes=5, seconds=i * 5),
        "failed_login", "10.0.0.99", "admin", "RU")

# Attacker 2: slower, 12 failures over 4 minutes
for i in range(12):
    add(start + timedelta(minutes=20, seconds=i * 20),
        "failed_login", "203.0.113.50", "admin", "CN")

# Admin actions: one suspicious, one scheduled backup job, one normal
add(datetime(2026, 11, 6, 2, 14, 9), "admin_action", "172.16.0.7", "root", "PK")
add(datetime(2026, 11, 6, 3, 0, 0), "admin_action", "172.16.0.9", "backup", "PK")
add(datetime(2026, 11, 6, 10, 30, 0), "admin_action", "172.16.0.8", "sara", "PK")

events.sort(key=lambda e: e["time"])

# Admin login from an address nobody recognises
add(datetime(2026, 11, 6, 11, 15, 0), "login", "198.51.100.23", "admin", "RU")

# Attacker 3: guessing from inside the home country
for i in range(9):
    add(start + timedelta(minutes=40, seconds=i * 10),
        "failed_login", "192.168.1.200", "sara", "PK")

with open("events.jsonl", "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")

print(f"Wrote {len(events)} events to events.jsonl")