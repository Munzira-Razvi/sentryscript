import json
from collections import defaultdict, deque
from datetime import datetime

windows = defaultdict(deque)
for line in open("events.jsonl"):
    e = json.loads(line)
    if e["type"] != "failed_login":
        continue
    t = datetime.fromisoformat(e["time"]).timestamp()
    q = windows[e["ip"]]
    q.append(t)
    while q and t - q[0] > 120:
        q.popleft()
    if len(q) >= 5:
        print("Brute force from", e["ip"])
        q.clear()
        