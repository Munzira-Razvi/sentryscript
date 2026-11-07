import re
from datetime import datetime
from parser import SentryError

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w./-]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")
FAILED = re.compile(r"Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)")
SUDO = re.compile(r"^(?P<user>\S+)\s+:\s+.*COMMAND=")

def parse_auth_log(text, year=None):
    """Turn Linux auth.log / syslog lines into SentryScript events.

    Syslog timestamps have no year, so one is supplied (default: this year).
    """
    year = year or datetime.now().year
    events = []
    for line in text.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        month = MONTHS.get(m["mon"])
        if month is None:
            continue
        try:
            h, mi, s = (int(x) for x in m["clock"].split(":"))
            when = datetime(year, month, int(m["day"]), h, mi, s)
        except ValueError:
            continue

        msg, proc = m["msg"], m["proc"]
        etype, hit = None, None
        if proc == "sshd":
            if (hit := FAILED.search(msg)):
                etype = "failed_login"
            elif (hit := ACCEPTED.search(msg)):
                etype = "login"
        elif proc == "sudo":
            if (hit := SUDO.match(msg)):
                etype = "admin_action"
        if etype is None:
            continue

        events.append({
            "time": when.isoformat(),
            "type": etype,
            "user": hit["user"],
            "ip": hit.groupdict().get("ip", "local"),
            "host": m["host"],
            "_ts": when.timestamp(),
        })

    if not events:
        raise SentryError(
            "No SSH or sudo events were recognised in this log. "
            "Is it a Linux auth.log, and did you pass --format auth?")
    events.sort(key=lambda e: e["_ts"])
    return events