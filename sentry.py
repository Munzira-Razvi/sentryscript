import argparse
import sys
from parser import load_rules, SentryError
from engine import load_events, run, COLORS, RESET

def print_alerts(alerts):
    for a in alerts:
        color = COLORS[a["severity"]]
        print(f"{color}[{a['severity'].upper()}]{RESET} {a['rule']} at {a['time']}")
        for kind, text in a["actions"]:
            print(f"  {kind}: {text}")
        n = len(a["evidence"])
        print(f"  triggered by {n} event{'s' if n != 1 else ''}\n")

def main():
    ap = argparse.ArgumentParser(
        prog="sentry", description="SentryScript: detection rules for security logs")
    sub = ap.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="validate a rule file")
    check.add_argument("rules")

    runp = sub.add_parser("run", help="run rules against an event log")
    runp.add_argument("rules")
    runp.add_argument("events")

    args = ap.parse_args()

    try:
        rules = load_rules(args.rules)
        if args.command == "check":
            print(f"OK: {len(rules)} rule(s) valid in {args.rules}")
            return
        events = load_events(args.events)
        alerts = run(rules, events)
    except SentryError as e:
        print(f"error: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"error: file not found: {e.filename}")
        sys.exit(1)

    print(f"Processed {len(events)} events with {len(rules)} rule(s)\n")
    print_alerts(alerts)
    if not alerts:
        print("No alerts.")

if __name__ == "__main__":
    main()