import argparse
import sys
from parser import load_rules, SentryError
from engine import parse_events, run, COLORS, RESET
from logformats import parse_auth_log
from sigma import to_sigma

def read_events(path, fmt, year):
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    if fmt == "auth":
        return parse_auth_log(text, year)
    return parse_events(text)

def print_alerts(alerts, explain=False):
    for a in alerts:
        color = COLORS[a["severity"]]
        print(f"{color}[{a['severity'].upper()}]{RESET} {a['rule']} at {a['time']}")
        for kind, text in a["actions"]:
            print(f"  {kind}: {text}")
        n = len(a["evidence"])
        print(f"  triggered by {n} event{'s' if n != 1 else ''}")
        if explain:
            print("  evidence:")
            for e in a["evidence"]:
                extras = ", ".join(f"{k}={v}" for k, v in e.items()
                                   if k not in ("time", "type", "_ts"))
                print(f"    {e['time']}  {e['type']:<14} {extras}")
        print()

def main():
    ap = argparse.ArgumentParser(
        prog="sentry", description="SentryScript: detection rules for security logs")
    sub = ap.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="validate a rule file")
    check.add_argument("rules")

    runp = sub.add_parser("run", help="run rules against an event log")
    runp.add_argument("rules")
    runp.add_argument("events")
    runp.add_argument("--explain", action="store_true",
                      help="show the events that triggered each alert")
    runp.add_argument("--format", choices=["jsonl", "auth"], default="jsonl",
                      help="log format: jsonl (default) or auth (Linux auth.log)")
    runp.add_argument("--year", type=int,
                      help="year for auth.log timestamps (default: this year)")

    comp = sub.add_parser("compile", help="export rules to another format")
    comp.add_argument("rules")
    comp.add_argument("--to", choices=["sigma"], default="sigma")
    comp.add_argument("-o", "--output", help="write to a file instead of the screen")

    args = ap.parse_args()

    try:
        rules = load_rules(args.rules)
        if args.command == "check":
            print(f"OK: {len(rules)} rule(s) valid in {args.rules}")
            return
        if args.command == "compile":
            text = to_sigma(rules)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(text)
                print(f"Wrote {len(rules)} rule(s) as Sigma to {args.output}")
            else:
                print(text)
            return
        events = read_events(args.events, args.format, args.year)
        alerts = run(rules, events)
    except SentryError as e:
        print(f"error: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"error: file not found: {e.filename}")
        sys.exit(1)

    print(f"Processed {len(events)} events with {len(rules)} rule(s)\n")
    print_alerts(alerts, args.explain)
    if not alerts:
        print("No alerts.")

if __name__ == "__main__":
    main()
    