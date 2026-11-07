from flask import Flask, jsonify, render_template, request
from parser import parse_rules, SentryError
from engine import parse_events, run

app = Flask(__name__)

def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()

@app.route("/")
def index():
    return render_template("index.html",
                           rules=read("rules.sentry"),
                           events=read("events.jsonl"))

@app.route("/api/run", methods=["POST"])
def api_run():
    data = request.get_json()
    try:
        rules = parse_rules(data["rules"], "your rules")
        events = parse_events(data["events"])
        alerts = run(rules, events)
    except SentryError as e:
        return jsonify(ok=False, error=str(e))
    except KeyError as e:
        return jsonify(ok=False,
                       error=f"An alert message uses {{{e.args[0]}}}, "
                             f"but the event has no field with that name.")

    for a in alerts:
        a["evidence"] = [{k: v for k, v in ev.items() if k != "_ts"}
                         for ev in a["evidence"]]
    return jsonify(ok=True, alerts=alerts,
                   rule_count=len(rules), event_count=len(events))

if __name__ == "__main__":
    app.run(debug=True)