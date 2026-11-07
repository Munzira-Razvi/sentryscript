# SentryScript

**A small language for writing security detection rules.**

Security teams constantly need rules like "alert me if one IP fails to log in
5 times in 2 minutes, unless it comes from our home country." In
general-purpose code that means parsing logs, tracking time windows and
counting per IP. In SentryScript it is one readable rule:

```
rule brute_force {
  severity: high
  when failed_login from ip count >= 5 within 2m and country != "PK"
  then alert "Brute force from {ip} ({country})"
       block ip for 30m
}
```

## Features

- **Readable rules**: a security analyst can review them without being a programmer
- **Built-in time windows**: sliding-window counting per IP or per user is one phrase
- **Two rule types**: count rules (too many events) and time rules (events at odd hours)
- **Filters with `and`**: narrow any rule by event fields (`country != "PK"`, `user == "admin"`)
- **Explainable alerts**: `--explain` shows the exact events behind every alert
- **Real log support**: reads Linux `auth.log` (SSH logins, sudo commands) directly
- **Web playground**: write rules, paste logs and see alerts in the browser
- **Helpful errors**: file, line, column, a caret under the mistake, and what was expected
- **Editor support**: syntax highlighting for `.sentry` files in VS Code
- **Safe by design**: actions such as `block` are simulated, so rules can be tested freely

## Quick start

Requires Python 3.11+.

```
pip install -r requirements.txt
python make_logs.py                                    # create sample logs
python sentry.py check rules.sentry                    # validate rules
python sentry.py run rules.sentry events.jsonl         # run rules on logs
python sentry.py run rules.sentry events.jsonl --explain
```

Real Linux logs:

```
python sentry.py run examples/ssh_auth.sentry samples/auth.log --format auth --year 2026 --explain
```

Web playground:

```
python app.py        # then open http://127.0.0.1:5000
```

Example output:

```
[HIGH] brute_force at 2026-11-06T10:05:20
  alert: Brute force from 10.0.0.99 (RU)
  block: 10.0.0.99 for 30m (simulated)
  triggered by 5 events
  evidence:
    2026-11-06T10:05:00  failed_login   ip=10.0.0.99, user=admin, country=RU
    ...
```

## Language overview

**Count rules** fire when an event happens too often in a time window:

```
when failed_login from ip count >= 5 within 2m
```

**Time rules** fire when an event happens inside or outside a time range:

```
when admin_action at time not in 08:00..18:00
```

**Filters** narrow either kind of rule:

```
when admin_action at time not in 08:00..18:00 and user != "backup"
```

**Actions**: `alert "message with {fields}"` and `block <field> for <duration>`.
**Severity** (optional): `low | medium | high | critical`.

See [docs/language.md](docs/language.md) for the full reference and the
[examples](examples/) folder for complete programs.

## How it works

```
rules.sentry --> Lark parser --> AST --> Rule engine --> Alerts
                                            ^
     events.jsonl or auth.log --> events ---+
```

| File | Purpose |
|---|---|
| `grammar.lark` | the language grammar |
| `parser.py` | turns rule text into Python objects, with friendly errors |
| `engine.py` | sliding-window, time-of-day and filter evaluation |
| `logformats.py` | converts Linux `auth.log` lines into events |
| `sentry.py` | command-line tool (`check` and `run`) |
| `app.py` and `templates/` | web playground |
| `vscode-extension/` | syntax highlighting for VS Code |
| `make_logs.py` | generates sample attack traffic |
## Tests

```
pip install pytest
python -m pytest -v
```

## Editor support (VS Code)

Copy the `vscode-extension` folder to `%USERPROFILE%\.vscode\extensions\sentryscript-lang`
(Linux/Mac: `~/.vscode/extensions/`) and reload VS Code.

## Real-world use case

A small company with no budget for a commercial SIEM can write its whole
detection policy in one readable file (see `examples/startup_policy.sentry`),
run it over its real SSH logs, and review alerts together with the evidence
that triggered each one.

## Roadmap

- Export rules to Sigma format
- More actions (webhooks, email)
- Web-server log formats (nginx, Apache)
- Live mode that watches a log file as it grows

## License

MIT