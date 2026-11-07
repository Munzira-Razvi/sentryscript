# SentryScript

**A small language for writing security detection rules.**

Security teams write rules like "alert me if one IP fails to log in 5 times
in 2 minutes." In general-purpose code, that takes dozens of lines of
parsing, counting and time handling. In SentryScript it takes five.

```
rule brute_force {
  severity: high
  when failed_login from ip count >= 5 within 2m
  then alert "Brute force from {ip}"
       block ip for 30m
}
```

## Why a DSL?

- **Readable by non-programmers**: a security analyst can review the rules.
- **Time windows built in**: sliding-window counting per IP or user is one phrase.
- **Safe by design**: actions like `block` are simulated, so rules can be tested without side effects.
- **Helpful errors**: mistakes show the file, line, column and what was expected.
- **Explainable alerts**: --explain shows the exact events behind every alert.

## Quick start

Requires Python 3.11+.

```
pip install lark
python make_logs.py                                   # create sample logs
python sentry.py check rules.sentry                   # validate rules
python sentry.py run rules.sentry events.jsonl        # run rules on logs
python sentry.py run rules.sentry events.jsonl --explain   # show why each alert fired
```

Example output:

```
[HIGH] brute_force at 2026-11-06T10:05:20
  alert: Brute force from 10.0.0.99
  block: 10.0.0.99 for 30m (simulated)
  triggered by 5 events
```

## Language overview

Two kinds of rules:

**Count rules**: fire when an event happens too often in a time window.

```
when failed_login from ip count >= 5 within 2m
```

**Time rules**: fire when an event happens inside or outside a time range.

```
when admin_action at time not in 08:00..18:00
```

Actions: `alert "message with {fields}"` and `block <field> for <duration>`.
Optional `severity: low | medium | high | critical`.

See [docs/language.md](docs/language.md) for the full reference and the
[examples](examples/) folder for sample programs.

## How it works

```
rules.sentry --> Lark parser --> AST --> Rule engine --> Alerts
                                            ^
                    events.jsonl (JSON logs)+
```

- `grammar.lark`: the language grammar
- `parser.py`: turns rule text into Python objects, with friendly errors
- `engine.py`: sliding-window and time-of-day evaluation
- `sentry.py`: command-line tool (`check` and `run`)
- `make_logs.py`: generates sample attack traffic for testing

## Real-world use case

A small company with no budget for a commercial SIEM can write its whole
detection policy in one readable file (see `examples/startup_policy.sentry`),
run it over its login logs, and review alerts with the evidence that
triggered each one.

## Roadmap

- Export rules to Sigma format
- More actions (webhooks, email)
- Conditions combined with `and`

## License

MIT