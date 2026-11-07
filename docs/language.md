# SentryScript Language Reference

## Program structure

A program is one or more rules. Comments start with `#`.

```
rule <name> {
  severity: <level>        # optional, default: medium
  when <condition>
  then <action> [<action> ...]
}
```

## Severity

`low`, `medium`, `high`, `critical`. Alerts are color-coded in the terminal.

## Conditions

### Count condition

```
when <event> from <field> count >= <N> within <duration>
```

Counts events of type `<event>`, grouped separately by `<field>` (for example
per IP), inside a sliding window. The rule fires when the count reaches `N`.

### Time condition

```
when <event> at time [not] in HH:MM..HH:MM
```

Fires on a single event whose time of day is inside the range (or outside it
with `not`). Ranges may cross midnight, e.g. `22:00..06:00`.

## Durations

A number followed by `s` (seconds), `m` (minutes) or `h` (hours): `30s`, `2m`, `1h`.

## Actions

| Action | Example | Effect |
|---|---|---|
| `alert "text"` | `alert "Attack from {ip}"` | Reports an alert. `{field}` is filled from the event. |
| `block <field> for <duration>` | `block ip for 30m` | Simulated block, recorded in the output. |

## Event format

Events are JSON lines with at least `time`, `type`, plus any fields:

```
{"time": "2026-11-06T10:00:01", "type": "failed_login", "ip": "10.0.0.5", "user": "ali"}
```

## Errors

Syntax errors show the file, line, column and the expected token. Unknown
severity levels list the allowed values.