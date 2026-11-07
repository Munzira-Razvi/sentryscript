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

`low`, `medium`, `high`, `critical`. Alerts are color-coded.

## Conditions

### Count condition

```
when <event> from <field> count >= <N> within <duration> [and <filter> ...]
```

Counts events of type `<event>`, grouped separately by `<field>` (for example
per IP), inside a sliding window. Fires when the count reaches `N`, then
starts counting again.

### Time condition

```
when <event> at time [not] in HH:MM..HH:MM [and <filter> ...]
```

Fires on a single event whose time of day is inside the range (or outside it
with `not`). Ranges may cross midnight, e.g. `22:00..06:00`.

### Filters

```
and <field> == "text"
and <field> != "text"
and <field> == 42
```

An event must pass every filter before it is counted or checked. Filters read
any field of the event.

## Durations

A number followed by `s`, `m` or `h`: `30s`, `2m`, `1h`.

## Actions

| Action | Example | Effect |
|---|---|---|
| `alert "text"` | `alert "Attack from {ip}"` | Reports an alert. `{field}` is filled from the event (shown as `?` if missing). |
| `block <field> for <duration>` | `block ip for 30m` | Simulated block, recorded in the output. |

## Events

Events are JSON lines with at least `time` and `type`, plus any other fields:

```
{"time": "2026-11-06T10:00:01", "type": "failed_login", "ip": "10.0.0.5", "user": "ali", "country": "PK"}
```

### Linux auth.log (`--format auth`)

| Log line | Event type |
|---|---|
| sshd `Failed password ...` | `failed_login` (fields: `user`, `ip`, `host`) |
| sshd `Accepted ...` | `login` |
| sudo `... COMMAND=...` | `admin_action` |

Syslog lines carry no year, so pass `--year 2026` (default: the current year).

## Command line

```
python sentry.py check <rules>
python sentry.py run <rules> <events> [--explain] [--format jsonl|auth] [--year N]
```

## Errors

Syntax errors show the file, line, column, a caret under the mistake and the
expected tokens. Unknown severity levels list the allowed values.