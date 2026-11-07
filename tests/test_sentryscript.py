import json
import pytest

from parser import parse_rules, SentryError
from engine import parse_events, run
from logformats import parse_auth_log

COUNT_RULE = '''
rule brute {
  severity: high
  when failed_login from ip count >= 5 within 2m
  then alert "Brute force from {ip}"
}
'''

TIME_RULE = '''
rule night {
  when admin_action at time not in 08:00..18:00
  then alert "Off-hours by {user}"
}
'''


def make_events(*items):
    return parse_events("\n".join(json.dumps(i) for i in items))


def failed(ip, minute, second=0, **extra):
    return {"time": f"2026-11-06T10:{minute:02d}:{second:02d}",
            "type": "failed_login", "ip": ip, **extra}


def admin(clock, user="root"):
    return {"time": f"2026-11-06T{clock}", "type": "admin_action",
            "ip": "172.16.0.7", "user": user}


# ---------- parsing ----------

def test_parses_count_rule():
    rule = parse_rules(COUNT_RULE)[0]
    assert rule.name == "brute"
    assert rule.severity == "high"
    assert rule.kind == "count"
    assert rule.event == "failed_login"
    assert rule.group_by == "ip"
    assert rule.threshold == 5
    assert rule.window == 120


def test_parses_time_rule_with_filter():
    text = '''
    rule night {
      when admin_action at time not in 08:00..18:00 and user != "backup"
      then alert "x"
    }
    '''
    rule = parse_rules(text)[0]
    assert rule.kind == "time"
    assert rule.negate is True
    assert rule.start == 8 * 60 and rule.end == 18 * 60
    assert rule.severity == "medium"          # default
    assert rule.filters[0].field == "user"
    assert rule.filters[0].op == "!="
    assert rule.filters[0].value == "backup"


def test_syntax_error_reports_line_and_column():
    bad = COUNT_RULE.replace("count", "cuont")
    with pytest.raises(SentryError) as err:
        parse_rules(bad)
    assert "line" in str(err.value) and "column" in str(err.value)


def test_unknown_severity_is_rejected():
    with pytest.raises(SentryError) as err:
        parse_rules(COUNT_RULE.replace("high", "urgent"))
    assert "urgent" in str(err.value)


# ---------- count rules ----------

def test_fires_when_threshold_reached():
    events = make_events(*[failed("10.0.0.99", 0, s) for s in (0, 10, 20, 30, 40)])
    alerts = run(parse_rules(COUNT_RULE), events)
    assert len(alerts) == 1
    assert alerts[0]["actions"][0][1] == "Brute force from 10.0.0.99"
    assert len(alerts[0]["evidence"]) == 5


def test_does_not_fire_below_threshold():
    events = make_events(*[failed("10.0.0.99", 0, s) for s in (0, 10, 20, 30)])
    assert run(parse_rules(COUNT_RULE), events) == []


def test_old_events_leave_the_window():
    # five failures, but three minutes apart: never 5 inside any 2 minutes
    events = make_events(*[failed("10.0.0.99", m) for m in (0, 3, 6, 9, 12)])
    assert run(parse_rules(COUNT_RULE), events) == []


def test_each_ip_is_counted_separately():
    events = make_events(
        *[failed("10.0.0.1", 0, s) for s in (0, 10, 20)],
        *[failed("10.0.0.2", 0, s) for s in (5, 15, 25)],
    )
    assert run(parse_rules(COUNT_RULE), events) == []


def test_filter_excludes_matching_events():
    rule = '''
    rule r {
      when failed_login from ip count >= 2 within 1m and country != "PK"
      then alert "x"
    }
    '''
    home = make_events(failed("1.1.1.1", 0, 0, country="PK"),
                       failed("1.1.1.1", 0, 5, country="PK"))
    away = make_events(failed("2.2.2.2", 0, 0, country="RU"),
                       failed("2.2.2.2", 0, 5, country="RU"))
    assert run(parse_rules(rule), home) == []
    assert len(run(parse_rules(rule), away)) == 1


# ---------- time rules ----------

def test_time_rule_fires_outside_hours_only():
    events = make_events(admin("02:14:09"), admin("10:30:00", "sara"))
    alerts = run(parse_rules(TIME_RULE), events)
    assert len(alerts) == 1
    assert alerts[0]["actions"][0][1] == "Off-hours by root"


def test_time_range_can_cross_midnight():
    rule = '''
    rule late {
      when admin_action at time in 22:00..06:00
      then alert "late"
    }
    '''
    events = make_events(admin("23:30:00"), admin("12:00:00"))
    alerts = run(parse_rules(rule), events)
    assert len(alerts) == 1
    assert alerts[0]["time"] == "2026-11-06T23:30:00"


def test_missing_field_in_message_shows_question_mark():
    rule = '''
    rule r {
      when admin_action at time not in 08:00..18:00
      then alert "Hello {nothere}"
    }
    '''
    alerts = run(parse_rules(rule), make_events(admin("02:00:00")))
    assert alerts[0]["actions"][0][1] == "Hello ?"


# ---------- auth.log ----------

AUTH_LOG = """\
Nov  6 10:05:00 web01 sshd[2210]: Failed password for invalid user admin from 10.0.0.99 port 40110 ssh2
Nov  6 10:05:20 web01 sshd[2214]: Accepted password for sara from 192.168.1.14 port 51022 ssh2
Nov  6 02:14:09 web01 sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/apt update
Nov  6 03:00:00 web01 CRON[99]: something unrelated
"""


def test_auth_log_is_converted_to_events():
    events = parse_auth_log(AUTH_LOG, year=2026)
    assert [e["type"] for e in events] == ["admin_action", "failed_login", "login"]
    failed_event = events[1]
    assert failed_event["ip"] == "10.0.0.99"
    assert failed_event["user"] == "admin"


def test_unrecognised_log_gives_a_clear_error():
    with pytest.raises(SentryError):
        parse_auth_log("this is not a log file\n", year=2026)

        # ---------- lists: let, in, not in ----------

LIST_RULES = '''
let trusted = ["172.16.0.7", "172.16.0.8"]

rule unknown_login {
  when login from ip count >= 1 within 1m and user == "admin" and ip not in trusted
  then alert "Unfamiliar admin login from {ip}"
}
'''


def login(ip, user="admin"):
    return {"time": "2026-11-06T11:00:00", "type": "login",
            "ip": ip, "user": user}


def test_not_in_list_flags_only_unlisted_values():
    events = make_events(login("172.16.0.7"), login("198.51.100.23"))
    alerts = run(parse_rules(LIST_RULES), events)
    assert len(alerts) == 1
    assert alerts[0]["actions"][0][1] == "Unfamiliar admin login from 198.51.100.23"


def test_in_list_matches_only_listed_values():
    rules = parse_rules('''
    let privileged = ["admin", "root"]
    rule r {
      when failed_login from ip count >= 2 within 1m and user in privileged
      then alert "x"
    }
    ''')
    hit = make_events(failed("1.1.1.1", 0, 0, user="root"),
                      failed("1.1.1.1", 0, 5, user="root"))
    miss = make_events(failed("2.2.2.2", 0, 0, user="sara"),
                       failed("2.2.2.2", 0, 5, user="sara"))
    assert len(run(rules, hit)) == 1
    assert run(rules, miss) == []


def test_inline_list_works_without_let():
    rules = parse_rules('''
    rule r {
      when login from ip count >= 1 within 1m and ip not in ["10.0.0.1", "10.0.0.2"]
      then alert "x"
    }
    ''')
    events = make_events(login("10.0.0.1"), login("10.0.0.9"))
    assert len(run(rules, events)) == 1


def test_undefined_list_gives_a_clear_error():
    with pytest.raises(SentryError) as err:
        parse_rules(LIST_RULES.replace("let trusted", "let other"))
    assert "trusted" in str(err.value)