from parser import parse_rules
from sigma import to_sigma

def test_count_rule_becomes_correlation():
    rules = parse_rules('''
    rule brute {
      severity: high
      when failed_login from ip count >= 5 within 2m and country != "PK"
      then alert "x"
    }
    ''')
    out = to_sigma(rules)
    assert "correlation:" in out
    assert "type: event_count" in out
    assert "gte: 5" in out
    assert "timespan: 2m" in out
    assert "- ip" in out
    assert "condition: selection and not filter_0" in out
    assert "level: high" in out

def test_time_rule_has_note_but_no_correlation():
    rules = parse_rules('''
    rule night {
      when admin_action at time not in 08:00..18:00
      then alert "x"
    }
    ''')
    out = to_sigma(rules)
    assert "correlation:" not in out
    assert "time of day" in out