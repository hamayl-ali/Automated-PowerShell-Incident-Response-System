"""
sigma_engine.py
-----------------
A lightweight Sigma rule engine for evaluating community-style Sigma
detection rules (https://github.com/SigmaHQ/sigma) against normalized log
events (plain Python dicts).

This is NOT a full Sigma-spec implementation -- it supports the subset that
covers the large majority of real-world process_creation / PowerShell
rules:

  - detection blocks with named selections (selection, selection1, keywords,
    filter, etc.), each a dict of field: value(s)
  - field modifiers: |contains, |startswith, |endswith, |re, and |all as a
    combinable suffix (e.g. field|contains|all requires every value to match)
  - a list of values under one field = OR match across that list
  - condition expressions: "selection", "selection1 and selection2",
    "selection1 or selection2", "selection and not filter",
    "1 of selection*", "all of selection*"

NOT supported (see README limitations): parenthesized/nested boolean
expressions, aggregation conditions (count() by ...), timeframe/near
correlation across multiple events, and Sigma's full field-mapping/pipeline
system for translating field names between log sources.

Field names in this project's sample rules are aligned to this project's
own internal event schema (e.g. "script_block"), not the official Sigma
field taxonomy for a specific product -- see README for why.
"""

import os
import re
import yaml


def load_sigma_rules(rules_dir: str) -> list:
    """Loads every .yml/.yaml file in a directory as a Sigma rule dict."""
    rules = []
    if not rules_dir or not os.path.isdir(rules_dir):
        return rules
    for fn in sorted(os.listdir(rules_dir)):
        if not fn.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(rules_dir, fn)
        try:
            with open(path, "r") as f:
                rule = yaml.safe_load(f)
            if rule:
                rule["_file"] = fn
                rules.append(rule)
        except yaml.YAMLError:
            continue
    return rules


def _match_modifier(actual, expected, modifier) -> bool:
    if actual is None:
        return False
    actual_str = str(actual).lower()
    expected_str = str(expected).lower()
    if modifier == "contains":
        return expected_str in actual_str
    if modifier == "startswith":
        return actual_str.startswith(expected_str)
    if modifier == "endswith":
        return actual_str.endswith(expected_str)
    if modifier == "re":
        return bool(re.search(str(expected), str(actual), re.I))
    return actual_str == expected_str  # plain equality, no modifier


def _eval_field_condition(event: dict, field_key: str, value) -> bool:
    """field_key may be 'field', 'field|contains', or 'field|contains|all'."""
    parts = field_key.split("|")
    field = parts[0]
    modifiers = [p for p in parts[1:] if p != "all"]
    require_all = "all" in parts[1:]
    modifier = modifiers[0] if modifiers else None

    actual = event.get(field)
    values = value if isinstance(value, list) else [value]

    results = [_match_modifier(actual, v, modifier) for v in values]
    return all(results) if require_all else any(results)


def _eval_selection(event: dict, selection) -> bool:
    """A selection is normally a dict of field:value pairs, AND'd together.
    A list of dicts at the top level means OR across the alternatives."""
    if isinstance(selection, list):
        return any(_eval_selection(event, item) for item in selection)
    return all(_eval_field_condition(event, k, v) for k, v in selection.items())


def _resolve_wildcard_group(detection: dict, pattern: str) -> list:
    prefix = pattern.rstrip("*")
    return [k for k in detection.keys() if k != "condition" and k.startswith(prefix)]


def _eval_condition(event: dict, detection: dict, condition: str) -> bool:
    condition = condition.strip()

    match = re.match(r"^(1|all)\s+of\s+([\w*]+)$", condition, re.I)
    if match:
        quant, pattern = match.groups()
        names = _resolve_wildcard_group(detection, pattern)
        results = [_eval_selection(event, detection[n]) for n in names if n in detection]
        if not results:
            return False
        return any(results) if quant == "1" else all(results)

    match = re.match(r"^not\s+(.+)$", condition, re.I)
    if match:
        return not _eval_condition(event, detection, match.group(1))

    # Left-to-right, no parenthesis support -- sufficient for the two/three
    # term conditions common in real-world process_creation Sigma rules.
    lowered = condition.lower()
    if " and not " in lowered:
        idx = lowered.index(" and not ")
        left, right = condition[:idx], condition[idx + len(" and not "):]
        return _eval_condition(event, detection, left) and not _eval_condition(event, detection, right)
    if " and " in lowered:
        idx = lowered.index(" and ")
        left, right = condition[:idx], condition[idx + len(" and "):]
        return _eval_condition(event, detection, left) and _eval_condition(event, detection, right)
    if " or " in lowered:
        idx = lowered.index(" or ")
        left, right = condition[:idx], condition[idx + len(" or "):]
        return _eval_condition(event, detection, left) or _eval_condition(event, detection, right)

    name = condition.strip()
    return _eval_selection(event, detection[name]) if name in detection else False


def evaluate_rule(event: dict, rule: dict) -> bool:
    detection = rule.get("detection", {})
    condition = detection.get("condition", "")
    if not condition:
        return False
    try:
        return _eval_condition(event, detection, condition)
    except Exception:
        return False  # a malformed/unsupported rule should never crash a scan


def evaluate_rules(event: dict, rules: list) -> list:
    """Returns a list of findings (project-standard shape) for every Sigma
    rule that matches this event."""
    findings = []
    for rule in rules:
        if not evaluate_rule(event, rule):
            continue
        mitre_tags = [t for t in rule.get("tags", []) if t.lower().startswith("attack.t")]
        findings.append({
            "rule": rule.get("title", rule.get("_file", "Unnamed Sigma Rule")),
            "mitre_technique": ", ".join(t.split(".", 1)[1].upper() for t in mitre_tags) or "N/A",
            "mitre_technique_name": rule.get("title", ""),
            "mitre_tactic": ", ".join(
                t.split(".", 1)[1].replace("_", " ").title()
                for t in rule.get("tags", []) if t.lower().startswith("attack.") and not t.lower().startswith("attack.t")
            ) or "N/A",
            "severity": rule.get("level", "medium"),
            "source": "sigma",
            "sigma_id": rule.get("id"),
        })
    return findings
