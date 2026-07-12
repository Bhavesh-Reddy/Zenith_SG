"""License compatibility engine (deterministic, rule-table driven).

Real-schema rules: each license_rules.json record carries
`compatible_with_proprietary` (bool), `viral` (bool), `risk_level`.
Applications carry `license_model` ('proprietary' | 'internal-only') —
this is the distribution-scope signal that was a documented limitation
before the real dataset arrived.

Decision table (mirrors the dataset's own documented semantics):
  * viral license (GPL-2.0/GPL-3.0/AGPL-3.0) in a PROPRIETARY app
        -> CONFLICT
  * viral license in an INTERNAL-ONLY app
        -> no conflict (not distributed), but an advisory note is emitted
           so the report can still surface it for legal awareness
  * license 'UNKNOWN' or no matching rule
        -> UNKNOWN status (legal review needed; separate finding type)
  * everything else -> compatible
"""

CONFLICT, UNKNOWN, ADVISORY, OK = "conflict", "unknown", "advisory", "ok"


def build_rule_index(license_rules):
    return {r["license"]: r for r in license_rules}


def check_license(rule_index, license_name, app_license_model):
    """Return (status, rule_or_None, note)."""
    rule = rule_index.get(license_name)
    if rule is None or license_name == "UNKNOWN":
        return UNKNOWN, rule, (f"license '{license_name}' has no declared/known "
                               f"terms — legal status unclear, flagged for review "
                               f"(never silently assumed compatible)")
    if rule["viral"] and not rule["compatible_with_proprietary"]:
        if app_license_model == "proprietary":
            return CONFLICT, rule, (f"{license_name} is viral copyleft "
                                    f"(risk={rule['risk_level']}) inside a "
                                    f"proprietary application — derivative works "
                                    f"would require open-sourcing")
        return ADVISORY, rule, (f"{license_name} is viral copyleft but the "
                                f"application is {app_license_model} (not "
                                f"distributed) — no conflict under current use; "
                                f"re-evaluate before any external distribution")
    return OK, rule, "compatible with application license model"


def license_risk_tier(rule_index, license_name):
    """0=LOW/none, 1=MEDIUM, 2=HIGH, 3=CRITICAL (feature for the ML layer)."""
    rule = rule_index.get(license_name)
    if rule is None:
        return 2  # unknown terms ~ HIGH per the dataset's own risk guide
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(rule["risk_level"], 0)
