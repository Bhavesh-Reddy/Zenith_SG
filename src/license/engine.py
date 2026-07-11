"""License compatibility engine (deterministic, rule-table driven).

DOCUMENTED ASSUMPTION: all applications are treated as proprietary,
internally-developed software (the SocGen context), so a dependency's
license conflicts iff its rule's compatible_with list does not include
"Proprietary".

DOCUMENTED LIMITATION: neither applications.json nor sbom_dependencies.csv
carries a distribution-scope field (distributed vs. internal-only use), so
this engine cannot distinguish a GPL library that is merely used internally
from one that is shipped to customers. All copyleft conflicts are flagged
with `scope_known: false` in the evidence rather than silently guessed.
"""

APP_LICENSE_CONTEXT = "Proprietary"


def build_rule_index(license_rules):
    return {r["license_type"]: r for r in license_rules}


def check_license(rule_index, license_type):
    """Return (is_conflict, rule_or_None, note)."""
    rule = rule_index.get(license_type)
    if rule is None:
        return False, None, f"no rule for license '{license_type}' — not flagged (unknown, not guessed)"
    if APP_LICENSE_CONTEXT in rule.get("compatible_with", []):
        return False, rule, "compatible with proprietary use"
    return True, rule, (f"{license_type} not compatible with {APP_LICENSE_CONTEXT} "
                        f"per license_rules (risk_level={rule['risk_level']}); "
                        f"distribution scope unknown — no scope field in data")


def license_risk_tier(rule_index, license_type):
    """0 = low/unknown, 1 = medium, 2 = high (feature for the ML layer)."""
    rule = rule_index.get(license_type)
    if rule is None:
        return 0
    return {"low": 0, "medium": 1, "high": 2}.get(rule.get("risk_level"), 0)
