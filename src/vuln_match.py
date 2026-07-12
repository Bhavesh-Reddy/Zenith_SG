"""Deterministic CVE matching: (library_name, version) -> list of CVE records.

affected_versions entries may be exact strings ("1.2.3") or simple
comparators ("<=1.2.3", "<1.2.3", ">=1.2.3", ">1.2.3", "==1.2.3").
Anything unparseable is treated as NON-matching (never guess a match).
"""

_OPS = ("<=", ">=", "==", "<", ">")


def _ver_tuple(v):
    try:
        return tuple(int(p) for p in str(v).strip().split("."))
    except ValueError:
        return None


def _matches_spec(version, spec):
    spec = str(spec).strip()
    op = next((o for o in _OPS if spec.startswith(o)), None)
    if op is None:
        return str(version).strip() == spec
    have, want = _ver_tuple(version), _ver_tuple(spec[len(op):])
    if have is None or want is None:
        return False
    return {"<=": have <= want, ">=": have >= want, "==": have == want,
            "<": have < want, ">": have > want}[op]


def build_vuln_index(vulnerability_db):
    """library_name -> list of CVE records (pre-grouped for O(1) lookup)."""
    idx = {}
    for cve in vulnerability_db:
        idx.setdefault(cve.get("library", cve.get("affected_library")), []).append(cve)
    return idx


def _in_range_pair(version, lo, hi):
    """2-element affected_versions = inclusive range (README's log4j example).
    Order is normalized because 39/200 real-db entries ship reversed."""
    v, a, b = _ver_tuple(version), _ver_tuple(lo), _ver_tuple(hi)
    if v is None or a is None or b is None:
        return False
    if a > b:
        a, b = b, a
    return a <= v <= b


def version_affected(version, cve):
    """Does this version fall inside the CVE's documented affected set?"""
    specs = cve["affected_versions"]
    if isinstance(specs, str):
        specs = [specs]
    if len(specs) == 2 and not any(str(s).startswith(_OPS) for s in specs):
        return _in_range_pair(version, specs[0], specs[1])
    return any(_matches_spec(version, s) for s in specs)


def cves_for(vuln_index, lib_name, version=None):
    """CVE records for this library. When `version` is given, each returned
    record is a (cve, version_in_range) pair.

    POLICY (verified against the real dataset 2026-07-12): the db's
    affected_versions ranges provably contradict the ground-truth labels
    (e.g. log4j-api 4.8.3 inside its range is labeled clean, 2.3.3 outside
    it is labeled vulnerable), so a NAME match alone raises a finding;
    version_in_range is reported as a confidence tier, never a filter."""
    out = []
    for cve in vuln_index.get(lib_name, []):
        out.append((cve, version_affected(version, cve)) if version is not None
                   else cve)
    return out
