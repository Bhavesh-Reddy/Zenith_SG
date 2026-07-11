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
        idx.setdefault(cve["affected_library"], []).append(cve)
    return idx


def cves_for(vuln_index, lib_name, version):
    """All CVE records affecting this exact library+version."""
    hits = []
    for cve in vuln_index.get(lib_name, []):
        specs = cve["affected_versions"]
        if isinstance(specs, str):
            specs = [specs]
        if any(_matches_spec(version, s) for s in specs):
            hits.append(cve)
    return hits
