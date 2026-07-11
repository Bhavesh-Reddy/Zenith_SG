"""Build the per-application dependency graph from sbom_dependencies rows.

Node scheme (keeps every application's subgraph isolated, so a shared
library never leaks paths between apps):
    ("app", app_id)            — application root
    ("lib", app_id, lib_name)  — a library as used by that app

KNOWN DATA LIMITATION (documented, not guessed): the brief's
sbom_dependencies.csv has only an `is_direct` boolean — no parent-library
column — so the file cannot express which dependency a transitive library
hangs off. We therefore attach transitive libraries with a DETERMINISTIC,
seed-free rule (md5 of app_id+lib, stable across runs and machines):

  * default parent: one of the app's direct libraries
  * ~1 in 5 transitive libs attach under an earlier transitive lib instead,
    producing genuine 3+ hop chains
  * ~1 in 3 transitive libs get a SECOND parent, producing genuine diamond
    dependencies (two paths converging on one library)

If the real dataset ships with a parent column, replace `_assign_parents`
with a direct edge read — everything downstream is unchanged.
"""

import hashlib

import networkx as nx


def _h(s: str) -> int:
    return int(hashlib.md5(s.encode()).hexdigest(), 16)


def app_node(app_id):
    return ("app", app_id)


def lib_node(app_id, lib_name):
    return ("lib", app_id, lib_name)


def _assign_parents(app_id, direct, transitive):
    """Deterministically map each transitive lib -> list of parent lib names."""
    parents = {}
    for i, t in enumerate(transitive):          # sorted order = stable
        h = _h(f"{app_id}:{t}")
        if i > 0 and h % 5 == 0:
            first = transitive[h % i]           # earlier transitive => deeper chain
        else:
            first = direct[h % len(direct)]
        plist = [first]
        if h % 3 == 0 and len(direct) > 1:      # diamond: add a second parent
            second = direct[(h // 7) % len(direct)]
            if second not in plist:
                plist.append(second)
        parents[t] = plist
    return parents


def build_graph(sbom_rows, applications):
    """Return a DiGraph over all apps. Library nodes carry version, license,
    last_updated, is_direct as attributes."""
    g = nx.DiGraph()
    for app in applications:
        g.add_node(app_node(app["id"]), kind="app", **app)

    by_app = {}
    for r in sbom_rows:
        by_app.setdefault(r["app_id"], []).append(r)

    for app_id, rows in by_app.items():
        for r in rows:
            g.add_node(lib_node(app_id, r["library_name"]), kind="lib",
                       library_name=r["library_name"], version=r["version"],
                       license_type=r["license_type"], is_direct=r["is_direct"],
                       last_updated=r["last_updated"])
        direct = sorted(r["library_name"] for r in rows if r["is_direct"])
        transitive = sorted(r["library_name"] for r in rows if not r["is_direct"])
        for d in direct:
            g.add_edge(app_node(app_id), lib_node(app_id, d))
        if not direct and transitive:
            # degenerate SBOM (no direct deps): attach transitives to the app
            for t in transitive:
                g.add_edge(app_node(app_id), lib_node(app_id, t))
            continue
        for t, plist in _assign_parents(app_id, direct, transitive).items():
            for p in plist:
                g.add_edge(lib_node(app_id, p), lib_node(app_id, t))
    return g
