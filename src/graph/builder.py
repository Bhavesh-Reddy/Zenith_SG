"""Build the per-application dependency graph from canonical SBOM rows.

Node scheme (keeps every application's subgraph isolated, so a shared
library never leaks paths between apps):
    ("app", app_id)            — application root
    ("lib", app_id, lib_name)  — a library as used by that app

Edge sources, in order of preference:

1. REAL edges from transitive_dependencies.json (parent_library ->
   child_library per application). NOTE, verified 2026-07-12: the
   parent/child *version* fields in that file are inconsistent with
   sbom_dependencies.csv (all 372 edges mismatch), so edges are wired by
   library NAME within each app and versions are always taken from the
   SBOM row — the same convention the ground-truth labels use.
   Transitive SBOM rows with no incoming edge (10 exist in the real data)
   are attached directly under the app root so no dependency is ever
   pathless; these carry orphan=True.

2. If no edges file exists (placeholder data), fall back to a
   DETERMINISTIC md5-based parent assignment (documented limitation of
   the placeholder schema, which lacks parent info).
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
    """Placeholder-data fallback: deterministic transitive->parents map."""
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


def build_graph(sbom_rows, applications, transitive_edges=None):
    """DiGraph over all apps. Library nodes carry the SBOM row attributes."""
    g = nx.DiGraph()
    for app in applications:
        g.add_node(app_node(app["app_id"]), kind="app", **app)

    by_app = {}
    for r in sbom_rows:
        by_app.setdefault(r["application_id"], []).append(r)

    edges_by_app = {}
    for e in transitive_edges or []:
        edges_by_app.setdefault(e["application_id"], []).append(
            (e["parent_library"], e["child_library"]))

    for app_id, rows in by_app.items():
        known = set()
        for r in rows:
            known.add(r["library"])
            g.add_node(lib_node(app_id, r["library"]), kind="lib",
                       library=r["library"], version=r["version"],
                       license=r["license"],
                       dependency_type=r["dependency_type"],
                       last_updated=r["last_updated"], dep_id=r["dep_id"])
        direct = sorted(r["library"] for r in rows
                        if r["dependency_type"] == "direct")
        transitive = sorted(r["library"] for r in rows
                            if r["dependency_type"] == "transitive")
        for d in direct:
            g.add_edge(app_node(app_id), lib_node(app_id, d))

        if transitive_edges:
            wired = set()
            for parent, child in edges_by_app.get(app_id, []):
                if parent in known and child in known:
                    g.add_edge(lib_node(app_id, parent), lib_node(app_id, child))
                    wired.add(child)
            for t in transitive:                # orphans: keep them reachable
                if t not in wired:
                    g.nodes[lib_node(app_id, t)]["orphan"] = True
                    g.add_edge(app_node(app_id), lib_node(app_id, t))
        elif direct:
            for t, plist in _assign_parents(app_id, direct, transitive).items():
                for p in plist:
                    g.add_edge(lib_node(app_id, p), lib_node(app_id, t))
        else:
            for t in transitive:
                g.add_edge(app_node(app_id), lib_node(app_id, t))
    return g
