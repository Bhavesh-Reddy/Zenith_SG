"""Hand-built 6-node graph with known 2-hop and 3-hop vulnerable chains,
including a diamond converging on the vulnerable library V.

Structure (all edges explicit — independent of the CSV parent-assignment
rule, so this proves the TRAVERSAL itself is correct):

    APP-X ── libA ── libC ── libV   (3-hop chain)
    APP-X ── libB ── libV           (2-hop chain)  } diamond on libV
    APP-X ── libB ── libD           (clean, must NOT be flagged)

Expected path set to libV, exactly:
    [APP-X, libA, libC, libV]
    [APP-X, libB, libV]

Run:  python -m tests.test_graph   (also pytest-compatible)
"""

import networkx as nx

from src.graph.builder import app_node, lib_node
from src.graph.traversal import depth_of, paths_to_library
from src.vuln_match import build_vuln_index, cves_for


def _build_fixture():
    g = nx.DiGraph()
    a = "APP-X"
    g.add_node(app_node(a), kind="app")
    for lib in ("libA", "libB", "libC", "libD", "libV"):
        g.add_node(lib_node(a, lib), kind="lib", library_name=lib)
    g.add_edge(app_node(a), lib_node(a, "libA"))
    g.add_edge(app_node(a), lib_node(a, "libB"))
    g.add_edge(lib_node(a, "libA"), lib_node(a, "libC"))
    g.add_edge(lib_node(a, "libC"), lib_node(a, "libV"))
    g.add_edge(lib_node(a, "libB"), lib_node(a, "libV"))
    g.add_edge(lib_node(a, "libB"), lib_node(a, "libD"))
    return g, a


def test_exact_path_set_to_vulnerable_lib():
    g, a = _build_fixture()
    paths = sorted(paths_to_library(g, a, "libV"))
    expected = sorted([["APP-X", "libA", "libC", "libV"],
                       ["APP-X", "libB", "libV"]])
    assert paths == expected, f"path set mismatch:\n got {paths}\n exp {expected}"


def test_hop_counts():
    g, a = _build_fixture()
    assert depth_of(g, a, "libB") == 1          # direct
    assert depth_of(g, a, "libV") == 2          # shortest of the two paths
    assert depth_of(g, a, "libC") == 2
    lengths = sorted(len(p) - 1 for p in paths_to_library(g, a, "libV"))
    assert lengths == [2, 3], f"expected one 2-hop and one 3-hop chain, got {lengths}"


def test_clean_lib_single_expected_path_and_no_false_extra():
    g, a = _build_fixture()
    assert paths_to_library(g, a, "libD") == [["APP-X", "libB", "libD"]]
    assert paths_to_library(g, a, "libZ") == []   # absent lib: no paths invented


def test_diamond_not_deduplicated_and_version_matching():
    g, a = _build_fixture()
    vuln_db = [{"cve_id": "CVE-T-1", "affected_library": "libV",
                "affected_versions": ["1.0.0", "<0.9.0"],
                "cvss_score": 9.1, "has_patch": False}]
    idx = build_vuln_index(vuln_db)
    assert cves_for(idx, "libV", "1.0.0") == [(vuln_db[0], True)]   # exact
    assert cves_for(idx, "libV", "0.8.2") == [(vuln_db[0], True)]   # comparator
    # near-miss version: still name-matched (policy) but NOT version-confirmed
    assert cves_for(idx, "libV", "1.0.1") == [(vuln_db[0], False)]
    assert cves_for(idx, "libD", "1.0.0") == []          # clean lib: no match
    assert len(paths_to_library(g, a, "libV")) == 2      # compound, not deduped


if __name__ == "__main__":
    for fn in (test_exact_path_set_to_vulnerable_lib, test_hop_counts,
               test_clean_lib_single_expected_path_and_no_false_extra,
               test_diamond_not_deduplicated_and_version_matching):
        fn()
        print(f"PASS {fn.__name__}")
    print("all hand-built graph tests passed")
