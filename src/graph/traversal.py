"""Full-path enumeration from an application to any target library.

Uses exhaustive simple-path search (NetworkX all_simple_paths, DFS-based).
The graph is a DAG by construction, so enumeration terminates and finds
EVERY distinct path — this is what backs the 100% transitive-resolution
claim. Multiple paths to one library are all returned (diamond = compound
risk; never deduplicate here).
"""

import networkx as nx

from src.graph.builder import app_node, lib_node


def paths_to_library(g, app_id, lib_name):
    """All simple paths app -> lib as lists of readable names,
    e.g. ["APP-001", "flask", "jinja2"]. Empty list if unreachable."""
    src, dst = app_node(app_id), lib_node(app_id, lib_name)
    if src not in g or dst not in g:
        return []
    out = []
    for path in nx.all_simple_paths(g, src, dst):
        out.append([n[1] if n[0] == "app" else n[2] for n in path])
    return out


def depth_of(g, app_id, lib_name):
    """Shortest hop count from app to library (1 = direct). None if unreachable."""
    src, dst = app_node(app_id), lib_node(app_id, lib_name)
    try:
        return nx.shortest_path_length(g, src, dst)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None
