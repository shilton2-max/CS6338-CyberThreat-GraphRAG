"""Graph analytics for the CS-6338 cyber threat GraphRAG project.

Provides two PageRank execution paths:
1. Neo4j Graph Data Science (preferred when the GDS plugin is installed).
2. NetworkX fallback using the same evidence-backed Entity relationships.

A benchmark-only helper also runs PageRank over the verified QA subgraph so the
analytics pipeline can be tested without a live Neo4j service.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

import networkx as nx


BENCHMARK_NAMES = {
    "ATTACK:G0007": "APT28",
    "ATTACK:T1059.001": "PowerShell",
    "ATTACK:T1105": "Ingress Tool Transfer",
    "ATTACK:T1037.001": "Logon Script (Windows)",
    "ATTACK:T1550.002": "Pass the Hash",
    "ATTACK:T1498": "Network Denial of Service",
    "ATTACK:T1557.004": "Evil Twin",
    "ATTACK:T1596": "Search Open Technical Databases",
    "ATTACK:T1589.001": "Credentials",
    "ATTACK:T1059.003": "Windows Command Shell",
    "ATTACK:T1566.001": "Spearphishing Attachment",
    "ATTACK:T1598": "Phishing for Information",
    "ATTACK:T1588.002": "Tool",
    "ATTACK:M1026": "Privileged Account Management",
    "ATTACK:M1045": "Code Signing",
    "ATTACK:M1038": "Execution Prevention",
    "ATTACK:M1037": "Filter Network Traffic",
    "ATTACK:M1031": "Network Intrusion Prevention",
    "ATTACK:M1024": "Restrict Registry Permissions",
    "ATTACK:M1018": "User Account Management",
    "ATTACK:M1052": "User Account Control",
    "ATTACK:M1017": "User Training",
    "ATTACK:M1056": "Pre-compromise",
    "ATTACK:M1054": "Software Configuration",
    "ATTACK:M1049": "Antivirus/Antimalware",
    "ATTACK:M1021": "Restrict Web-Based Content",
}

RELATION_TYPES = (
    "USES",
    "IMPLEMENTS",
    "EXPLOITS",
    "TARGETS",
    "MITIGATED_BY",
    "ATTRIBUTED_TO",
)


def _rank_rows(
    edges: Iterable[tuple[str, str]],
    names: dict[str, str] | None = None,
    alpha: float = 0.85,
    top_n: int = 15,
) -> dict:
    """Run deterministic directed PageRank and return topology summary + top rows."""
    graph = nx.DiGraph()
    graph.add_edges_from(edges)
    if graph.number_of_nodes() == 0:
        return {
            "node_count": 0,
            "relationship_count": 0,
            "weakly_connected_components": 0,
            "density": 0.0,
            "average_total_degree": 0.0,
            "top_nodes": [],
        }

    scores = nx.pagerank(graph, alpha=alpha)
    names = names or {}
    rows = [
        {
            "id": node_id,
            "name": names.get(node_id, node_id),
            "score": round(float(score), 8),
            "in_degree": int(graph.in_degree(node_id)),
            "out_degree": int(graph.out_degree(node_id)),
        }
        for node_id, score in sorted(scores.items(), key=lambda x: (-x[1], x[0]))[:top_n]
    ]
    return {
        "node_count": graph.number_of_nodes(),
        "relationship_count": graph.number_of_edges(),
        "weakly_connected_components": nx.number_weakly_connected_components(graph),
        "density": round(float(nx.density(graph)), 8),
        "average_total_degree": round(
            sum(dict(graph.degree()).values()) / graph.number_of_nodes(), 4
        ),
        "top_nodes": rows,
    }


def _name_map_from_queries(queries: list[dict]) -> dict[str, str]:
    names: dict[str, str] = dict(BENCHMARK_NAMES)
    # Examples captured by this regex: PowerShell (T1059.001), User Training (M1017)
    pattern = re.compile(r"([A-Za-z][A-Za-z0-9 /:+\-']{1,80}?)\s*\(((?:G|T|M)\d{4}(?:\.\d{3})?)\)")
    for q in queries:
        text = f"{q.get('question', '')} {q.get('gold_answer', '')}"
        for label, attack_id in pattern.findall(text):
            label = label.strip(" .,:;-[]")
            # Prevent a long sentence fragment from becoming the node label.
            if len(label.split()) <= 8:
                names.setdefault("ATTACK:" + attack_id, label)
    return names


def pagerank_from_eval_queries(queries_path: Path, top_n: int = 15) -> dict:
    """Run PageRank on the benchmark's source-verified APT28 technique/mitigation paths.

    Q01-Q12 encode the benchmark graph as expected entity IDs:
      G0007 -> Technique -> one or more Mitigations.
    Q18-Q20 repeat selected paths and are automatically deduplicated.
    """
    queries = json.loads(queries_path.read_text(encoding="utf-8"))
    edges: set[tuple[str, str]] = set()

    for q in queries:
        ids = q.get("expected_entity_ids") or []
        if len(ids) < 2:
            continue
        group_ids = [x for x in ids if x.startswith("ATTACK:G")]
        technique_ids = [x for x in ids if x.startswith("ATTACK:T")]
        mitigation_ids = [x for x in ids if x.startswith("ATTACK:M")]
        if group_ids and technique_ids:
            group_id, technique_id = group_ids[0], technique_ids[0]
            edges.add((group_id, technique_id))
            for mitigation_id in mitigation_ids:
                edges.add((technique_id, mitigation_id))

    result = _rank_rows(edges, _name_map_from_queries(queries), top_n=top_n)
    result.update(
        {
            "engine": "networkx",
            "scope": "verified_qa_benchmark_subgraph",
            "algorithm": "PageRank",
            "damping_factor": 0.85,
            "source_file": str(queries_path),
            "note": (
                "This is a reproducible analytics sanity check over the benchmark graph. "
                "Use the live 'pagerank' command for the full Neo4j Entity graph."
            ),
        }
    )
    return result


def _networkx_live(graph, top_n: int) -> dict:
    rels = graph.run(
        """MATCH (a:Entity)-[r]->(b:Entity)
        WHERE type(r) IN $types
        RETURN a.id AS source,b.id AS target""",
        types=list(RELATION_TYPES),
    )
    entities = graph.all_entities(limit=100000)
    names = {row["id"]: row.get("name") or row["id"] for row in entities}
    result = _rank_rows(
        ((row["source"], row["target"]) for row in rels),
        names=names,
        top_n=top_n,
    )
    # Persist every graph node score, not only the displayed top-N list.
    pagerank_graph = nx.DiGraph()
    pagerank_graph.add_edges_from((row["source"], row["target"]) for row in rels)
    all_scores = nx.pagerank(pagerank_graph, alpha=0.85) if pagerank_graph.number_of_nodes() else {}
    rows = [{"id": node_id, "score": float(score)} for node_id, score in all_scores.items()]
    if rows:
        graph.run(
            """UNWIND $rows AS row MATCH (n:Entity {id:row.id})
            SET n.pagerank=row.score""",
            rows=rows,
        )
    result.update(
        {
            "engine": "networkx-live-fallback",
            "scope": "neo4j_entity_graph",
            "algorithm": "PageRank",
            "damping_factor": 0.85,
        }
    )
    return result


def _gds_live(graph, top_n: int) -> dict:
    version = graph.run("CALL gds.version() YIELD version RETURN version")[0]["version"]
    graph_name = "cti_entity_graph"

    exists_rows = graph.run("CALL gds.graph.exists($name) YIELD exists RETURN exists", name=graph_name)
    if exists_rows and exists_rows[0].get("exists"):
        graph.run("CALL gds.graph.drop($name, false) YIELD graphName RETURN graphName", name=graph_name)

    projected = graph.run(
        """CALL gds.graph.project($name,'Entity',$relationship_types)
        YIELD graphName,nodeCount,relationshipCount
        RETURN graphName,nodeCount,relationshipCount""",
        name=graph_name,
        relationship_types=list(RELATION_TYPES),
    )[0]

    write = graph.run(
        """CALL gds.pageRank.write($name, {
            writeProperty:'pagerank',
            dampingFactor:0.85,
            maxIterations:20
        })
        YIELD nodePropertiesWritten,ranIterations,didConverge
        RETURN nodePropertiesWritten,ranIterations,didConverge""",
        name=graph_name,
    )[0]

    rows = graph.run(
        """MATCH (n:Entity)
        WHERE n.pagerank IS NOT NULL
        RETURN n.id AS id,n.name AS name,n.entity_type AS entity_type,
               n.pagerank AS score
        ORDER BY score DESC LIMIT $limit""",
        limit=top_n,
    )
    result = {
        "engine": "neo4j-gds",
        "gds_version": version,
        "scope": "neo4j_entity_graph",
        "algorithm": "PageRank",
        "damping_factor": 0.85,
        "node_count": projected["nodeCount"],
        "relationship_count": projected["relationshipCount"],
        "node_properties_written": write["nodePropertiesWritten"],
        "iterations": write["ranIterations"],
        "converged": write["didConverge"],
        "top_nodes": rows,
    }
    graph.run("CALL gds.graph.drop($name, false) YIELD graphName RETURN graphName", name=graph_name)
    return result


def run_pagerank(graph, top_n: int = 15, engine: str = "auto") -> dict:
    """Run PageRank against the live graph.

    engine='auto' prefers Neo4j GDS and falls back to NetworkX if GDS is not
    installed. engine='gds' requires GDS. engine='networkx' always uses fallback.
    """
    if engine not in {"auto", "gds", "networkx"}:
        raise ValueError("engine must be one of: auto, gds, networkx")
    if engine == "networkx":
        return _networkx_live(graph, top_n)
    try:
        return _gds_live(graph, top_n)
    except Exception as exc:
        if engine == "gds":
            raise
        result = _networkx_live(graph, top_n)
        result["gds_fallback_reason"] = f"{type(exc).__name__}: {exc}"
        return result


def save_result(result: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
