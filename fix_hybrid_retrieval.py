from pathlib import Path
import shutil

root = Path.cwd()
qa_path = root / "ctirag" / "qa.py"
graph_path = root / "ctirag" / "graph.py"

if not qa_path.exists() or not graph_path.exists():
    raise SystemExit("Run this from the CS6338_CyberThreat_GraphRAG project root.")

for p in (qa_path, graph_path):
    backup = p.with_suffix(p.suffix + ".bak_before_retrieval_fix")
    if not backup.exists():
        shutil.copy2(p, backup)

qa = qa_path.read_text(encoding="utf-8")
old_call = '                paths = self.graph.neighborhood_paths(seeds, 60)\n'
new_call = '                paths = self.graph.neighborhood_paths(seeds, 200)\n'
if old_call in qa:
    qa = qa.replace(old_call, new_call, 1)
elif new_call not in qa:
    raise SystemExit("Could not find the expected neighborhood_paths call in ctirag/qa.py")

old_block = '''        paths = paths[:60]\n        node_count = len({n["id"] for p in paths for n in p["nodes"]})\n        selected, seen_nodes, seen_edges = [], set(), set()\n        for p in paths:\n            nodeids = {n["id"] for n in p["nodes"]}\n            edgekeys = {(e.get("source_id"), e["type"], e.get("target_id"), e["source_doc_id"])\n                        for e in p["edges"]}\n            if len(seen_nodes | nodeids) <= 40 and len(seen_edges | edgekeys) <= 60:\n                selected.append(p)\n                seen_nodes |= nodeids\n                seen_edges |= edgekeys\n        paths = selected\n'''
new_block = '''        # Rank graph paths by what the question actually asks for.\n        # For example, a query asking for techniques AND mitigations should prefer\n        # ThreatGroup -> Technique -> Mitigation paths over longer side branches.\n        q_lower = question.casefold()\n        wants_mitigation = "mitigat" in q_lower\n        wants_technique = "technique" in q_lower or "ttp" in q_lower\n\n        def path_rank(p):\n            types = {n.get("type") for n in p.get("nodes", [])}\n            coverage = int(wants_mitigation and "Mitigation" in types) + int(wants_technique and "Technique" in types)\n            return (-coverage, len(p.get("edges", [])))\n\n        paths = sorted(paths, key=path_rank)[:120]\n        selected, seen_nodes, seen_edges = [], set(), set()\n        for p in paths:\n            nodeids = {n["id"] for n in p["nodes"]}\n            # Treat repeated evidence for the same semantic edge as one retrieval edge.\n            edgekeys = {(e.get("source_id"), e["type"], e.get("target_id")) for e in p["edges"]}\n            if edgekeys and edgekeys.issubset(seen_edges):\n                continue\n            if len(seen_nodes | nodeids) <= 40 and len(seen_edges | edgekeys) <= 60:\n                selected.append(p)\n                seen_nodes |= nodeids\n                seen_edges |= edgekeys\n        paths = selected\n'''
if old_block in qa:
    qa = qa.replace(old_block, new_block, 1)
elif new_block not in qa:
    raise SystemExit("Could not find the expected path-selection block in ctirag/qa.py")

qa_path.write_text(qa, encoding="utf-8")

graph = graph_path.read_text(encoding="utf-8")
start = graph.index("    def neighborhood_paths(")
end = graph.index("    def embedding_data(", start)
new_func = '''    def neighborhood_paths(self, seed_ids: list[str], max_paths: int = 60) -> list[dict]:\n        # Keep traversal explainable. Mitigation and Target nodes may be endpoints,\n        # but they are not allowed as intermediate bridges to unrelated entities.\n        return self.run(\"\"\"MATCH p=(start:Entity)-[:USES|IMPLEMENTS|EXPLOITS|TARGETS|MITIGATED_BY|ATTRIBUTED_TO*1..3]-(finish:Entity)\n          WHERE start.id IN $seeds AND ALL(r IN relationships(p)\n            WHERE r.evidence_text IS NOT NULL AND r.source_doc_id IS NOT NULL)\n            AND NONE(n IN nodes(p)[1..-1] WHERE n:Mitigation OR n:Target)\n          WITH p, start, finish\n          ORDER BY length(p) ASC\n          RETURN [n IN nodes(p) | {id:n.id,name:n.name,type:n.entity_type}] AS nodes,\n                 [r IN relationships(p) | {type:type(r),source_id:startNode(r).id,target_id:endNode(r).id,source_doc_id:r.source_doc_id,\n                     source_url:r.source_url,evidence_text:r.evidence_text,\n                     confidence_score:r.confidence_score}] AS edges\n          LIMIT $limit\"\"\", seeds=seed_ids[:10], limit=max_paths)\n\n'''
graph = graph[:start] + new_func + graph[end:]
graph_path.write_text(graph, encoding="utf-8")

print("Hybrid retrieval fix installed.")
print("Backups created beside qa.py and graph.py.")
print("Next: python -m unittest discover -s tests -v")
