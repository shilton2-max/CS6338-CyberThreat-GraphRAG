from pathlib import Path
import shutil

root = Path.cwd()
graph_path = root / "ctirag" / "graph.py"

if not graph_path.exists():
    raise SystemExit("Run this from the CS6338_CyberThreat_GraphRAG project root.")

backup = graph_path.with_suffix(graph_path.suffix + ".bak_before_entity_merge_fix")
if not backup.exists():
    shutil.copy2(graph_path, backup)

text = graph_path.read_text(encoding="utf-8")

old = '''        self.run(f"""MERGE (n:Entity:`{typ}` {{id:$id}})
            SET n.name=$name,n.aliases=$aliases,n.entity_type=$typ,
                n.attack_id=$attack_id,n.cve_id=$cve_id,
                n.description=$description,n.confidence_score=$confidence
            WITH n MATCH (a:Advisory {{id:$doc_id}})
            MERGE (n)-[r:DESCRIBED_IN {{source_doc_id:$doc_id}}]->(a)
            SET r.source_url=$url,r.evidence_text=$evidence,r.confidence_score=$confidence""",
'''

new = '''        self.run(f"""MERGE (n:Entity {{id:$id}})
            ON CREATE SET n:`{typ}`, n.entity_type=$typ
            SET n.name=CASE
                    WHEN n.verified_source IS NOT NULL AND n.name IS NOT NULL THEN n.name
                    ELSE $name END,
                n.aliases=CASE
                    WHEN n.verified_source IS NOT NULL AND n.aliases IS NOT NULL THEN n.aliases
                    ELSE $aliases END,
                n.entity_type=CASE
                    WHEN n.verified_source IS NOT NULL AND n.entity_type IS NOT NULL THEN n.entity_type
                    ELSE $typ END,
                n.attack_id=CASE
                    WHEN n.attack_id IS NOT NULL AND n.attack_id <> '' THEN n.attack_id
                    ELSE $attack_id END,
                n.cve_id=CASE
                    WHEN n.cve_id IS NOT NULL AND n.cve_id <> '' THEN n.cve_id
                    ELSE $cve_id END,
                n.description=CASE
                    WHEN n.verified_source IS NOT NULL AND n.description IS NOT NULL AND n.description <> '' THEN n.description
                    ELSE $description END,
                n.confidence_score=coalesce(n.confidence_score,$confidence)
            WITH n MATCH (a:Advisory {{id:$doc_id}})
            MERGE (n)-[r:DESCRIBED_IN {{source_doc_id:$doc_id}}]->(a)
            SET r.source_url=$url,r.evidence_text=$evidence,r.confidence_score=$confidence""",
'''

if old in text:
    text = text.replace(old, new, 1)
elif 'MERGE (n:Entity {id:$id})' in text and 'ON CREATE SET n:`{typ}`' in text:
    print("Entity merge fix already appears to be installed.")
    raise SystemExit(0)
else:
    raise SystemExit("Could not find the expected upsert_entity block in ctirag/graph.py")

old2 = '''        self.run(f"""MERGE (n:Entity:`{typ}` {{id:$id}})
            SET n.name=$name,n.aliases=$aliases,n.entity_type=$typ,
            n.attack_id=$attack_id,n.cve_id=$cve_id,n.description=$description,
            n.verified_source='MITRE ATT&CK STIX 2.1'""",
'''

new2 = '''        self.run(f"""MERGE (n:Entity {{id:$id}})
            SET n:`{typ}`, n.name=$name,n.aliases=$aliases,n.entity_type=$typ,
            n.attack_id=$attack_id,n.cve_id=$cve_id,n.description=$description,
            n.verified_source='MITRE ATT&CK STIX 2.1'""",
'''

if old2 in text:
    text = text.replace(old2, new2, 1)

graph_path.write_text(text, encoding="utf-8")

print("Neo4j entity merge fix installed.")
print("Existing MITRE entities will now be matched by unique Entity.id before labels are considered.")
print("Backup created beside graph.py.")
print("Next: python -m unittest discover -s tests -v")