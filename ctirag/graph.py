"""Neo4j graph storage and evidence-only retrieval. Read queries are fixed, not LLM-generated."""
from __future__ import annotations
import os
from pathlib import Path
from neo4j import GraphDatabase
from dotenv import load_dotenv
from .schema import TYPES, ALLOWED
load_dotenv()

REL_TYPES = tuple(ALLOWED)


class Graph:
    def __init__(self):
        self.driver = GraphDatabase.driver(os.getenv("NEO4J_URI", "bolt://localhost:7687"),
                                           auth=(os.getenv("NEO4J_USERNAME", "neo4j"), os.getenv("NEO4J_PASSWORD", "")))
        self.db = os.getenv("NEO4J_DATABASE", "neo4j")

    def close(self):
        self.driver.close()

    def run(self, query, **params):
        with self.driver.session(database=self.db) as session:
            return [record.data() for record in session.run(query, **params)]

    def initialize(self, cypher_file: Path):
        for clause in cypher_file.read_text(encoding="utf-8").split(";"):
            if clause.strip() and not clause.lstrip().startswith("//"):
                self.run(clause.strip())
            elif "CREATE" in clause and clause.lstrip().startswith("//"):
                # Drop comments so CREATE statements cannot be silently skipped.
                cleaned = "\n".join(line for line in clause.splitlines() if not line.lstrip().startswith("//"))
                if cleaned.strip():
                    self.run(cleaned)

    def upsert_document(self, document: dict, chunk: dict):
        self.run("""MERGE (a:Advisory {id:$doc_id})
            SET a.title=$title,a.publication_date=$date,a.source_url=$url
            MERGE (c:TextChunk {id:$chunk_id})
            SET c.text=$text,c.title=$title,c.doc_id=$doc_id,c.source_url=$url,
                c.start_offset=$offset
            MERGE (c)-[:PART_OF]->(a)""",
            doc_id=document["doc_id"], title=document["title"], date=document.get("publication_date", ""),
            url=document["source_url"], chunk_id=chunk["id"], text=chunk["text"], offset=chunk["start_offset"])

    def upsert_entity(self, entity: dict, doc: dict, evidence: str = ""):
        typ = entity["entity_type"]
        if typ not in TYPES:
            raise ValueError(f"Invalid entity type: {typ}")
        # Entity label is generic for vector indexing; typed labels restricted by allowlist.
        self.run(f"""MERGE (n:Entity {{id:$id}})
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
            id=entity["id"], name=entity["name"], aliases=entity.get("aliases", []), typ=typ,
            attack_id=entity.get("attack_id", ""), cve_id=entity.get("cve_id", ""),
            description=entity.get("description", ""), confidence=entity.get("confidence_score", .7),
            doc_id=doc["doc_id"], url=doc["source_url"], evidence=evidence)

    def upsert_relation(self, relation: dict):
        predicate = relation["predicate"]
        if predicate not in REL_TYPES:
            raise ValueError("Disallowed relationship type")
        if not relation.get("evidence_text") or not relation.get("source_doc_id"):
            raise ValueError("Relation requires evidence_text and source_doc_id")
        self.run(f"""MATCH (a:Entity {{id:$src}}),(b:Entity {{id:$dst}})
            MERGE (a)-[r:`{predicate}` {{source_doc_id:$doc,chunk_id:$chunk}}]->(b)
            SET r.evidence_text=$evidence,r.source_url=$url,r.confidence_score=$confidence,
                r.source_kind=$source_kind""",
            src=relation["source_id"], dst=relation["target_id"], doc=relation["source_doc_id"],
            chunk=relation.get("chunk_id", ""), evidence=relation["evidence_text"],
            url=relation.get("source_url", ""), confidence=relation.get("confidence_score", .7),
            source_kind=relation.get("source_kind", "CISA_EXTRACTED"))

    def vector_search(self, index: str, query: list[float], k: int) -> list[dict]:
        if index not in {"chunk_embedding_index", "entity_text_embedding_index", "entity_embedding_index"}:
            raise ValueError("Unknown vector index")
        return self.run("""CALL db.index.vector.queryNodes($index,$limit,$embedding)
            YIELD node, score RETURN node.id AS id, node.name AS name,
            node.text AS text,node.doc_id AS doc_id,node.source_url AS source_url,
            node.entity_type AS entity_type,score ORDER BY score DESC""",
            index=index, limit=k, embedding=query)

    def all_entities(self, limit=5000):
        return self.run("""MATCH (n:Entity) RETURN n.id AS id,n.name AS name,
            n.aliases AS aliases,n.attack_id AS attack_id,n.cve_id AS cve_id,
            n.entity_type AS entity_type LIMIT $limit""", limit=limit)

    def neighborhood_paths(self, seed_ids: list[str], max_paths: int = 60) -> list[dict]:
        # Keep traversal explainable. Mitigation and Target nodes may be endpoints,
        # but they are not allowed as intermediate bridges to unrelated entities.
        return self.run("""MATCH p=(start:Entity)-[:USES|IMPLEMENTS|EXPLOITS|TARGETS|MITIGATED_BY|ATTRIBUTED_TO*1..3]-(finish:Entity)
          WHERE start.id IN $seeds AND ALL(r IN relationships(p)
            WHERE r.evidence_text IS NOT NULL AND r.source_doc_id IS NOT NULL)
            AND NONE(n IN nodes(p)[1..-1] WHERE n:Mitigation OR n:Target)
          WITH p, start, finish
          ORDER BY length(p) ASC
          RETURN [n IN nodes(p) | {id:n.id,name:n.name,type:n.entity_type}] AS nodes,
                 [r IN relationships(p) | {type:type(r),source_id:startNode(r).id,target_id:endNode(r).id,source_doc_id:r.source_doc_id,
                     source_url:r.source_url,evidence_text:r.evidence_text,
                     confidence_score:r.confidence_score}] AS edges
          LIMIT $limit""", seeds=seed_ids[:10], limit=max_paths)

    def embedding_data(self):
        nodes = self.run("MATCH (n:Entity) RETURN n.id AS id,n.name AS name,n.entity_type AS typ,n.description AS description")
        edges = self.run("""MATCH (a:Entity)-[r:USES|IMPLEMENTS|EXPLOITS|TARGETS|MITIGATED_BY|ATTRIBUTED_TO]->(b:Entity)
            RETURN a.id AS src,b.id AS dst""")
        return nodes, edges

    def store_vectors(self, label: str, rows: list[dict], field: str, batch_size=100):
        if label not in {"Entity", "TextChunk"} or field not in {"embedding", "text_embedding", "graph_embedding"}:
            raise ValueError("Invalid vector property")
        for i in range(0, len(rows), batch_size):
            batch = rows[i:i + batch_size]
            self.run(f"""UNWIND $rows AS row MATCH (n:`{label}` {{id:row.id}})
                SET n.`{field}`=row.embedding""", rows=batch)

    def text_chunks(self):
        return self.run("MATCH (c:TextChunk) RETURN c.id AS id,c.text AS text")

    def stats(self):
        return {"nodes": self.run("MATCH (n) RETURN count(n) AS n")[0]["n"],
                "relationships": self.run("MATCH ()-[r]->() RETURN count(r) AS n")[0]["n"],
                "advisories": self.run("MATCH (n:Advisory) RETURN count(n) AS n")[0]["n"],
                "chunks": self.run("MATCH (n:TextChunk) RETURN count(n) AS n")[0]["n"],
                "domain_entities": self.run("MATCH (n:Entity) RETURN count(n) AS n")[0]["n"]}

    def upsert_structured_entity(self, entity: dict):
        typ = entity["entity_type"]
        if typ not in TYPES:
            raise ValueError(f"Unknown type: {typ}")
        self.run(f"""MERGE (n:Entity {{id:$id}})
            SET n:`{typ}`, n.name=$name,n.aliases=$aliases,n.entity_type=$typ,
            n.attack_id=$attack_id,n.cve_id=$cve_id,n.description=$description,
            n.verified_source='MITRE ATT&CK STIX 2.1'""",
            id=entity["id"], name=entity["name"], aliases=entity.get("aliases", []),
            typ=typ, attack_id=entity.get("attack_id", ""),
            cve_id=entity.get("cve_id", ""), description=entity.get("description", ""))
