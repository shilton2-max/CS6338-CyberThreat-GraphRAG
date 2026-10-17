"""Single-entry Windows-friendly CLI for the CS-6338 GraphRAG project."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()
ROOT = Path(__file__).resolve().parent


def output(data):
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def get_graph():
    from ctirag.graph import Graph
    g = Graph()
    g.driver.verify_connectivity()
    return g


def cli():
    parser = argparse.ArgumentParser(description="Cyber Threat Intelligence GraphRAG | CS-6338")
    sp = parser.add_subparsers(dest="command", required=True)
    d = sp.add_parser("download", help="Collect CISA advisories from real CISA pages")
    d.add_argument("--limit", type=int, default=100)
    d.add_argument("--urls", type=Path, help="Optional file containing one official CISA advisory URL per line")
    m = sp.add_parser("import-local", help="Import locally saved real advisory texts using a CSV manifest")
    m.add_argument("--manifest", type=Path, default=ROOT / "data" / "manual_manifest.csv")
    e = sp.add_parser("extract", help="LLM extract structured entities/relations with provenance")
    e.add_argument("--max-chunks", type=int, default=0, help="Run a small experiment first, e.g. 5")
    sp.add_parser("init-db", help="Create uniqueness constraints, indexes and 384d/64d vector indexes")
    sp.add_parser("load", help="Load advisory chunks and verified extraction into Neo4j")
    a = sp.add_parser("import-attack", help="Import verified MITRE STIX 2.1 subgraph")
    a.add_argument("--focus", nargs="+", default=["G0007"], help="Official ATT&CK IDs, e.g. G0007")
    a.add_argument("--max-relations", type=int, default=300)
    a.add_argument("--stix", type=Path, default=ROOT / "data" / "enterprise-attack.json")
    emb = sp.add_parser("embed", help="384d advisory/entity text embeddings and 64d Node2Vec")
    emb.add_argument("--skip-node2vec", action="store_true")
    q = sp.add_parser("ask", help="Ask a question in hybrid or text-only mode")
    q.add_argument("question", nargs="+", help="Question in ordinary English")
    q.add_argument("--mode", choices=["hybrid", "text"], default="hybrid")
    sp.add_parser("stats", help="Counts of actual loaded records")
    pg = sp.add_parser("pagerank", help="Run PageRank on the live Neo4j Entity graph (GDS preferred)")
    pg.add_argument("--engine", choices=["auto", "gds", "networkx"], default="auto")
    pg.add_argument("--top", type=int, default=15)
    pgb = sp.add_parser("pagerank-benchmark", help="Run reproducible PageRank on the verified QA benchmark subgraph")
    pgb.add_argument("--queries", type=Path, default=ROOT / "eval" / "eval_queries.json")
    pgb.add_argument("--top", type=int, default=15)
    t = sp.add_parser("triple-eval", help="Evaluate predicted relations against HUMAN-verified gold triples")
    t.add_argument("--gold", type=Path, default=ROOT / "eval" / "gold_triples.json")
    sp.add_parser("annotation-candidates", help="Create up to 60 UNVERIFIED relation-review items")
    v = sp.add_parser("qa-eval", help="Text baseline vs GraphRAG evaluation and human scoring CSV")
    v.add_argument("--gold", type=Path, default=ROOT / "eval" / "eval_queries.json")
    v.add_argument("--local-judge", action="store_true", help="Run Ollama RAGAS-style judge (NOT official RAGAS)")
    hu = sp.add_parser("human-summary", help="Aggregate reviewed 1-to-5 scores")
    hu.add_argument("--csv", type=Path, default=ROOT / "outputs" / "human_review.csv")
    r = sp.add_parser("ragas", help="Optional official RAGAS 0.2.x evaluation")
    r.add_argument("--input", type=Path, default=ROOT / "outputs" / "qa_results.json")
    args = parser.parse_args()
    advisory_path = ROOT / "data" / "advisories"
    extraction_file = ROOT / "outputs" / "extracted.jsonl"
    cache = ROOT / "data" / "cache"
    if args.command == "download":
        from ctirag.source import download_advisories
        output(download_advisories(advisory_path, args.limit, args.urls))
    elif args.command == "import-local":
        from ctirag.import_local import import_manifest
        output(import_manifest(args.manifest, advisory_path))
    elif args.command == "extract":
        from ctirag.extract import extract_corpus
        output(extract_corpus(advisory_path, extraction_file, cache / "extraction", args.max_chunks))
    elif args.command == "ragas":
        from ctirag.official_ragas import run_ragas
        output({"official_ragas_file": run_ragas(args.input, ROOT / "outputs" / "ragas_results.csv")})
    elif args.command == "human-summary":
        from ctirag.evaluate import summarize_human_scores
        output(summarize_human_scores(args.csv))
    elif args.command == "annotation-candidates":
        from ctirag.annotations import make_gold_candidates
        output(make_gold_candidates(extraction_file, ROOT / "eval" / "candidate_gold_triples.json"))
    elif args.command == "pagerank-benchmark":
        from ctirag.analytics import pagerank_from_eval_queries, save_result
        result = pagerank_from_eval_queries(args.queries, args.top)
        save_result(result, ROOT / "outputs" / "pagerank_benchmark.json")
        output(result)
    elif args.command == "triple-eval":
        from ctirag.evaluate import triple_metrics
        if not extraction_file.exists():
            raise FileNotFoundError("First run extraction; outputs/extracted.jsonl missing")
        predictions = [rel for line in extraction_file.read_text(encoding="utf-8").splitlines()
                       for rel in json.loads(line)["relations"]]
        gold = json.loads(args.gold.read_text(encoding="utf-8"))
        output(triple_metrics(predictions, gold))
    else:
        g = get_graph()
        try:
            if args.command == "init-db":
                g.initialize(ROOT / "schema.cypher")
                output({"initialized": True, "note": "Vector indexes build asynchronously; run SHOW VECTOR INDEXES in Neo4j"})
            elif args.command == "load":
                from ctirag.source import load_advisories, chunk_document
                if not extraction_file.exists():
                    raise FileNotFoundError("First run: python run.py extract")
                docs = load_advisories(advisory_path)
                count = {"documents": len(docs), "chunks": 0, "relations": 0}
                for doc in docs:
                    for chunk in chunk_document(doc):
                        g.upsert_document(doc, chunk)
                        count["chunks"] += 1
                for line in extraction_file.read_text(encoding="utf-8").splitlines():
                    record = json.loads(line)
                    doc = record["document"]
                    for e in record["entities"]:
                        g.upsert_entity(e, doc, evidence=e.get("description", ""))
                    for rel in record["relations"]:
                        g.upsert_relation(rel)
                        count["relations"] += 1
                output(count)
            elif args.command == "import-attack":
                from ctirag.attack import import_attack
                output(import_attack(g, args.stix, {i.upper() for i in args.focus}, args.max_relations))
            elif args.command == "embed":
                from ctirag.embedding import embed_graph
                output(embed_graph(g, cache / "embeddings", not args.skip_node2vec))
            elif args.command == "stats":
                output(g.stats())
            elif args.command == "pagerank":
                from ctirag.analytics import run_pagerank, save_result
                result = run_pagerank(g, args.top, args.engine)
                save_result(result, ROOT / "outputs" / "pagerank_live.json")
                output(result)
            elif args.command in ("ask", "qa-eval"):
                from ctirag.qa import QA
                qa = QA(g, cache / "embeddings")
                if args.command == "ask":
                    output(qa.ask(" ".join(args.question), args.mode))
                else:
                    from ctirag.evaluate import evaluate_qa
                    output(evaluate_qa(qa, args.gold, ROOT / "outputs", args.local_judge))
        finally:
            g.close()


if __name__ == "__main__":
    cli()
