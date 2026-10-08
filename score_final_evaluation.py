from pathlib import Path
import json, csv, math, re, statistics
from collections import defaultdict

ROOT = Path.cwd()
results_path = ROOT / "outputs" / "qa_results.json"
gold_path = ROOT / "eval" / "eval_queries_deadline.json"
out_json = ROOT / "outputs" / "final_metrics.json"
out_csv = ROOT / "outputs" / "final_metrics_by_question.csv"

if not results_path.exists():
    raise SystemExit("Missing outputs/qa_results.json")
if not gold_path.exists():
    raise SystemExit("Missing eval/eval_queries_deadline.json")

results = json.loads(results_path.read_text(encoding="utf-8"))
gold = json.loads(gold_path.read_text(encoding="utf-8"))
gold_map = {q["id"]: q for q in gold}

def tokens(s):
    return re.findall(r"[a-z0-9]+(?:\.[0-9]+)?", (s or "").lower())

def lexical_prf(answer, reference):
    a = tokens(answer)
    g = tokens(reference)
    if not a or not g:
        return 0.0, 0.0, 0.0
    from collections import Counter
    ca, cg = Counter(a), Counter(g)
    overlap = sum((ca & cg).values())
    p = overlap / len(a)
    r = overlap / len(g)
    f1 = 0.0 if p + r == 0 else 2 * p * r / (p + r)
    return p, r, f1

# Semantic metrics using the same family already used by the project.
try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    def emb(texts):
        return model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
    def cos(a, b):
        return float(np.dot(a, b))
    semantic_available = True
except Exception as e:
    print("Semantic model unavailable; semantic fields will be null:", e)
    semantic_available = False

rows = []

for r in results:
    qid = r.get("question_id")
    q = gold_map.get(qid, {})
    question = r.get("question", q.get("question", ""))
    answer = r.get("answer", "")
    gold_answer = r.get("gold_answer", q.get("gold_answer", ""))
    mode = r.get("mode", "")

    lp, lr, lf1 = lexical_prf(answer, gold_answer)

    expected_docs = set(q.get("expected_doc_ids", []))
    actual_docs = set(r.get("retrieved_doc_ids", []))
    doc_precision = (len(expected_docs & actual_docs) / len(actual_docs)) if actual_docs else (1.0 if not expected_docs else 0.0)
    doc_recall = (len(expected_docs & actual_docs) / len(expected_docs)) if expected_docs else None

    expected_entities = set(q.get("expected_entity_ids", []))
    actual_entities = set(r.get("retrieved_entity_ids", []))
    entity_precision = (len(expected_entities & actual_entities) / len(actual_entities)) if actual_entities and expected_entities else None
    entity_recall = (len(expected_entities & actual_entities) / len(expected_entities)) if expected_entities else None

    answer_similarity = None
    answer_relevance = None
    faithfulness_proxy = None

    if semantic_available:
        qv, av, gv = emb([question, answer, gold_answer])
        answer_similarity = cos(av, gv)
        answer_relevance = cos(av, qv)

        contexts = [c for c in r.get("contexts", []) if isinstance(c, str) and c.strip()]
        # Average best context support per answer sentence.
        sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", answer) if len(s.strip()) >= 8]
        if contexts and sentences:
            # limit very large raw text while preserving retrieved evidence
            contexts = [c[:12000] for c in contexts[:8]]
            sv = emb(sentences)
            cv = emb(contexts)
            scores = []
            for svec in sv:
                scores.append(max(float(svec @ cvec) for cvec in cv))
            faithfulness_proxy = sum(scores) / len(scores)

    rows.append({
        "question_id": qid,
        "mode": mode,
        "lexical_precision": lp,
        "lexical_recall": lr,
        "lexical_f1": lf1,
        "answer_similarity": answer_similarity,
        "answer_relevance": answer_relevance,
        "faithfulness_proxy": faithfulness_proxy,
        "document_precision": doc_precision,
        "document_recall": doc_recall,
        "entity_precision": entity_precision,
        "entity_recall": entity_recall,
        "required_path_entity_hit": r.get("required_path_entity_hit"),
        "retrieval_time_ms": r.get("retrieval_time_ms"),
        "generation_time_ms": r.get("generation_time_ms"),
    })

def avg(vals):
    vals = [v for v in vals if isinstance(v, (int, float)) and not isinstance(v, bool)]
    return (sum(vals) / len(vals)) if vals else None

summary = {}
for mode in ("text", "hybrid"):
    mr = [x for x in rows if x["mode"] == mode]
    summary[mode] = {
        "runs": len(mr),
        "lexical_precision": avg([x["lexical_precision"] for x in mr]),
        "lexical_recall": avg([x["lexical_recall"] for x in mr]),
        "lexical_f1": avg([x["lexical_f1"] for x in mr]),
        "answer_similarity": avg([x["answer_similarity"] for x in mr]),
        "answer_relevance": avg([x["answer_relevance"] for x in mr]),
        "faithfulness_proxy": avg([x["faithfulness_proxy"] for x in mr]),
        "document_precision": avg([x["document_precision"] for x in mr]),
        "document_recall": avg([x["document_recall"] for x in mr]),
        "entity_precision": avg([x["entity_precision"] for x in mr]),
        "entity_recall": avg([x["entity_recall"] for x in mr]),
        "path_hit_rate": avg([x["required_path_entity_hit"] for x in mr]),
        "average_retrieval_ms": avg([x["retrieval_time_ms"] for x in mr]),
        "average_generation_ms": avg([x["generation_time_ms"] for x in mr]),
    }

comparison = {}
for metric in (
    "lexical_precision","lexical_recall","lexical_f1","answer_similarity",
    "answer_relevance","faithfulness_proxy","document_precision","document_recall",
    "entity_precision","entity_recall","path_hit_rate"
):
    t = summary["text"].get(metric)
    h = summary["hybrid"].get(metric)
    comparison[metric + "_hybrid_minus_text"] = (h - t) if isinstance(t,(int,float)) and isinstance(h,(int,float)) else None

payload = {
    "benchmark": {
        "human_verified_questions": sum(1 for q in gold if q.get("verified_by_human") is True),
        "system_runs": len(results),
        "notes": [
            "Lexical precision/recall/F1 compare generated answer tokens with the human-verified gold answer.",
            "Answer similarity and answer relevance use all-MiniLM-L6-v2 cosine similarity.",
            "Faithfulness proxy is the average best semantic similarity between each answer sentence and retrieved contexts; it is not official RAGAS entailment.",
            "Document/entity precision and recall compare retrieved IDs with expected IDs in the human-verified benchmark.",
            "Path hit rate is available for hybrid questions with expected graph entities."
        ]
    },
    "summary_by_mode": summary,
    "hybrid_minus_text": comparison
}

out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

with out_csv.open("w", newline="", encoding="utf-8-sig") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)

def fmt(v):
    if v is None:
        return "n/a"
    if isinstance(v, float):
        return f"{v:.4f}"
    return str(v)

print("\nFINAL AUTOMATED EVALUATION")
print("=" * 74)
print(f"{'Metric':30} {'Text-RAG':>14} {'GraphRAG':>14}")
print("-" * 74)
labels = [
    ("Lexical precision","lexical_precision"),
    ("Lexical recall","lexical_recall"),
    ("Lexical F1","lexical_f1"),
    ("Answer similarity","answer_similarity"),
    ("Answer relevance","answer_relevance"),
    ("Faithfulness proxy","faithfulness_proxy"),
    ("Document precision","document_precision"),
    ("Document recall","document_recall"),
    ("Entity precision","entity_precision"),
    ("Entity recall","entity_recall"),
    ("Path hit rate","path_hit_rate"),
    ("Avg retrieval ms","average_retrieval_ms"),
    ("Avg generation ms","average_generation_ms"),
]
for label, key in labels:
    print(f"{label:30} {fmt(summary['text'].get(key)):>14} {fmt(summary['hybrid'].get(key)):>14}")

print("\nSaved:")
print(out_json)
print(out_csv)
print("\nIMPORTANT: 'faithfulness_proxy' is a local semantic proxy, not an official RAGAS score.")
