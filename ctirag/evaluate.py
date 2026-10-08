"""Triple precision/recall/F1, repeatable QA harness, human review, optional local judge."""
from __future__ import annotations
import csv
import json
import re
from pathlib import Path
from .llm import json_chat


def triple_key(t: dict) -> tuple[str, str, str]:
    return (str(t.get("source_id", "")).strip().upper(),
            str(t.get("predicate", "")).strip().upper(),
            str(t.get("target_id", "")).strip().upper())


def triple_metrics(predicted: list[dict], gold: list[dict]) -> dict:
    expected = {triple_key(x) for x in gold if x.get("verified_by_human") is True}
    actual = {triple_key(x) for x in predicted}
    if not expected:
        raise ValueError("No human-verified gold triples. Review gold_triples.json first.")
    tp = len(actual & expected)
    fp = len(actual - expected)
    fn = len(expected - actual)
    p = tp / (tp + fp) if (tp + fp) else 0
    r = tp / (tp + fn) if (tp + fn) else 0
    return {"true_positive": tp, "false_positive": fp, "false_negative": fn,
            "precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0,
            "verified_gold_triples": len(expected)}


def local_ragas_style_judge(question: str, answer: str, contexts: list[str], reference: str):
    """Transparent Ollama judge inspired by RAGAS; NOT the official ragas package."""
    rubric = """Act as an independent evaluator. Return ONLY JSON with keys:
faithfulness (0.0-1.0), answer_relevance (0.0-1.0), context_recall (0.0-1.0), notes.
Faithfulness: proportion of factual answer claims supported by context.
Answer relevance: how directly the answer addresses the question.
Context recall: whether context contains facts needed for the gold reference.
Never reward a fabricated citation. If reference is unavailable set context_recall null.
Do not use outside knowledge. Cite evidence in notes."""
    result = json_chat(rubric, json.dumps({"question": question, "answer": answer,
                                          "contexts": contexts[:12], "reference": reference})[:30000])
    for key in ("faithfulness", "answer_relevance", "context_recall"):
        v = result.get(key)
        if v is not None and not isinstance(v, (int, float)):
            raise ValueError(f"Judge returned invalid {key}")
        if isinstance(v, (int, float)) and not 0 <= v <= 1:
            raise ValueError(f"Judge returned out-of-range {key}")
    return result


def evaluate_qa(qa, queries_path: Path, out_dir: Path, local_judge: bool = False) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    questions = json.loads(queries_path.read_text(encoding="utf-8"))
    eligible = [q for q in questions if q.get("verified_by_human") is True and q.get("gold_answer")]
    if not eligible:
        raise ValueError("No verified benchmark questions. Complete eval_queries.json before formal evaluation.")

    logs = []
    human_rows = []
    failures = []

    partial_path = out_dir / "qa_results.partial.json"

    for q in eligible:
        for mode in ("text", "hybrid"):
            try:
                result = qa.ask(q["question"], mode)
                expected_ids = set(q.get("expected_doc_ids", []))
                expected_entities = set(q.get("expected_entity_ids", []))
                actual_ids = set(result["retrieved_doc_ids"])
                actual_entities = set(result["retrieved_entity_ids"])
                result["question_id"] = q["id"]
                result["gold_answer"] = q["gold_answer"]
                result["context_recall_proxy"] = (
                    len(expected_ids & actual_ids) / len(expected_ids)
                    if expected_ids else None
                )
                result["required_path_entity_hit"] = (
                    int(expected_entities <= actual_entities)
                    if expected_entities and mode == "hybrid" else None
                )
                if local_judge:
                    result["local_judge_not_official_ragas"] = local_ragas_style_judge(
                        q["question"], result["answer"], result["contexts"], q["gold_answer"]
                    )
                logs.append(result)
                human_rows.append({
                    "question_id": q["id"],
                    "mode": mode,
                    "question": q["question"],
                    "answer": result["answer"],
                    "gold_answer": q["gold_answer"],
                    "factuality_1_to_5": "",
                    "completeness_1_to_5": "",
                    "coherence_1_to_5": "",
                    "reviewer_notes": ""
                })
                print(f"[OK] {q['id']} {mode}")
            except Exception as exc:
                failure = {
                    "question_id": q["id"],
                    "mode": mode,
                    "question": q["question"],
                    "error": f"{type(exc).__name__}: {exc}",
                }
                failures.append(failure)
                print(f"[SKIP] {q['id']} {mode}: {failure['error']}")

            partial_path.write_text(
                json.dumps({"results": logs, "failures": failures}, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )

    (out_dir / "qa_results.json").write_text(
        json.dumps(logs, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (out_dir / "qa_failures.json").write_text(
        json.dumps(failures, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    if human_rows:
        with (out_dir / "human_review.csv").open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=list(human_rows[0]))
            writer.writeheader()
            writer.writerows(human_rows)

    avg_retrieval = (
        round(sum(x["retrieval_time_ms"] for x in logs) / len(logs), 1)
        if logs else None
    )
    avg_generation = (
        round(sum(x["generation_time_ms"] for x in logs) / len(logs), 1)
        if logs else None
    )

    summary = {
        "verified_questions": len(eligible),
        "planned_system_runs": len(eligible) * 2,
        "successful_runs": len(logs),
        "failed_runs": len(failures),
        "average_retrieval_ms_successful_runs": avg_retrieval,
        "average_generation_ms_successful_runs": avg_generation,
        "human_review_template": str(out_dir / "human_review.csv"),
        "evaluation_results": str(out_dir / "qa_results.json"),
        "evaluation_failures": str(out_dir / "qa_failures.json"),
        "partial_checkpoint": str(partial_path),
    }
    (out_dir / "qa_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return summary

def summarize_human_scores(path: Path) -> dict:
    """Aggregate completed 1-5 human rubric ratings; never fabricate missing scores."""
    rows = []
    with path.open(newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            scores = {}
            for field in ("factuality_1_to_5", "completeness_1_to_5", "coherence_1_to_5"):
                try:
                    score = int(row[field])
                except (ValueError, TypeError) as exc:
                    raise ValueError(f"Missing/noninteger human score: {row.get('question_id')}, {row.get('mode')}, {field}") from exc
                if score < 1 or score > 5:
                    raise ValueError(f"Score must be 1-5: {row.get('question_id')}, {field}")
                scores[field] = score
            rows.append({**row, **scores})
    if not rows:
        raise ValueError("Human review CSV is empty")
    modes = sorted(set(r["mode"] for r in rows))
    report = {"rated_answers": len(rows), "distinct_questions": len(set(r["question_id"] for r in rows)),
              "modes": {}}
    for mode in modes:
        x = [r for r in rows if r["mode"] == mode]
        report["modes"][mode] = {"n": len(x)}
        for k in ("factuality_1_to_5", "completeness_1_to_5", "coherence_1_to_5"):
            report["modes"][mode]["mean_" + k] = round(sum(r[k] for r in x) / len(x), 3)
    return report
