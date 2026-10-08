from pathlib import Path
import re
import shutil

root = Path.cwd()

# 1) Cap Ollama answer length during evaluation.
llm = root / "ctirag" / "llm.py"
if not llm.exists():
    raise SystemExit("Run this from the project root (same folder as run.py).")
bak = llm.with_suffix(llm.suffix + ".bak_before_deadline_eval")
if not bak.exists():
    shutil.copy2(llm, bak)

s = llm.read_text(encoding="utf-8")
old = '"options": {"temperature": 0},'
new = '"options": {"temperature": 0, "num_predict": int(os.getenv("OLLAMA_NUM_PREDICT", "256"))},'
if old in s:
    s = s.replace(old, new, 1)
elif "OLLAMA_NUM_PREDICT" not in s:
    raise SystemExit("Could not patch ctirag/llm.py automatically.")
llm.write_text(s, encoding="utf-8")

# 2) Keep open-ended QA prompts bounded so one huge graph context cannot stall Ollama.
qa = root / "ctirag" / "qa.py"
bak = qa.with_suffix(qa.suffix + ".bak_before_deadline_eval")
if not bak.exists():
    shutil.copy2(qa, bak)

s = qa.read_text(encoding="utf-8")
if "prompt[:20000]" not in s:
    if "answer = chat(SYSTEM, prompt)" not in s:
        raise SystemExit("Could not find QA chat call in ctirag/qa.py.")
    s = s.replace("answer = chat(SYSTEM, prompt)", "answer = chat(SYSTEM, prompt[:20000])")
qa.write_text(s, encoding="utf-8")

# 3) Make qa-eval checkpoint after every run and continue if one question times out.
ev = root / "ctirag" / "evaluate.py"
bak = ev.with_suffix(ev.suffix + ".bak_before_deadline_eval")
if not bak.exists():
    shutil.copy2(ev, bak)

s = ev.read_text(encoding="utf-8")
start = s.index("def evaluate_qa(")
end = s.index("\ndef summarize_human_scores", start)

new_func = '''def evaluate_qa(qa, queries_path: Path, out_dir: Path, local_judge: bool = False) -> dict:
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
'''

s = s[:start] + new_func + s[end:]
ev.write_text(s, encoding="utf-8")

print("Deadline evaluation fix installed.")
print("Changes:")
print("  - caps Ollama responses with OLLAMA_NUM_PREDICT (default 256)")
print("  - caps open-ended QA prompt passed to Ollama at 20,000 characters")
print("  - checkpoints every evaluation run")
print("  - continues if one question times out")
print("Backups were created beside llm.py, qa.py, and evaluate.py.")
