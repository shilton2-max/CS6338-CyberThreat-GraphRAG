from pathlib import Path
import shutil

root = Path.cwd()
qa_path = root / "ctirag" / "qa.py"

if not qa_path.exists():
    raise SystemExit("Run this from the CS6338_CyberThreat_GraphRAG project root.")

backup = qa_path.with_suffix(qa_path.suffix + ".bak_before_deterministic_pairs")
if not backup.exists():
    shutil.copy2(qa_path, backup)

qa = qa_path.read_text(encoding="utf-8")

helper_marker = "\n\nclass QA:\n"
helper_code = r'''

def _format_attack_id(value: str | None) -> str:
    value = value or ""
    return value.replace("ATTACK:", "")


def _render_pair_answer(pair_records: list[dict], limit_techniques: int = 12) -> str:
    grouped = {}
    for r in pair_records:
        key = (r.get("technique_id"), r.get("technique_name"))
        if not key[0]:
            continue
        grouped.setdefault(key, [])
        mit = (r.get("mitigation_id"), r.get("mitigation_name"))
        if mit not in grouped[key]:
            grouped[key].append(mit)

    lines = []
    for (tech_id, tech_name), mitigations in grouped.items():
        parts = []
        for mit_id, mit_name in mitigations:
            if not mit_id:
                continue
            parts.append(f"{mit_name} ({_format_attack_id(mit_id)})")
        if not parts:
            continue
        lines.append(
            f"- {tech_name} ({_format_attack_id(tech_id)}) -> "
            + "; ".join(parts)
            + " [MITRE-STIX]"
        )
        if len(lines) >= limit_techniques:
            break

    if not lines:
        return "Not enough evidence in the indexed advisories and graph to answer that reliably."

    return (
        "Based on the retrieved MITRE ATT&CK graph evidence, these are the top "
        "technique-to-mitigation links found for the requested threat group:\\n\\n"
        + "\\n".join(lines)
        + "\\n\\nThese links come directly from ThreatGroup -[USES]-> Technique "
          "-[MITIGATED_BY]-> Mitigation graph paths."
    )
'''

if "_render_pair_answer(" not in qa:
    if helper_marker not in qa:
        raise SystemExit("Could not find insertion point in ctirag/qa.py")
    qa = qa.replace(helper_marker, helper_code + helper_marker, 1)

old_block = '''        if not text_evidence and not graph_evidence:
            answer, generation_ms = SYSTEM.split("say exactly:")[1].split("'")[1], 0.0
        else:
            start = time.perf_counter()
            pair_section = ""
            if mode == "hybrid" and pair_evidence:
                pair_section = "\\n\\nDIRECT TECHNIQUE-MITIGATION PAIRS:\\n" + "\\n---\\n".join(pair_evidence[:18])
            prompt = (f"QUESTION:\\n{question}\\n\\nTEXT EVIDENCE:\\n" + "\\n---\\n".join(text_evidence)
                      + pair_section
                      + "\\n\\nGRAPH EVIDENCE:\\n" + ("\\n---\\n".join(graph_evidence) if mode == "hybrid" else "Not available in text-only mode.")
                      + "\\n\\nANSWER strictly from provided evidence, with citations. "
                        "If DIRECT TECHNIQUE-MITIGATION PAIRS are present and the question asks for techniques and mitigations, "
                        "use those pairs as the primary structure of the answer.")
            answer = chat(SYSTEM, prompt)
            generation_ms = round((time.perf_counter() - start) * 1000, 1)
'''

new_block = '''        q_lower = question.casefold()
        pair_question = (
            mode == "hybrid"
            and bool(pair_records)
            and ("mitigat" in q_lower)
            and ("technique" in q_lower or "ttp" in q_lower)
        )

        if pair_question:
            # Structured graph question: render directly from verified graph pairs.
            # This avoids an 8B local LLM renaming techniques or separating a
            # mitigation from the technique it actually mitigates.
            answer = _render_pair_answer(pair_records)
            generation_ms = 0.0
        elif not text_evidence and not graph_evidence:
            answer, generation_ms = SYSTEM.split("say exactly:")[1].split("'")[1], 0.0
        else:
            start = time.perf_counter()
            pair_section = ""
            if mode == "hybrid" and pair_evidence:
                pair_section = "\\n\\nDIRECT TECHNIQUE-MITIGATION PAIRS:\\n" + "\\n---\\n".join(pair_evidence[:18])
            prompt = (f"QUESTION:\\n{question}\\n\\nTEXT EVIDENCE:\\n" + "\\n---\\n".join(text_evidence)
                      + pair_section
                      + "\\n\\nGRAPH EVIDENCE:\\n" + ("\\n---\\n".join(graph_evidence) if mode == "hybrid" else "Not available in text-only mode.")
                      + "\\n\\nANSWER strictly from provided evidence, with citations. "
                        "If DIRECT TECHNIQUE-MITIGATION PAIRS are present and the question asks for techniques and mitigations, "
                        "use those pairs as the primary structure of the answer.")
            answer = chat(SYSTEM, prompt)
            generation_ms = round((time.perf_counter() - start) * 1000, 1)
'''

if old_block in qa:
    qa = qa.replace(old_block, new_block, 1)
elif "pair_question = (" not in qa:
    raise SystemExit("Could not find the expected answer-generation block in ctirag/qa.py")

qa_path.write_text(qa, encoding="utf-8")

print("Deterministic technique-mitigation renderer installed.")
print("Backup created beside qa.py.")
print("Next: python -m unittest discover -s tests -v")
