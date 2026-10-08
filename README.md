# Cyber Threat Intelligence GraphRAG Chatbot

**Seth Hilton | CS-6338 Knowledge Engineering | Dr. Erdoğan Doğdu | Angelo State University**

An implementation of the **Cyber Threat Intelligence GraphRAG Chatbot** specified in the September 28 proposal and October 6 system design. It targets cybersecurity questions that require 2–3 connected facts (threat group → malware → technique → mitigation), with traceable CISA and MITRE ATT&CK evidence.

> **Status:** Runnable source implementation and unit tests are included. **No live CISA corpus has been downloaded, no local Ollama / Neo4j deployment has been executed by the assistant, and no empirical extraction/QA/RAGAS scores are claimed.** You must run the pipeline and verify the gold annotations on your machine before submitting performance claims.

## The professor's four required components

| Course requirement | Implemented in this package | What remains to run / verify |
|---|---|---|
| 1. Schema engineering & KG extraction | Strict Pydantic extraction JSON, Ollama prompts, relation-type policy, verbatim-evidence checks, exact ATT&CK/CVE ID matching, alias/fuzzy deduplication (92% merge, 80–91% local LLM verification), 0.70 acceptance + 0.50–0.69 review queue, Neo4j constraints and provenance | Download 100 CISA advisories; run extraction; inspect manual review queue and verify 50–60 triples |
| 2. Embeddings & indexing | `all-MiniLM-L6-v2` 384-dimensional advisory and entity text vectors, biased-walk Node2Vec 64-dimensional graph vectors (walk length 30, 100 walks, p=1, q=.5, seed 42), three Neo4j vector indexes | Run on an actual populated graph; capture the ONLINE indexes and graph summary |
| 3. Hybrid GraphRAG QA | 5 text chunks + 5 semantic entity seeds, exact ID/name/alias seed matching, graph neighborhood up to three hops / 40 unique nodes / 60 unique edges, Node2Vec expansion from graph seeds, evidence-cited Ollama answer, safe fallback, text-only baseline, Streamlit UI | Run sample questions with indexed data and capture sources/paths/timing |
| 4. Evaluation | Triple precision/recall/F1, verified QA gold set format (25 templates), text RAG vs. GraphRAG paired runner, reference-source recall proxy, required-path hit, timed logs, human 1–5 scoring sheet, optional local judge and official RAGAS 0.2.x runner | **Manually validate** >=50–60 extracted triples, >=20–25 multi-hop answers, score human rubric; run official RAGAS with optional packages |

**Important distinction:** A 25-question *template* is included; it is **not** a verified 25-question gold benchmark. Likewise, a gold-triple example is **unverified** until you check the underlying ATT&CK version and source evidence. Never report the unverified examples as measured results.

## 0. Prerequisites for Windows 10/11

Use **Python 3.11** if available, **Neo4j Desktop** with a running local database (Neo4j 5.18+ / recent release), and **Ollama** with Llama 3.1 8B. Your previous CS-6338 work used Ollama and Neo4j, so you can use the same running services. The first `sentence-transformers` invocation downloads the 384d model unless it is already cached. MITRE STIX is a large (~50 MB) download.

In Windows **PowerShell**, from the extracted project folder:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
```

Set your actual **Neo4j Desktop** password in `.env`. Do not paste it in chat or put secrets in screenshots. Defaults are `bolt://localhost:7687`, user `neo4j`, database `neo4j`.

In a separate terminal, run `ollama pull llama3.1:8b` and make sure Ollama is available (the desktop Ollama app normally starts the local server; otherwise `ollama serve`).

First verify the self-contained code tests:

```powershell
python -m unittest discover -s tests -v
```

## 1. Obtain genuine CISA Cybersecurity Advisories

For the initial proof-of-function, start with **five** known CISA advisory URLs:

```powershell
python run.py download --urls data/advisory_urls.txt --limit 5
```

If that works, scale to the ~100-advisory target:

```powershell
python run.py download --limit 100
```

The loader stores one JSON record per real advisory in `data/advisories/`, with `doc_id`, `title`, `publication_date`, `source_url` and full `text`. It writes `download_report.json` listing actual downloads and errors. **Do not assume 100 were collected unless that report says 100.**

The CISA website can block scripts with a 403 or rate limits. If so, manually save real advisory text in UTF-8 `.txt` files under `data/`, fill in `data/manual_manifest.csv` with `doc_id,title,publication_date,source_url,text_file`, then:

```powershell
python run.py import-local --manifest data/manual_manifest.csv
```

For this fallback, `text_file` is relative to the manifest folder (for example `AA25-141A.txt`), and each source URL must be an official `https://www.cisa.gov/` URL. This is real-data provenance, **not** the synthetic example in `data/sample/`.

## 2. LLM extraction and entity resolution

Smoke-test the extraction process on a few 2,500-character chunks (300-character overlap):

```powershell
python run.py extract --max-chunks 5
```

Once that succeeds, rerun over the entire downloaded corpus (cached chunk extractions are reused):

```powershell
python run.py extract
```

Important outputs:

- `outputs/extracted.jsonl`: validated graph-ready evidence and entities by advisory chunk.
- `outputs/review_queue.jsonl`: rejected/uncertain triples, malformed responses, and possible duplicate names.
- `data/cache/extraction/`: raw extraction JSON cache (repeat runs don't regenerate everything).

Review any unsupported evidence or ambiguous identity rather than adding an invented relationship.

## 3. Neo4j: schema, text, entities, verified MITRE STIX

Start your Neo4j Desktop database before running:

```powershell
python run.py init-db
python run.py load
python run.py import-attack --focus G0007 --max-relations 300
python run.py stats
```

`--focus G0007` is the **APT28** starter MITRE ATT&CK group; supply additional official ATT&CK IDs via `--focus G0007 GXXXX ...` based on your selected CISA corpus. The MITRE import reads a true **Enterprise ATT&CK STIX 2.1 bundle**, caches it under `data/enterprise-attack.json`, imports only up to the selected bounded relationship count and includes known related mitigations. It does not invent CISA evidence. It marks MITRE-verified edges with separate provenance.

If the automatic STIX download fails, download `enterprise-attack.json` from the official `mitre-attack/attack-stix-data` repository, save it under `data/`, and rerun the same command.

In Neo4j Browser, verify:

```cypher
MATCH (n) RETURN labels(n) AS labels, count(*) AS count ORDER BY count DESC;
MATCH (a:Entity)-[r:USES|IMPLEMENTS|MITIGATED_BY]->(b:Entity)
RETURN a.name, type(r), b.name, r.source_doc_id, r.evidence_text LIMIT 20;
```

## 4. 384-dimensional embeddings + Node2Vec 64-dimensional embeddings

```powershell
python run.py embed
```

Creates / fills Neo4j vector indexes:

- `chunk_embedding_index`: TextChunk 384d (local MiniLM).
- `entity_text_embedding_index`: Entity 384d (for semantic text→entity seed search).
- `entity_embedding_index`: Entity 64d (Node2Vec graph structure, **queried from seed graph embeddings**; natural-language text vectors are never compared to these 64d vectors).

Neo4j builds indexes asynchronously. Check readiness in Neo4j Browser:

```cypher
SHOW VECTOR INDEXES YIELD name, state, populationPercent
RETURN name, state, populationPercent;
```

Wait for `ONLINE` before running the chatbot. The query API uses `db.index.vector.queryNodes` for broad Neo4j 5.x compatibility; newer Neo4j releases mark it deprecated but it may remain usable.

## 5. Ask questions and show the chatbot

```powershell
python run.py ask "Which techniques are associated with APT28 and what mitigations apply?" --mode hybrid
python run.py ask "Which techniques are associated with APT28 and what mitigations apply?" --mode text
streamlit run app.py
```

The **hybrid** answer returns graph paths, entity IDs, text chunks, citations and query/generation times. The **text** mode does not retrieve graph nodes/paths and acts as a clean comparison. Both use the same underlying text and Llama 3.1 answer model. The answerer must say it lacks enough evidence when links are missing.

## 6. Ground truth + automated and human evaluation

The earlier project design mentions **52 ATT&CK-backed starter triples** and **23 starter QA prompts**. Those files were not provided inside this implementation package; **do not claim their contents are here**. If you still have `gold_triples.json` and `eval_queries.json` from your older checkpoint, review them and overwrite the included *unverified templates* rather than having to annotate them again.

Generate up to 60 review candidates from genuine extracted triples:

```powershell
python run.py annotation-candidates
```

Open `eval/candidate_gold_triples.json` and check each subject/relationship/object against the actual sources. Build `eval/gold_triples.json` with `verified_by_human: true` only after manual checking. **Use exhaustively annotated chunks for measuring precision**, otherwise a correct unreviewed predicted edge could be mistakenly scored as a false positive.

Prepare `eval/eval_queries.json`: there are 25 unverified multi-hop *question prompts* already listed. For at least 20 relevant questions, replace vague descriptions with real names/CVEs, fill in a real `gold_answer`, `expected_doc_ids` and `expected_entity_ids` where known, and mark `verified_by_human: true` only after review. Set aside the final questions so they're not tuned on repeatedly.

Then run:

```powershell
python run.py triple-eval
python run.py qa-eval
```

This generates:

- `outputs/qa_results.json`: paired text/GraphRAG outputs with document IDs, path IDs, generated answers and timings.
- `outputs/qa_summary.json`: measured mean response times and actual verified question count.
- `outputs/human_review.csv`: separate 1–5 factuality, completeness, and coherence scores for each system/question.

Once you have actually filled out every human score (1–5), run `python run.py human-summary` to calculate the separate mean factuality, completeness and coherence by system. Do not run it on blank fields.

For the optional local *RAGAS-style* Llama evaluator, use `python run.py qa-eval --local-judge`; its scores **are not official RAGAS**. For the optional **official RAGAS 0.2.x** metrics run:

```powershell
python -m pip install -r requirements-ragas.txt
python run.py ragas
```

The official RAGAS runner attempts faithfulness, answer relevancy, and context recall using your local Ollama model plus the same MiniLM embedding model. This optional integration is version-sensitive and has **not** been live-tested in the assistant's environment; if your installed library API differs, it may need compatibility changes. Never claim RAGAS metrics were measured if they did not run.

## 7. Evidence to capture for the submission

1. Successful real CISA download report showing document IDs and count (target ~100), plus MITRE STIX provenance.
2. A sample extraction JSON with verbatim evidence and a review-queue item; deduplicated canonical IDs and Neo4j schema labels.
3. `SHOW VECTOR INDEXES` screenshot with three ONLINE indexes; Node2Vec vector example, 64 dimensions, seed 42.
4. Streamlit question/answer screenshots showing retrieved graph paths **and** supporting CISA/MITRE source IDs/URLs.
5. Gold annotation counts, triple precision/recall/F1, text vs hybrid QA run logs, RAGAS metrics if run, human 1–5 scores, and retrieval/generation timing.

**Performance targets are goals, not tested measurements:** retrieval <=~2 s and complete answers <=~12 s depend heavily on hardware, Neo4j and local Llama 3.1 performance.

## Safety and reproducibility

- Local Llama 3.1 inference and MiniLM embedding require no paid model API; internet is needed to fetch datasets/models initially.
- All real source relationships retain `source_doc_id`, URL and evidence. Graph traversal never creates new, permanent inferred links.
- A document's text is retrieved as *untrusted* external material; it cannot instruct the model to ignore the grounding policy.
- Keep `.env`, large data downloads, and private annotations out of public version control.
- `data/sample/SYNTHETIC-DEMO.json` is a **synthetic test fixture**. Its claims must **never** appear in a report as real CISA evidence.
- To test only the source logic before setup, `python -m unittest discover -s tests -v` works without the real Neo4j/Ollama services when minimal schema/test dependencies are available.
