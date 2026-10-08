"""Optional official RAGAS 0.2.x evaluation on previously generated verified answers.

This is not part of the dependency-light default QA pipeline; install
requirements-ragas.txt only after the core project works.
"""
from pathlib import Path
import json
import os
from dotenv import load_dotenv
load_dotenv()


def run_ragas(qa_results: Path, output: Path):
    try:
        from datasets import Dataset
        from ragas import evaluate
        from ragas.metrics import faithfulness, answer_relevancy, context_recall
        from ragas.llms import LangchainLLMWrapper
        from ragas.embeddings import LangchainEmbeddingsWrapper
        from langchain_ollama import ChatOllama
        from langchain_huggingface import HuggingFaceEmbeddings
    except ImportError as exc:
        raise RuntimeError("Install optional packages: pip install -r requirements-ragas.txt") from exc
    logs = json.loads(qa_results.read_text(encoding="utf-8"))
    rows = [{"question": r["question"], "answer": r["answer"],
             "contexts": r["contexts"], "ground_truth": r["gold_answer"]} for r in logs]
    if not rows:
        raise ValueError("No QA results to evaluate")
    dataset = Dataset.from_list(rows)
    llm = LangchainLLMWrapper(ChatOllama(model=os.getenv("OLLAMA_MODEL", "llama3.1:8b"),
                                          base_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
                                          temperature=0))
    embeddings = LangchainEmbeddingsWrapper(HuggingFaceEmbeddings(
        model_name=os.getenv("TEXT_EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")))
    # RAGAS 0.2.x legacy metric API; adjust if choosing a newer major version.
    result = evaluate(dataset, metrics=[faithfulness, answer_relevancy, context_recall],
                      llm=llm, embeddings=embeddings, raise_exceptions=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    result.to_pandas().to_csv(output, index=False)
    return str(output)
