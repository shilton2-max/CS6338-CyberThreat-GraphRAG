"""384d sentence embeddings and 64d Node2Vec graph embeddings (seed 42)."""
from __future__ import annotations
import hashlib
import json
import os
import random
from pathlib import Path
import networkx as nx
import numpy as np


class TextEncoder:
    def __init__(self, cache_dir: Path):
        self.cache = cache_dir
        self.cache.mkdir(parents=True, exist_ok=True)
        self.model_name = os.getenv("TEXT_EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
        # Lazy load heavy dependencies only when needed.
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer(self.model_name)
        self.dim = self.model.get_sentence_embedding_dimension()
        if self.dim != 384:
            raise ValueError(f"Expected all-MiniLM 384d model; got {self.dim}d")

    def embed(self, content: str) -> list[float]:
        key = hashlib.sha256((self.model_name + ":" + content).encode()).hexdigest()
        path = self.cache / f"{key}.npy"
        if path.exists():
            return np.load(path).astype(float).tolist()
        vec = np.asarray(self.model.encode(content, normalize_embeddings=True), dtype=np.float32)
        np.save(path, vec)
        return vec.astype(float).tolist()


def biased_walk(g: nx.Graph, start: str, length: int, rng: random.Random,
                p: float = 1.0, q: float = .5) -> list[str]:
    walk = [start]
    while len(walk) < length:
        current = walk[-1]
        nbrs = sorted(g.neighbors(current))
        if not nbrs:
            break
        if len(walk) == 1:
            next_node = rng.choice(nbrs)
        else:
            previous = walk[-2]
            weights = [(1/p if x == previous else 1 if g.has_edge(previous, x) else 1/q)
                       for x in nbrs]
            next_node = rng.choices(nbrs, weights=weights, k=1)[0]
        walk.append(next_node)
    return walk


def node2vec_vectors(nodes: list[dict], edges: list[dict], dimensions=64,
                     walk_length=30, num_walks=100, seed=42) -> dict[str, list[float]]:
    from gensim.models import Word2Vec
    rng = random.Random(seed)
    graph = nx.Graph()
    graph.add_nodes_from(n["id"] for n in nodes)
    graph.add_edges_from((e["src"], e["dst"]) for e in edges)
    if not graph.nodes or not graph.edges:
        return {}
    walks = []
    ids = sorted(graph.nodes)
    for _ in range(num_walks):
        rng.shuffle(ids)
        for node in ids:
            if graph.degree(node) > 0:
                walks.append(biased_walk(graph, node, walk_length, rng))
    w2v = Word2Vec(sentences=walks, vector_size=dimensions, window=10, min_count=0,
                   sg=1, workers=1, seed=seed, epochs=5)
    vecs = {}
    for node in graph.nodes:
        if node not in w2v.wv:
            continue
        vec = w2v.wv[node].astype(np.float32)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vecs[node] = (vec / norm).astype(float).tolist()
    return vecs


def embed_graph(graph, cache_dir: Path, do_node2vec=True) -> dict:
    encoder = TextEncoder(cache_dir)
    chunks = graph.text_chunks()
    entities, edges = graph.embedding_data()
    if chunks:
        graph.store_vectors("TextChunk", [{"id": c["id"], "embedding": encoder.embed(c["text"])}
                                          for c in chunks], "embedding")
    if entities:
        graph.store_vectors("Entity", [{"id": e["id"], "embedding": encoder.embed(
            (e.get("name") or "") + " " + (e.get("description") or "")[:400])} for e in entities],
            "text_embedding")
    count = 0
    if do_node2vec:
        vectors = node2vec_vectors(entities, edges)
        graph.store_vectors("Entity", [{"id": k, "embedding": v} for k, v in vectors.items()],
                            "graph_embedding")
        count = len(vectors)
    return {"text_chunks_embedded": len(chunks), "entities_text_embedded": len(entities),
            "entities_node2vec_embedded": count, "graph_edges": len(edges), "seed": 42,
            "sentence_model": encoder.model_name}
