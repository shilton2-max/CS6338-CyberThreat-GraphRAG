"""Simple, usable cyber threat intelligence GraphRAG demonstration UI."""
import json
from pathlib import Path
import streamlit as st
from dotenv import load_dotenv
load_dotenv()
from ctirag.graph import Graph
from ctirag.qa import QA

st.set_page_config(page_title="Cyber Threat Intelligence GraphRAG", page_icon="🔐", layout="wide")
st.title("Cyber Threat Intelligence GraphRAG")
st.caption("CS-6338 Knowledge Engineering | Seth Hilton | CISA + MITRE ATT&CK + Neo4j + Ollama")

@st.cache_resource
def get_qa():
    g = Graph()
    g.driver.verify_connectivity()
    return QA(g, Path("data/cache/embeddings"))

question = st.text_input("Ask a threat-intelligence question", "Which techniques are associated with APT28, and what mitigations apply?")
mode = st.radio("Retrieval system", ["hybrid", "text"], horizontal=True)
if st.button("Ask", type="primary"):
    try:
        with st.spinner("Retrieving evidence and generating answer..."):
            result = get_qa().ask(question, mode)
        st.subheader("Answer")
        st.write(result["answer"])
        c1, c2 = st.columns(2)
        c1.metric("Retrieval time (ms)", result["retrieval_time_ms"])
        c2.metric("Generation time (ms)", result["generation_time_ms"])
        with st.expander("Advisory sources", expanded=True):
            st.json(result["sources"])
        with st.expander("Supporting graph paths"):
            st.json(result["graph_paths"])
        with st.expander("Full evaluation/QA log"):
            st.json(result)
    except Exception as exc:
        st.error(str(exc))
        st.info("Make sure Ollama and Neo4j Desktop are running, data is loaded, and indexes are ONLINE.")
