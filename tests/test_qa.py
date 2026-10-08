import unittest
from unittest.mock import patch
from ctirag.qa import QA

class DummyEncoder:
    def embed(self, _):
        return [0.0] * 383 + [1.0]

class DummyGraph:
    def vector_search(self, index, q, k):
        if index == 'chunk_embedding_index':
            return [{'id':'chunk:1','doc_id':'AA-TEST','source_url':'https://www.cisa.gov/example',
                     'text':'ExampleGroup uses ExampleMalware.','score':.93}]
        if index == 'entity_text_embedding_index':
            return [{'id':'G1','name':'ExampleGroup','entity_type':'ThreatGroup','score':.92}]
        return []
    def all_entities(self, limit=5000):
        return [{'id':'G1','name':'ExampleGroup','aliases':[],'attack_id':'','cve_id':''}]
    def neighborhood_paths(self, seeds, max_paths=60):
        return [{'nodes':[{'id':'G1','name':'ExampleGroup','type':'ThreatGroup'},
                          {'id':'M1','name':'ExampleMalware','type':'Malware'}],
                 'edges':[{'source_id':'G1','target_id':'M1','type':'USES','source_doc_id':'AA-TEST',
                           'source_url':'https://www.cisa.gov/example',
                           'evidence_text':'ExampleGroup uses ExampleMalware.'}]}]
    def run(self, query, **params):
        return []

class TestQA(unittest.TestCase):
    def test_hybrid_uses_both_sources(self):
        qa = object.__new__(QA)
        qa.graph = DummyGraph()
        qa.encoder = DummyEncoder()
        with patch('ctirag.qa.chat', return_value='ExampleGroup uses ExampleMalware [AA-TEST].') as generate:
            result = qa.ask('What does ExampleGroup use?', 'hybrid')
        prompt = generate.call_args.args[1]
        self.assertIn('GRAPH EVIDENCE:', prompt)
        self.assertIn('TEXT EVIDENCE:', prompt)
        self.assertIn('G1 -[USES]-> M1', prompt)
        self.assertIn('AA-TEST', result['retrieved_doc_ids'])
        self.assertIn('M1', result['retrieved_entity_ids'])

    def test_baseline_has_no_graph_paths(self):
        qa = object.__new__(QA)
        qa.graph = DummyGraph()
        qa.encoder = DummyEncoder()
        with patch('ctirag.qa.chat', return_value='Answer [AA-TEST].'):
            result = qa.ask('What does ExampleGroup use?', 'text')
        self.assertFalse(result['graph_paths'])
        self.assertTrue(result['retrieved_doc_ids'])

if __name__ == '__main__':
    unittest.main()
