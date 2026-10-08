import unittest
from ctirag.evaluate import triple_metrics
from ctirag.qa import _seed_ids

class TestEvaluation(unittest.TestCase):
    def test_triples_dedupe_and_f1(self):
        a = {"source_id": "A", "predicate": "USES", "target_id": "B"}
        b = {"source_id": "A", "predicate": "USES", "target_id": "C"}
        result = triple_metrics([a, b, a], [{**a, "verified_by_human": True}])
        self.assertAlmostEqual(result["precision"], .5)
        self.assertEqual(result["recall"], 1)
        self.assertAlmostEqual(result["f1"], 2/3)

    def test_query_seed_identification(self):
        candidates = [{"id": "ATTACK:G0007", "name": "APT28", "aliases": ["Fancy Bear"], "attack_id": "G0007"}]
        self.assertEqual(_seed_ids("What does Fancy Bear use?", candidates), ["ATTACK:G0007"])

if __name__ == "__main__":
    unittest.main()
