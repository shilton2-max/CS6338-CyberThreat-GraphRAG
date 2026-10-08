import unittest
from ctirag.attack import build_stix_subgraph, relation_predicate

class TestAttack(unittest.TestCase):
    def test_mitigates_direction(self):
        b = {"objects": [
            {"id": "intrusion-set--a", "type": "intrusion-set", "name": "DemoGroup", "external_references": [{"source_name": "mitre-attack", "external_id": "G0007"}]},
            {"id": "attack-pattern--b", "type": "attack-pattern", "name": "DemoTechnique", "external_references": [{"source_name": "mitre-attack", "external_id": "T1001"}]},
            {"id": "course-of-action--c", "type": "course-of-action", "name": "DemoMitigation", "external_references": [{"source_name": "mitre-attack", "external_id": "M1001"}]},
            {"id": "relationship--d", "type": "relationship", "source_ref": "intrusion-set--a", "target_ref": "attack-pattern--b", "relationship_type": "uses"},
            {"id": "relationship--e", "type": "relationship", "source_ref": "course-of-action--c", "target_ref": "attack-pattern--b", "relationship_type": "mitigates"}
        ]}
        nodes, rels = build_stix_subgraph(b, {"G0007"})
        self.assertEqual(len(rels), 2)
        mitigation = next(x for x in rels if x["predicate"] == "MITIGATED_BY")
        self.assertEqual(mitigation["source_id"], "ATTACK:T1001")
        self.assertEqual(mitigation["target_id"], "ATTACK:M1001")

if __name__ == "__main__":
    unittest.main()
