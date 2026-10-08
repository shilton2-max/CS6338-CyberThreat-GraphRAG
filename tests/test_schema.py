import unittest
from ctirag.schema import Entity, Relation, ExtractionBatch, Resolver, validate_batch, canonical_id
from ctirag.source import chunk_document

class TestSchema(unittest.TestCase):
    def test_official_ids_and_aliases(self):
        a = Entity(id="E1", name="APT28", attack_id="G0007", entity_type="ThreatGroup")
        b = Entity(id="E2", name="Fancy Bear", aliases=["APT28"], entity_type="ThreatGroup")
        self.assertEqual(canonical_id(a), "ATTACK:G0007")
        resolver = Resolver()
        self.assertEqual(resolver.resolve(a), "ATTACK:G0007")
        self.assertEqual(resolver.resolve(b), "ATTACK:G0007")

    def test_type_evidence_and_confidence(self):
        e1 = Entity(id="E1", name="ExampleGroup", entity_type="ThreatGroup")
        e2 = Entity(id="E2", name="ExampleMalware", entity_type="Malware")
        text = "ExampleGroup uses ExampleMalware."
        valid = Relation(source_id="E1", target_id="E2", predicate="USES", evidence_text="ExampleGroup uses ExampleMalware.", confidence_score=.85)
        bad = Relation(source_id="E1", target_id="E2", predicate="USES", evidence_text="ExampleGroup exploits Everything.", confidence_score=.85)
        entities, accepted, review = validate_batch(ExtractionBatch(entities=[e1, e2], relations=[valid, bad]), text)
        self.assertEqual(len(accepted), 1)
        self.assertEqual(review[0]["reason"], "evidence_not_in_source_chunk")

    def test_chunks_keep_overlap(self):
        d = {"doc_id": "TEST", "title": "sample", "source_url": "x", "text": "A" * 6100}
        chunks = chunk_document(d)
        self.assertEqual(len(chunks), 3)
        self.assertEqual(chunks[1]["start_offset"], 2200)
        self.assertEqual(len(chunks[0]["text"]), 2500)

if __name__ == "__main__":
    unittest.main()
