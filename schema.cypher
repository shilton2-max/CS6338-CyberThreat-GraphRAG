// Neo4j 5.18+ schema - safe to execute repeatedly.
CREATE CONSTRAINT entity_unique IF NOT EXISTS FOR (n:Entity) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT advisory_unique IF NOT EXISTS FOR (n:Advisory) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT textchunk_unique IF NOT EXISTS FOR (n:TextChunk) REQUIRE n.id IS UNIQUE;
CREATE INDEX entity_name IF NOT EXISTS FOR (n:Entity) ON (n.name);
CREATE INDEX entity_attack_id IF NOT EXISTS FOR (n:Entity) ON (n.attack_id);
CREATE INDEX entity_cve_id IF NOT EXISTS FOR (n:Entity) ON (n.cve_id);
CREATE VECTOR INDEX chunk_embedding_index IF NOT EXISTS FOR (n:TextChunk) ON (n.embedding)
OPTIONS {indexConfig: {`vector.dimensions`: 384, `vector.similarity_function`: 'cosine'}};
CREATE VECTOR INDEX entity_text_embedding_index IF NOT EXISTS FOR (n:Entity) ON (n.text_embedding)
OPTIONS {indexConfig: {`vector.dimensions`: 384, `vector.similarity_function`: 'cosine'}};
CREATE VECTOR INDEX entity_embedding_index IF NOT EXISTS FOR (n:Entity) ON (n.graph_embedding)
OPTIONS {indexConfig: {`vector.dimensions`: 64, `vector.similarity_function`: 'cosine'}};


