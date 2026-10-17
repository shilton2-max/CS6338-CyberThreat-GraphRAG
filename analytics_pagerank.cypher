// CS-6338 Final Project - Neo4j Graph Data Science PageRank
// Requires the Neo4j Graph Data Science plugin.

CALL gds.graph.project(
  'cti_entity_graph',
  'Entity',
  ['USES','IMPLEMENTS','EXPLOITS','TARGETS','MITIGATED_BY','ATTRIBUTED_TO']
)
YIELD graphName, nodeCount, relationshipCount;

CALL gds.pageRank.write('cti_entity_graph', {
  writeProperty: 'pagerank',
  dampingFactor: 0.85,
  maxIterations: 20
})
YIELD nodePropertiesWritten, ranIterations, didConverge;

MATCH (n:Entity)
WHERE n.pagerank IS NOT NULL
RETURN n.id AS id,
       n.name AS name,
       n.entity_type AS entity_type,
       n.pagerank AS pagerank
ORDER BY pagerank DESC
LIMIT 15;

CALL gds.graph.drop('cti_entity_graph', false)
YIELD graphName;
