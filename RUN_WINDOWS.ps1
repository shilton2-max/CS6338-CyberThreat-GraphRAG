# Run in PowerShell FROM THE PROJECT DIRECTORY after setting up the virtual environment.
# Follow README.md. This script validates local prerequisites; it does not modify a database.
$ErrorActionPreference = 'Stop'
Write-Host 'Cyber Threat Intelligence GraphRAG -- local setup diagnostics'
python --version
Write-Host 'Running local source/unit tests...'
python -m unittest discover -s tests -v
Write-Host 'Done. Next: edit .env, start Neo4j and Ollama, then follow README steps 1-6.'
