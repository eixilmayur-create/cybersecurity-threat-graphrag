# Cybersecurity Threat Graph-RAG

Learning project combining an RDF knowledge graph, SPARQL retrieval, SHACL validation, Gemini answer generation, and a local FastAPI service.

The included threat data is demonstration data; do not interpret it as verified threat intelligence.

## Setup (PowerShell, Python 3.13)

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Set your own `GEMINI_API_KEY` in `.env`. Never commit that file.

## Retrieve evidence and generate an answer

```powershell
.\.venv\Scripts\python.exe src/graphrag/graph_retrieval.py --question "What malware, vulnerabilities, infrastructure and campaigns are associated with APT-29?"
.\.venv\Scripts\python.exe src/graphrag/graphrag_answer.py
```

Generated context, answers, and traces are saved under `outputs/` and excluded from Git.

## Run the local API

```powershell
.\.venv\Scripts\python.exe -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/docs. The API is intended for local use and has no authentication layer. A private source repository does not make a deployed API private.

## Repository hygiene

Local environment files, virtual environments, logs, caches, generated outputs, and historical backup files are excluded. `.env.example` contains no credentials. Keep deployment credentials and actual sensitive datasets out of source control.
