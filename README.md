# MAS4MBTS

Prototype for an agent-assisted Model-Based Security Testing workflow for ERC smart contracts.

The current focus is the reproducible knowledge chain required by the first internship topic: a RAG-based threat modeling agent for ERC smart contracts. The knowledge base is built first, then the threat modeling agent consumes it to generate ETM-compliant threat models.

## Current Scope

- Reproducible ERC vulnerability knowledge base
- Offline seed ingestion for ERC-20, ERC-721, ERC-1155, and ERC-4626
- Local vulnerability and threat-pattern records with SWC/CWE/OWASP mappings
- Auxiliary knowledge records for MITRE ATT&CK, DREAD, CVSS, and NIST SP 800-53
- Deterministic JSONL retrieval index
- RAG chunk index with traceable source metadata
- Hybrid retrieval with BM25, deterministic dense hashing, and reciprocal-rank fusion
- ETM JSON Schema for validating the generated structure
- Initial ERC-20 threat model generation prototype

## Project Layout

```text
knowledge_base/                 Reproducible knowledge base
knowledge_base/registry/        Source registry and ingestion status
knowledge_base/seeds/           Curated offline seed records
knowledge_base/processed/       Normalized records used by RAG
knowledge_base/processed/auxiliary/
                                Optional enrichment knowledge
knowledge_base/index/           Deterministic JSONL retrieval index
knowledge_base/index/chunks.jsonl
                                Chunked RAG passages
src/mas4mbts/knowledge/         Knowledge ingestion and retrieval tools
src/mas4mbts/agents/            Agent implementation
src/mas4mbts/schemas/           ETM JSON Schema
examples/phase1_test_suite/     Example contracts, contexts, and threat models
```

## Build Knowledge Base

```powershell
python -m src.mas4mbts.knowledge.build_knowledge_base
```

This command is offline and deterministic. It validates curated seed records, writes normalized records under `knowledge_base/processed/`, and builds `knowledge_base/index/documents.jsonl`.
It also builds `knowledge_base/index/chunks.jsonl` for RAG retrieval.

To rebuild using curated seeds plus any collected raw ERC markdown files:

```powershell
python -m src.mas4mbts.knowledge.build_knowledge_base --include-raw-ercs --include-raw-swc --include-raw-owasp
```

Query the local index:

```powershell
python -m src.mas4mbts.knowledge.retriever "ERC-20 approve allowance race condition" --erc ERC-20 -k 5
```

Query auxiliary knowledge:

```powershell
python -m src.mas4mbts.knowledge.retriever "DREAD CVSS threat prioritization smart contract" --kind auxiliary -k 5
```

Build only the chunk index from an existing `documents.jsonl`:

```powershell
python -m src.mas4mbts.knowledge.chunker --max-tokens 180 --overlap-tokens 35
```

Query the hybrid RAG index:

```powershell
python -m src.mas4mbts.knowledge.hybrid_retriever "ERC-20 approve allowance race condition SWC-114" --erc ERC-20 -k 5
```

The current hybrid retriever combines BM25 sparse retrieval, deterministic local dense hashing, and reciprocal-rank fusion. The deterministic dense backend is an offline implementation for reproducible development; it can later be replaced by OpenAI, Mistral, sentence-transformers, FAISS, or ChromaDB embeddings without changing the agent interface.

## Threat Model Prototype

```powershell
python -m src.mas4mbts.agents.erc_threat_model_agent `
  --input examples/phase1_test_suite/contexts/simple_erc20_token.context.json `
  --output examples/erc20_threat_model.generated.json
```

The command works without an API key by using a deterministic ERC-20 template. Later, the same agent can be connected to a LangChain chat model and vector retriever.

## Optional Online Collection

The reproducible pipeline does not require network access. Online collection is opt-in and writes raw snapshots under `knowledge_base/raw/`.

```powershell
python -m src.mas4mbts.knowledge.collect_online_sources --ercs 20,721,1155,4626 --snapshot-id kb_raw_erc_core_v0_1
```

Smoke-test online collection:

```powershell
python -m src.mas4mbts.knowledge.collect_online_sources --ercs 20 --include-owasp --limit 2 --snapshot-id kb_raw_smoke_test
```

Full ERC/SWC/OWASP collection:

```powershell
python -m src.mas4mbts.knowledge.collect_online_sources --all-ercs --all-swc --all-owasp --snapshot-id kb_raw_core_full_v0_1
```

Fetched files are raw source material stored under `knowledge_base/raw/`. The default offline build does not populate `raw/`; it uses curated seeds for reproducibility. Raw files should be normalized and validated before entering `knowledge_base/processed/`.

## Research Positioning

The ERC Threat Metamodel is OWASP-inspired: it adapts assets, entry points, trust levels, threats, vulnerabilities, mitigations, and validation objectives to ERC-based smart contracts. The generated threat model is an instance of this metamodel and can be used as input for attack-tree generation and security-test generation.
