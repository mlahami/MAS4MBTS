# Knowledge Base Design

## Goal

The knowledge base supports the RAG-based Threat Modeling Agent. It must be reproducible, extensible to new ERC standards, and usable later by the multi-agent MBST system.

## Layout

```text
knowledge_base/
  registry/
    sources.json
    ingestion_status.json
    versions.json
  seeds/
    erc_standards/
    vulnerabilities/
    threat_patterns/
  raw/
    ercs/
    swc/
    owasp/
  processed/
    erc_standards/
    vulnerabilities/
    threat_patterns/
    auxiliary/
    examples/
  index/
    documents.jsonl
    chunks.jsonl
    manifest.json
    chunk_manifest.json
```

## Principles

- `seeds/` contains curated records used for reproducible offline builds.
- `raw/` contains downloaded source artifacts from official repositories and websites. It stays empty during the default offline seed build.
- `processed/` contains normalized records that passed validation.
- `processed/auxiliary/` contains enrichment knowledge such as MITRE ATT&CK, DREAD, CVSS, and NIST mappings.
- `index/` contains retrieval-ready documents generated from `processed/`.
- `index/chunks.jsonl` contains shorter traceable passages used by the RAG retriever.
- `registry/sources.json` declares source authority, status, and usage policy.

## Build

```powershell
python -m src.mas4mbts.knowledge.build_knowledge_base
```

This runs:

```text
seed_ingestor -> processed records -> index_builder -> documents.jsonl
```

To include already collected raw ERC markdown files:

```powershell
python -m src.mas4mbts.knowledge.build_knowledge_base --include-raw-ercs --include-raw-swc --include-raw-owasp
```

This runs:

```text
seed_ingestor
  -> raw ERC normalizer
  -> raw SWC normalizer
  -> raw OWASP normalizer
  -> processed records
  -> index_builder
  -> documents.jsonl
  -> chunker
  -> chunks.jsonl
```

The seed records still provide controlled enrichment such as assets and security properties when the official ERC markdown does not explicitly encode them as structured fields.

## Retrieval

```powershell
python -m src.mas4mbts.knowledge.retriever "ERC-4626 withdraw accounting" --erc ERC-4626 -k 5
```

The current retriever is lexical and deterministic. It is intentionally simple so that experiments can be reproduced before adding ChromaDB or FAISS.

For the threat-modeling agent, use the hybrid chunk retriever:

```powershell
python -m src.mas4mbts.knowledge.hybrid_retriever "ERC-20 approve allowance race condition SWC-114" --erc ERC-20 -k 5
```

The hybrid retriever combines:

- BM25 sparse retrieval for exact security identifiers and standard-specific terms such as `ERC-20`, `SWC-114`, `CWE-362`, and `approve`.
- Deterministic dense hashing for local offline semantic matching during development.
- Reciprocal-rank fusion to merge sparse and dense rankings without depending on score calibration.

The deterministic dense hashing backend is a reproducible placeholder. For final experiments, it can be replaced by an embedding backend such as OpenAI, Mistral, sentence-transformers, FAISS, or ChromaDB while keeping the same retrieval interface.

## RAG Implementation Direction

The main proposed system should use Hybrid RAG over the collected KB. The primary baseline should be an LLM-only threat-modeling prompt that receives the contract and ETM schema but no retrieved KB. Optional ablations can isolate sparse-only and dense-only retrieval if the experiments need to explain where the hybrid gain comes from.

## Auxiliary Knowledge

Auxiliary knowledge is used to enrich generated threat models, not to identify ERC-specific weaknesses by itself.

Core knowledge sources:

```text
ERC specifications
OWASP Smart Contract Security
SWC
CWE
EthTrust
OpenZeppelin and audit-derived patterns
```

Auxiliary knowledge sources:

```text
MITRE ATT&CK  -> adversary behavior contextualization
DREAD         -> qualitative threat prioritization
CVSS          -> vulnerability scoring
NIST 800-53   -> mitigation/control guidance
```

Example query:

```powershell
python -m src.mas4mbts.knowledge.retriever "MITRE ATT&CK oracle manipulation blockchain attacker behavior" --kind auxiliary -k 3
```

The threat modeling agent should retrieve auxiliary records only after a relevant threat has been identified from core sources. For example, an oracle manipulation threat can be enriched with MITRE-style adversary context and NIST-style mitigation guidance, while DREAD or CVSS can be attached as optional risk assessment.

## Future Cron Job

The online collection flow is implemented as an explicit raw snapshot step:

```text
ERC watcher
  -> fetch raw ERC markdown from ethereum/ERCs
  -> parse metadata, functions, events, and status
  -> validate records
  -> write processed ERC knowledge
  -> rebuild retrieval index
```

Final ERCs can enter the main processed base. Draft, Review, or Last Call ERCs should be marked as candidates and used only with explicit metadata.

## Online Collection Commands

Collect the main ERC standards used in the initial experiments:

```powershell
python -m src.mas4mbts.knowledge.collect_online_sources --ercs 20,721,1155,4626 --snapshot-id kb_raw_erc_core_v0_1
```

Collect a small smoke-test snapshot:

```powershell
python -m src.mas4mbts.knowledge.collect_online_sources --ercs 20 --include-owasp --limit 2 --snapshot-id kb_raw_smoke_test
```

Discover ERC files from `ethereum/ERCs` and collect only the first 10 discovered files:

```powershell
python -m src.mas4mbts.knowledge.collect_online_sources --discover-ercs --limit 10 --snapshot-id kb_raw_erc_discovery_sample
```

Collect SWC raw files:

```powershell
python -m src.mas4mbts.knowledge.collect_online_sources --include-swc --snapshot-id kb_raw_swc_snapshot
```

Collect full OWASP Smart Contract Security raw files:

```powershell
python -m src.mas4mbts.knowledge.collect_online_sources --all-owasp --snapshot-id kb_raw_owasp_full_v0_1
```

Collect full ERC, SWC, and OWASP sources:

```powershell
python -m src.mas4mbts.knowledge.collect_online_sources --all-ercs --all-swc --all-owasp --snapshot-id kb_raw_core_full_v0_1
```

Each collection writes raw files under `knowledge_base/raw/` and a manifest under:

```text
knowledge_base/raw/manifests/
```

The manifest records source ids, repository metadata when available, collected file paths, URLs, byte sizes, and SHA-256 hashes.

## Raw Normalization Status

Implemented:

- ERC markdown normalization from `knowledge_base/raw/ercs/` to `knowledge_base/processed/erc_standards/`.
- SWC markdown normalization from `knowledge_base/raw/swc/entries/docs/SWC-*.md` to `knowledge_base/processed/vulnerabilities/`.
- OWASP Smart Contract Top 10 and SCWE markdown normalization to `knowledge_base/processed/vulnerabilities/`.

Planned:

- EthTrust raw normalization into Solidity security requirements.
