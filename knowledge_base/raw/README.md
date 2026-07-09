# Raw Source Artifacts

This directory is intentionally empty after an offline seed build.

It is reserved for downloaded source artifacts, such as:

- official ERC markdown files from `ethereum/ERCs`
- raw SWC registry files
- raw OWASP Smart Contract Security pages or exports
- raw EthTrust source documents

The reproducible default command:

```powershell
python -m src.mas4mbts.knowledge.build_knowledge_base
```

does not use network access and therefore does not populate `raw/`.

To collect raw online source snapshots, use:

```powershell
python -m src.mas4mbts.knowledge.collect_online_sources --ercs 20,721,1155,4626 --snapshot-id kb_raw_erc_core_v0_1
```

For a small smoke test:

```powershell
python -m src.mas4mbts.knowledge.collect_online_sources --ercs 20 --include-owasp --limit 2 --snapshot-id kb_raw_smoke_test
```

Fetched raw files should be treated as source material. They must be parsed,
normalized, and validated before entering `knowledge_base/processed/`.

Raw ERC markdown files can already be normalized with:

```powershell
python -m src.mas4mbts.knowledge.normalize_raw_ercs
```

Or included during a full rebuild:

```powershell
python -m src.mas4mbts.knowledge.build_knowledge_base --include-raw-ercs
```
