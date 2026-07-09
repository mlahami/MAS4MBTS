# Development Roadmap

## Objective

Develop a KB-assisted ERC Threat Model Agent that generates an ETM-compliant
threat model for a specific smart contract. Attack-tree and test-generation
agents remain downstream extensions.

## Phase 1: ERC Threat Model Agent

Status: ERC-aware, KB-aware deterministic prototype in progress.

Inputs:

- Solidity source, ABI, or prepared smart contract context
- ERC standard name, detected from source/ABI when possible, with explicit
  profiles for ERC-20, ERC-721, ERC-1155, and ERC-4626 plus a generic fallback
  for other ERC standards
- Smart contract context: functions, compiler version, optional address,
  inheritance, imports, events, modifiers, and state variables when available
- Local knowledge base
- ETM JSON Schema

Outputs:

- ETM-compliant threat model JSON

Implemented:

- Local knowledge base files
- ERC-aware deterministic threat model generation through declarative profiles
  and a generic standard fallback
- ETM JSON Schema
- Minimal schema validation without external dependencies
- ETM consistency checker for structural coverage, relation integrity,
  standard matching, traceability warnings, and SWC mapping counts
- ETM output comparator for Mode A deterministic versus Mode B LLM-assisted
  reports
- Hybrid KB retrieval over chunked local knowledge
- Lightweight Solidity/ABI contract analyzer with ERC detection
- Agent state with contract context, retrieved knowledge, draft model,
  validation errors, and final model
- Initial traceable KB source attachment on generated threats,
  vulnerabilities, countermeasures, and test objectives
- Mode A deterministic generation and Mode B Groq LLM-assisted generation

Next steps:

- Improve source selection quality and coverage for each ETM element
- Run Mode A / Mode B comparison over the full Phase 1 contract suite
- Expand and validate explicit ERC profiles with more contract examples
- Improve the generic fallback using richer KB-derived standard metadata
- Add LLM repair loop for invalid or incomplete ETM JSON
- Add LangGraph nodes for retrieval, generation, validation, and repair

## Phase 2: Attack Tree Agent

Inputs:

- ETM-compliant threat model JSON

Outputs:

- Attack tree model

Planned nodes:

- Threat selection
- Goal decomposition
- Attack step generation
- Attack tree validation

## Phase 3: Security Test Agent

Inputs:

- Attack tree leaves
- Test objectives
- Contract ABI or Solidity source

Outputs:

- Foundry, Hardhat, Echidna, or Slither-based security tests

## Phase 4: Execution and Feedback Agent

Inputs:

- Generated tests
- Test execution logs

Outputs:

- Passed/failed objectives
- Refined threat model
- New candidate tests

Feedback loop:

```text
Threat Model -> Attack Tree -> Tests -> Execution -> Analysis -> Threat Model Refinement
```
