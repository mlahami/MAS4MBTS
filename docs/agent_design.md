# ERC Threat Model Agent Design

## Agent Role

The ERC Threat Model Agent instantiates the ERC Threat Metamodel for a specific ERC standard and smart contract.

It does not directly generate tests. It produces a structured threat model that can later drive attack-tree and test-generation agents.

## Recommended LangGraph Nodes

```text
Contract Context Loader
  -> Knowledge Retriever
  -> Threat Model Generator
  -> ETM Validator
  -> Repair Node
  -> Threat Model Exporter
```

## State

```json
{
  "contract_context": {},
  "retrieved_knowledge": [],
  "draft_threat_model": {},
  "validation_errors": [],
  "final_threat_model": {}
}
```

## Knowledge Base

The first knowledge base should stay small and controlled:

- Official ERC specifications
- OWASP-inspired threat modeling concepts
- OWASP Smart Contract Security concepts
- EEA EthTrust requirements
- SWC entries as historical labels
- OpenZeppelin implementation notes
- Curated audit-derived threat patterns

The agent should cite which knowledge items justify each generated threat.

## Quality Checks

- Every threat must target at least one asset.
- Every threat must be triggered by at least one entry point or contract interaction.
- Every threat must violate at least one security property.
- Every threat must be linked to at least one test objective.
- Every privileged entry point must have an authorization-related security property.
