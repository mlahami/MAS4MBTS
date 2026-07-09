# Phase 1 Test Suite

This folder contains varied smart contracts and generated Phase 1 artifacts for
the KB-assisted ERC Threat Model Agent.

Layout:

- `contracts/`: Solidity inputs used to exercise ERC detection and context extraction.
- `contexts/`: generated contract contexts from the lightweight analyzer.
- `threat_models/`: generated ETM-compliant threat models.
- `agent_states/`: full agent states with retrieved KB evidence and validation errors.

The suite covers explicit ERC profiles and the generic fallback:

- `SimpleERC20Token.sol`: ERC-20 profile.
- `CollectibleNFT.sol`: ERC-721 profile.
- `GameItems1155.sol`: ERC-1155 profile.
- `TokenizedVault4626.sol`: ERC-4626 profile.
- `OperatorToken777.sol`: generic fallback for ERC-777.
