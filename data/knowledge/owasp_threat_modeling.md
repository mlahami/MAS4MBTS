# OWASP-Inspired Threat Modeling Concepts

The ETM uses general threat modeling concepts commonly found in OWASP-style threat modeling processes and adapts them to ERC smart contracts.

## Core Concepts

- Asset: something valuable that should be protected, such as balances, allowances, ownership, or total supply.
- Entry point: a public or external function through which an actor can interact with the contract.
- Trust level: the permission level associated with an actor or interaction.
- Threat: a potential harmful action against an asset through an entry point.
- Vulnerability: a weakness that can be exploited by a threat.
- Countermeasure: a mitigation or control that reduces the threat.
- Security property: an expected invariant or authorization rule.
- Test objective: a verifiable objective that checks whether a security property is enforced.

## STRIDE Categories

- Spoofing
- Tampering
- Repudiation
- Information Disclosure
- Denial of Service
- Elevation of Privilege
