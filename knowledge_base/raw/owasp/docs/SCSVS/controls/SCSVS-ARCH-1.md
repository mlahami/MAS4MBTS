---
search:
  exclude: true
---


# SCSVS-ARCH-1
## S1.1 Secure Design Patterns

### Control Objective
Ensure that smart contracts are designed with modularity, upgradability, and separation of concerns to enable secure operations, upgrades, and maintenance. Contracts should be designed to minimize security risks related to complex upgrades, privilege transfers, and mismanagement of dependencies.

### S1.1.A Modularity and Upgradability

| **SCSVS&nbsp;VR&nbsp;ID**   | Requirement                                                                 | L1 | L2 | R | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S1.1.A1      | Verify that the contract is divided into modular components or contracts.    |    | ✓  | ✓  |     |
| S1.1.A2      | Ensure that upgrade mechanisms are designed to allow secure and controlled updates. |    | ✓  | ✓  |     |
| S1.1.A3      | Check that module boundaries are clearly defined and that dependencies are managed. |    | ✓  | ✓  |     |
| S1.1.A4      | Ensure that changes to storage variable order or types between contract versions are managed to avoid storage collisions and data corruption. |    | ✓  | ✓  |     |
| S1.1.A5      | Verify that critical privilege transfers are conducted in a two-step process to ensure secure and reliable privilege changes. |    |    | ✓  |     |
| S1.1.A6      | Verify that the data location of parameters and return variables is correctly handled when overriding internal and public functions to avoid generating invalid code during virtual function calls. |    |    | ✓  |     |


### S1.1.B Separation of Concerns

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | R | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S1.1.B1      | Verify that different functionalities are separated into distinct contracts or modules. |    | ✓  | ✓  |     |
| S1.1.B2      | Ensure that each module has a single responsibility and minimal dependencies on other modules. |    | ✓  | ✓  |     |
| S1.1.B3      | Check for any cross-module dependencies that could lead to security risks.   |    | ✓  | ✓  |     |
| S1.1.B4      | Ensure that the protocol maintains consistent and reliable operation during the transfer of privileges, with considerations for various edge cases. |    |    | ✓  |     |
| S1.1.B5      | Verify that proxy contracts use the `onlyInitializing` modifier instead of `initializer` to ensure proper initialization. |    |    | ✓  |     |
| S1.1.B6      | Verify that storage layouts between contract versions are consistent to prevent data corruption and unpredictable behavior. |    |    | ✓  |     |
| S1.1.B7      | Ensure that immutable variables are consistent across implementations during proxy upgrades. |    |    | ✓  |     |
| S1.1.B8      | Verify that implementations of the same logic across different parts of the contract are consistent to avoid introducing errors or vulnerabilities. |    |    | ✓  |     |
| S1.1.B9      | Ensure that ETH and WETH are handled separately with appropriate checks to avoid errors due to incorrect assumptions about exclusivity. |    |    | ✓  |     |
| S1.1.B10     | Verify that contracts with constructors are not used in a proxy setup, and initializer logic is used instead. |    |    | ✓  |     |
