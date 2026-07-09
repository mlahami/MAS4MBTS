# SCSVS-CODE-1

## S2.1 Development Policies

### Control Objective
Establish and enforce secure coding standards and review processes to minimize vulnerabilities and ensure best practices are followed throughout the development lifecycle.

### S2.1.A Secure Coding Standards

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S2.1.A1      | Ensure that developers do not use outdated compiler versions and adhere to the latest compiler recommendations. |    | ✓  | ✓  |     |
| S2.1.A2      | Verify that deprecated functions are not used in the code.                 |    | ✓  | ✓  |     |

### S2.1.B Code Review Processes

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S2.1.B1      | Verify that all smart contract code changes are reviewed by at least two independent developers with expertise in smart contract security before merging to the main branch. |    | ✓  | ✓  |     |
| S2.1.B2      | Ensure that code reviews of smart contracts involve automated static analysis tools specifically designed for smart contracts, and that all flagged issues are addressed or documented prior to merging. |    | ✓  | ✓  |     |
| S2.1.B3      | Check that the code review process for smart contracts includes a thorough analysis for vulnerabilities such as reentrancy attacks, integer overflows, and improper access control. |    | ✓  | ✓  |     |
| S2.1.B4      | Verify that code reviews include adherence to smart contract development standards, such as the use of safe math libraries and secure design patterns. |    | ✓  | ✓  |     |
| S2.1.B5      | Ensure that code reviews incorporate a checklist of common smart contract vulnerabilities, and that each item on the list is addressed before code is approved. |    | ✓  | ✓  |     |

