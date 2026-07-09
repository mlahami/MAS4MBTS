# SCSVS-AUTH-2


## S4.2 Authorization Mechanisms

### Control Objective
Implement secure authorization mechanisms to safeguard critical functions and sensitive operations, ensuring only authorized entities can perform these actions.

### S4.2.A Secure Access to Critical Functions

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SCWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S4.2.A1      | Verify that the contract uses msg.sender for authorization instead of tx.origin to avoid vulnerabilities related to contracts that forward calls from legitimate users. |    | ✓  | ✓  |     |
| S4.2.A2      | Implement and verify appropriate access controls for functions that modify contract state or perform sensitive operations to prevent unauthorized access. |    | ✓  | ✓  |     |

### S4.2.B Timed Permissions

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SCWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S4.2.B1      | Ensure that msg.sender validation is properly implemented when using Merkle trees to maintain security and prevent unauthorized access. |    | ✓  | ✓  |     |
| S4.2.B2      | Use whitelisting to restrict interactions to a specific set of addresses, providing additional security against malicious actors. |    | ✓  | ✓  |     |
| S4.2.B3      | Ensure that functions modifying the contract state or accessing sensitive operations have proper access controls implemented. |    | ✓  | ✓  |     |


