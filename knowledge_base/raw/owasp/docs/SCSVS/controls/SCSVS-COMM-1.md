# SCSVS-COMM-1


## S5.1 Contract Interactions

### Control Objective
Ensure that all interactions between contracts are secure, minimizing risks associated with external calls, maintaining a minimal trusted surface, and handling errors appropriately.

### S5.1.A Secure Message Passing

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S5.1.A1      | Ensure that calls to inherited functions from LzApp use recommended approaches (e.g., _lzSend) to avoid vulnerabilities associated with direct calls to lzEndpoint.send. |    | ✓  | ✓  |     |
| S5.1.A2      | Ensure that when interacting with external contracts, the msg.sender remains consistent to avoid security issues related to unexpected changes in sender context. |    | ✓  | ✓  |     |
| S5.1.A3      | Manage untrusted external contract calls to prevent unexpected results such as multiple withdrawals or out-of-order events. |    | ✓  | ✓  |     |
| S5.1.A4      | Missing verification of interacting pools can introduce risks. Ensure that all pools are properly verified before interaction to prevent potential security issues. |    | ✓  | ✓  |     |
| S5.1.A5      | Verify that the low-level .delegatecall() is properly managed, acknowledging that it converts the return value to a Boolean without providing the execution outcome. |    | ✓  | ✓  |     |

### S5.1.B Minimal Trusted Surface

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S5.1.B1      | Verify that the smart contract minimizes its trusted surface by only interacting with other contracts and systems through well-defined and limited interfaces. |    | ✓  | ✓  |     |
| S5.1.B2      | Ensure that the smart contract includes checks to validate the trustworthiness and authenticity of interacting parties before executing sensitive operations. |    | ✓  | ✓  |     |
| S5.1.B3      | Check that the smart contract's interactions are designed to avoid dependencies on external data or contracts that could compromise security. |    | ✓  | ✓  |     |
| S5.1.B4      | Verify that the contract handles failures or unexpected behaviors from external interactions gracefully to avoid cascading failures. |    | ✓  | ✓  |     |
| S5.1.B5      | Ensure that interactions with other contracts are monitored and audited to detect and address any unusual or unauthorized activities. |    | ✓  | ✓  |     |

