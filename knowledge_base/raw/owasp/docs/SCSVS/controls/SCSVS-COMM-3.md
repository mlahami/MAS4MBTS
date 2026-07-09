# SCSVS-COMM-3

## S5.3 Cross-Chain Interactions

### Control Objective
Ensure secure handling of external calls and atomic swaps during cross-chain interactions to maintain operational reliability and prevent fraud.

### S5.3.A Handling External Calls Securely

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S5.3.A1      | Ensure that parameters for Chainlink VRF (Verifiable Random Function) are thoroughly validated to prevent the fulfillRandomWord function from returning incorrect values instead of reverting. |    | ✓  | ✓  |     |
| S5.3.A2      | Implement robust security checks for cross-chain messaging to ensure correct permissions and intended functionality. |    | ✓  | ✓  |     |
| S5.3.A3      | Verify that contracts created using the CREATE opcode handle block reorganizations securely to prevent unexpected eliminations. |    | ✓  | ✓  |     |
| S5.3.A4      | Ensure robust cross-chain messaging security checks to prevent replay attacks where signatures valid on one chain might be exploited on another. |    | ✓  | ✓  |     |

### S5.3.B Atomic Swaps

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S5.3.B1      | Verify that the smart contract supports atomic swaps with robust mechanisms to ensure that swaps are completed successfully or not executed at all. |    | ✓  | ✓  |     |
| S5.3.B2      | Ensure that the smart contract includes checks to validate the atomic swap conditions and prevent partial or fraudulent swaps. |    | ✓  | ✓  |     |
| S5.3.B3      | Check that the smart contract handles potential failures or disputes in atomic swaps securely and fairly. |    | ✓  | ✓  |     |
| S5.3.B4      | Verify that the atomic swap functionality is tested thoroughly to cover various scenarios and edge cases. |    | ✓  | ✓  |     |

