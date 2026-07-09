# SCSVS-BLOCK-1

## S8.1 Gas Limits

### Control Objective
Ensure that contract design and function implementations are efficient in gas usage to mitigate risks associated with out-of-gas errors and related vulnerabilities.

### S8.1.A Efficient Loop and Function Design

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S8.1.A1      | Ensure that contracts are protected against insufficient gas griefing attacks by carefully managing gas consumption in critical functions. |    | ✓  | ✓  |     |
| S8.1.A2      | Ensure that systems like the RocketDepositPool contract handle failures in functions like burn() gracefully. |    | ✓  | ✓  |     |
| S8.1.A3      | Verify that gas usage in functions and loops is efficient to avoid out-of-gas errors. |    | ✓  | ✓  |     |
| S8.1.A4      | Implement mechanisms to prevent denial of service attacks due to block gas limits, ensuring that transactions or operations do not exceed the gas limit constraints. |    | ✓  | ✓  |     |

### S8.1.B Fallback Mechanisms

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S8.1.B1      | Ensure that try/catch blocks are provided with adequate gas to avoid failures and unexpected behavior in case of errors. |    | ✓  | ✓  |     |

