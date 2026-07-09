# SCSVS-BRIDGE-1

## S9.1 State Management

### Control Objective
Ensure efficient and secure handling of state within smart contracts to prevent data corruption and unexpected behavior.

### S9.1.A Efficient and Secure State Handling

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S9.1.A1      | Ensure that payable functions in contracts handle all ETH passed in msg.value and provide a mechanism for withdrawal to avoid ETH being locked in the contract. |    | ✓  | ✓  |     |
| S9.1.A2      | Verify that deleting a variable of a nested structure correctly resets all nested level fields to default values to avoid unexpected behavior. |    | ✓  | ✓  |     |
| S9.1.A3      | Verify that storage structs and arrays with types shorter than 32 bytes are handled correctly, avoiding data corruption when encoded directly from storage using the experimental ABIEncoderV2. |    | ✓  | ✓  |     |
| S9.1.A4      | Verify that storage arrays containing structs or other statically-sized arrays are properly read and encoded in external function calls to prevent data corruption. |    | ✓  | ✓  |     |
| S9.1.A5      | Ensure that copying bytes arrays from memory or calldata to storage handles empty arrays correctly, avoiding data corruption when the target array's length is increased subsequently without storing new data. |    | ✓  | ✓  |     |

### S9.1.B State Channels

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S9.1.B1      | Verify that global state updates are correctly handled when working with memory copies to ensure accurate state management. |    | ✓  | ✓  |     |


