# SCSVS-ORACLE-2

## S7.2 Arithmetic Integrity

### Control Objective
Ensure that all calculations and logical operations within the smart contract are performed correctly to maintain data integrity and prevent manipulation.

### S7.2.A Secure Calculations and Logic

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SCWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S7.2.A1      | Ensure that price or rate calculations derived from asset balances are protected from manipulation, considering attack vectors like flash loans and donations. |    | ✓  | ✓  |     |
| S7.2.A2      | Ensure that the use of structs and arrays does not lead to data corruption or incorrect values due to storage encoding issues. |    | ✓  | ✓  |     |
| S7.2.A3      | Avoid operations that could lead to unintended data type conversions or precision loss by ensuring arithmetic operations are performed correctly. |    | ✓  | ✓  |     |
| S7.2.A4      | Enforce a minimum transaction amount to prevent attackers from clogging the network with zero amount or dust transactions. |    | ✓  | ✓  |     |
| S7.2.A5      | Validate that financial operations respect associative properties, ensuring consistent outcomes whether operations are performed in aggregate or iteratively. |    | ✓  | ✓  |     |
| S7.2.A6      | Implement proper rounding direction for calculations where accounting relies on user shares to avoid inaccuracies. |    | ✓  | ✓  |     |
| S7.2.A7      | Validate that inequalities and comparisons are correctly implemented to handle edge values appropriately. |    | ✓  | ✓  |     |
| S7.2.A8      | Ensure that abi.decode adheres to the type limits to avoid reverts due to overflow of target types. |    | ✓  | ✓  |     |
| S7.2.A9 | Ensure that logical operators such as `==`, `!=`, `&&`, `||`, and `!` are used correctly, especially when test coverage may be limited. |  | ✓  | ✓  |  |


### S7.2.B Precondition and Postcondition Checks

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SCWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S7.2.B1      | Ensure that multiplication is performed before division to maintain precision in calculations. |    | ✓  | ✓  |     |
| S7.2.B2      | Ensure that the request confirmation number is high enough to mitigate risks associated with chain re-orgs. |    | ✓  | ✓  |     |
| S7.2.B3      | Verify that off-by-one errors are avoided in loops and iterations, ensuring correct handling of list lengths and indexing. |    | ✓  | ✓  |     |
| S7.2.B4      | Verify that unsigned integers are not used to represent negative values, as this can lead to erroneous behavior. |    | ✓  | ✓  |     |
| S7.2.B5      | Verify that calculations with multiple terms handle all possible edge cases for min/max values to avoid errors. |    | ✓  | ✓  |     |

