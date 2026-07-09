# SCSVS-COMP-1

## S11.1 Tokens (ERC20, ERC721, ERC1155)

### Control Objective
Ensure secure implementation and management of token standards to prevent vulnerabilities.

### S11.1.A Secure Implementation and Management

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S11.1.A1     | Verify that the totalSupply value is consistent during token minting operations, ensuring that callbacks do not result in incorrect values. |    | ✓  | ✓  |     |
| S11.1.A2     | Some tokens have multiple addresses associated with them, which can introduce vulnerabilities. Ensure all token addresses are managed and verified securely to avoid related risks. |    | ✓  | ✓  |     |
| S11.1.A3     | Verify that tokens handle zero amount transfers properly to prevent issues in integrations and operations. |    | ✓  | ✓  |     |
| S11.1.A4     | Verify that tokens handle zero amount transfers properly to prevent issues in integrations and operations. |    | ✓  | ✓  |     |
| S11.1.A5     | Some tokens revert on the transfer of a zero amount, which can cause issues in certain integrations and operations. Ensure compatibility with such tokens to avoid integration problems. |    | ✓  | ✓  |     |
| S11.1.A6     | Not all ERC20 tokens comply with the EIP20 standard; some may not return a boolean flag or revert on failure. Verify compliance with the ERC20 standard to avoid compatibility issues. |    | ✓  | ✓  |     |


