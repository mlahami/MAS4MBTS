# SCSVS-GOV-2

## S3.2 Tokenomics

### Control Objective
Ensure that tokens used within the smart contract ecosystem are securely implemented, including aspects such as value management, rebasing mechanisms, and reward systems. Contracts should prevent token vulnerabilities like double-spending, incorrect rewards, and improper fee handling.

### S3.2.A Economic Security of Tokens and Their Use Cases

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S3.2.A1      | Ensure that Merkle trees do not contain duplicate proofs, as this can lead to vulnerabilities like double-spending. |    | ✓  | ✓  |     |
| S3.2.A2      | Verify that DeFi protocols account for tokens with negative rebase mechanisms, ensuring that value changes and potential miscalculations are properly handled and mitigated. |    | ✓  | ✓  |     |
| S3.2.A3      | Verify that reward claims are correctly implemented to ensure users receive their correct rewards. |    | ✓  | ✓  |     |
| S3.2.A4      | Verify that tokens do not have vulnerabilities such as incorrect fee application or unexpected behavior due to token transfer issues. |    | ✓  | ✓  |     |
| S3.2.A5      | Verify that all claimable addresses are included in the hashing process for Merkle tree leaves to prevent attackers from claiming funds they should not. |    | ✓  | ✓  |     |