# SCSVS-CRYPTO-2

## S6.2 Signature Verification

### Control Objective
Implement cryptographic techniques that ensure the secure verification of signatures and compliance with standards to maintain the integrity of authenticated transactions.

### S6.2.A Cryptographic Techniques for Authentication

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S6.2.A1      | Ensure that cryptographic algorithms used for signature verification are secure and follow best practices. |    | ✓  | ✓  |     |

### S6.2.B Standard Compliance (e.g., EIP-712)

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S6.2.B1      | Verify that ECDSA signature handling functions, such as ECDSA.recover and ECDSA.tryRecover, properly manage signature formats to prevent signature malleability, especially when handling both traditional 65-byte and EIP-2098 compact signatures. |    | ✓  | ✓  |     |

