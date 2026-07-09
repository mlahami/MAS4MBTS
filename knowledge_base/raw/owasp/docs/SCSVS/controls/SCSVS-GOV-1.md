# SCSVS-GOV-1

## S3.1 Economic Models

### Control Objective
Ensure that economic models, including incentive structures and tokenomics, are designed and implemented in a way that secures value and incentivizes proper behavior within the ecosystem. Contracts should handle fluctuating token values and avoid creating opportunities for exploitation.

### S3.1.A Incentive Structures

| **SCSVS&nbsp;VR&nbsp;ID**          | Requirement                                                                 | L1 | L2 | L3 | SWE |
| ------------ | --------------------------------------------------------------------------- | -- | -- | -- | --- |
| S3.1.A1      | Ensure that the withdrawal process implements a pull-based approach rather than a push-based one to track accounting and allow users to pull payments. | ✓  | ✓  | ✓  |     |
| S3.1.A2      | The rate of cbETH to ETH can decrease, impacting users who hold or interact with cbETH. Ensure mechanisms are in place to handle fluctuations in conversion rates. |    | ✓  | ✓  |     |
| S3.1.A3      | Validators on the Ethereum 2.0 Beacon Chain can be penalized or slashed for misbehavior, which can affect the value of rETH. Ensure that these dynamics are considered in value assessments and interactions. |    | ✓  | ✓  |     |
| S3.1.A4      | The conversion rate between ETH and rETH might change over time based on the rewards accrued from staking. Ensure that these fluctuations are properly managed and captured. |    | ✓  | ✓  |     |
