# ERC-20 Knowledge

ERC-20 is a fungible token standard. The core state assets are balances, allowances, total supply, and privileged ownership or roles when the implementation includes minting, burning, pausing, or administrative operations.

## Typical Entry Points

- `transfer(address,uint256)`: moves tokens from the caller to another address.
- `transferFrom(address,address,uint256)`: moves tokens using an allowance granted by the source account.
- `approve(address,uint256)`: sets an allowance for a spender.
- `allowance(address,address)`: reads the allowance granted to a spender.
- `balanceOf(address)`: reads the token balance of an account.
- `mint(address,uint256)`: optional extension; creates new tokens and must be access-controlled.
- `burn(uint256)` or `burnFrom(address,uint256)`: optional extension; destroys tokens and must preserve supply and authorization rules.

## ERC-20-Specific Security Properties

- Only the token holder or an approved spender can move tokens.
- A transfer must preserve balance and total-supply invariants.
- Allowance spending must not exceed the approved amount.
- Privileged operations such as minting must be restricted to authorized actors.
- Approval changes must not enable unintended double spending through transaction ordering.
