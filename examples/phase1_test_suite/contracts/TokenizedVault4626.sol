// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract TokenizedVault4626 is ERC4626, Ownable {
    constructor(IERC20 asset_) ERC20("TokenizedVault", "TVLT") ERC4626(asset_) Ownable(msg.sender) {}
}
