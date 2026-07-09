// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract TokenizedVault4626 is ERC4626, Ownable {
    constructor(IERC20 asset_) ERC20("TokenizedVault", "TVLT") ERC4626(asset_) Ownable(msg.sender) {}

    function asset() public view override returns (address) {
        return super.asset();
    }

    function totalAssets() public view override returns (uint256) {
        return super.totalAssets();
    }

    function convertToShares(uint256 assets) public view override returns (uint256) {
        return super.convertToShares(assets);
    }

    function convertToAssets(uint256 shares) public view override returns (uint256) {
        return super.convertToAssets(shares);
    }

    function maxDeposit(address receiver) public view override returns (uint256) {
        return super.maxDeposit(receiver);
    }

    function previewDeposit(uint256 assets) public view override returns (uint256) {
        return super.previewDeposit(assets);
    }

    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        return super.deposit(assets, receiver);
    }

    function maxMint(address receiver) public view override returns (uint256) {
        return super.maxMint(receiver);
    }

    function previewMint(uint256 shares) public view override returns (uint256) {
        return super.previewMint(shares);
    }

    function mint(uint256 shares, address receiver) public override returns (uint256) {
        return super.mint(shares, receiver);
    }

    function maxWithdraw(address owner) public view override returns (uint256) {
        return super.maxWithdraw(owner);
    }

    function previewWithdraw(uint256 assets) public view override returns (uint256) {
        return super.previewWithdraw(assets);
    }

    function withdraw(uint256 assets, address receiver, address owner) public override returns (uint256) {
        return super.withdraw(assets, receiver, owner);
    }

    function maxRedeem(address owner) public view override returns (uint256) {
        return super.maxRedeem(owner);
    }

    function previewRedeem(uint256 shares) public view override returns (uint256) {
        return super.previewRedeem(shares);
    }

    function redeem(uint256 shares, address receiver, address owner) public override returns (uint256) {
        return super.redeem(shares, receiver, owner);
    }
}
