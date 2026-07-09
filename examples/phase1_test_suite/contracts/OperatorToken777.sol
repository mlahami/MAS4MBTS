// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC777/ERC777.sol";

contract OperatorToken777 is ERC777 {
    constructor(address[] memory defaultOperators) ERC777("OperatorToken", "OPT", defaultOperators) {}

    function name() public view override returns (string memory) {
        return super.name();
    }

    function symbol() public view override returns (string memory) {
        return super.symbol();
    }

    function totalSupply() public view override returns (uint256) {
        return super.totalSupply();
    }

    function balanceOf(address holder) public view override returns (uint256) {
        return super.balanceOf(holder);
    }

    function granularity() public view override returns (uint256) {
        return super.granularity();
    }

    function defaultOperators() public view override returns (address[] memory) {
        return super.defaultOperators();
    }

    function isOperatorFor(address operator, address tokenHolder) public view override returns (bool) {
        return super.isOperatorFor(operator, tokenHolder);
    }

    function authorizeOperator(address operator) public override {
        super.authorizeOperator(operator);
    }

    function revokeOperator(address operator) public override {
        super.revokeOperator(operator);
    }

    function send(address recipient, uint256 amount, bytes memory data) public override {
        super.send(recipient, amount, data);
    }

    function operatorSend(
        address sender,
        address recipient,
        uint256 amount,
        bytes memory data,
        bytes memory operatorData
    ) public override {
        super.operatorSend(sender, recipient, amount, data, operatorData);
    }

    function burn(uint256 amount, bytes memory data) public override {
        super.burn(amount, data);
    }

    function operatorBurn(address account, uint256 amount, bytes memory data, bytes memory operatorData) public override {
        super.operatorBurn(account, amount, data, operatorData);
    }
}
