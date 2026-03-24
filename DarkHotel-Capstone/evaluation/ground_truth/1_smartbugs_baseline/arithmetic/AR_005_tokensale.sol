// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract TokenSale {
    mapping(address => uint256) public balances;
    uint256 constant PRICE = 1 ether;
    uint256 constant TOKENS_PER_ETH = 1000;

    function buy(uint256 numTokens) public payable {
        // VULNERABLE: numTokens * PRICE can overflow
        require(msg.value == numTokens * PRICE / TOKENS_PER_ETH);
        balances[msg.sender] += numTokens;
    }

    function sell(uint256 numTokens) public {
        require(balances[msg.sender] >= numTokens);
        balances[msg.sender] -= numTokens;
        msg.sender.transfer(numTokens * PRICE / TOKENS_PER_ETH);
    }
}
