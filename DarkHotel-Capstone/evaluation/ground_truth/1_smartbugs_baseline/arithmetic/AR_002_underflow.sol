// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract IntegerUnderflow {
    mapping(address => uint256) public balances;

    constructor() public {
        balances[msg.sender] = 1000;
    }

    function withdraw(uint256 amount) public {
        // VULNERABLE: Underflow if amount > balance
        balances[msg.sender] -= amount;
        msg.sender.transfer(amount);
    }
}
