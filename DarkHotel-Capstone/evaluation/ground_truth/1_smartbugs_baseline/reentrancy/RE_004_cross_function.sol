// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract CrossFunction {
    mapping(address => uint) public shares;
    mapping(address => uint) public withdrawalAmount;

    function deposit() public payable {
        shares[msg.sender] += msg.value;
    }

    function withdrawAll() public {
        uint amount = shares[msg.sender];
        // VULNERABLE: Cross-function reentrancy
        require(msg.sender.call.value(amount)());
        shares[msg.sender] = 0;
    }

    function transfer(address to, uint amount) public {
        // Can be called during reentrancy
        require(shares[msg.sender] >= amount);
        shares[msg.sender] -= amount;
        shares[to] += amount;
    }
}
