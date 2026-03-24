// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract IntegerOverflow {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        // VULNERABLE: No overflow check
        balances[msg.sender] += msg.value;
    }

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount);
        // VULNERABLE: Potential overflow
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
