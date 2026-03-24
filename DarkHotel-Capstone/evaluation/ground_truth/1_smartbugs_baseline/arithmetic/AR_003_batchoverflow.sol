// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract BatchOverflow {
    mapping(address => uint256) public balances;

    function batchTransfer(address[] receivers, uint256 value) public {
        // VULNERABLE: BatchOverflow - receivers.length * value can overflow
        uint256 amount = receivers.length * value;
        require(balances[msg.sender] >= amount);

        balances[msg.sender] -= amount;
        for (uint256 i = 0; i < receivers.length; i++) {
            balances[receivers[i]] += value;
        }
    }
}
