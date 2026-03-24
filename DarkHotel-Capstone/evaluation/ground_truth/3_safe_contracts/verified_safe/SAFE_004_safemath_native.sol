// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// SAFE: Solidity 0.8+ has built-in overflow checks
contract SafeMathNative {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        // SAFE: Native overflow protection in 0.8+
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        // SAFE: Will revert on underflow
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient");
        // SAFE: Checked math
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
