// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SafeCEIPattern {
    mapping(address => uint256) public balances;

    event Withdrawal(address indexed user, uint256 amount);

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // SAFE: Follows Checks-Effects-Interactions pattern
    function withdraw(uint256 amount) public {
        // Checks
        require(amount > 0, "Amount must be positive");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Effects (state changes BEFORE external call)
        balances[msg.sender] -= amount;

        // Interactions (external call AFTER state changes)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawal(msg.sender, amount);
    }
}
