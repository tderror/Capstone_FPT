// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract Bank {
    mapping(address => uint256) public balanceOf;

    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balanceOf[msg.sender] >= amount);
        // VULNERABLE: State updated after external call
        msg.sender.call.value(amount)("");
        balanceOf[msg.sender] -= amount;
    }
}
