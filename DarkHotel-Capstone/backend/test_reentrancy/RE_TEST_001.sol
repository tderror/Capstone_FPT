// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

// Classic DAO-style reentrancy vulnerability
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");

        // VULNERABLE: External call before state update
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");

        // State update AFTER external call - CEI violation!
        balances[msg.sender] -= _amount;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
