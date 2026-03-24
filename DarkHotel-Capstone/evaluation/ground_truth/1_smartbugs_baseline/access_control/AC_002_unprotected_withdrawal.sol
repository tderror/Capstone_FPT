// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract UnprotectedWithdrawal {
    mapping(address => uint) balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: Anyone can withdraw anyone's funds
    function withdraw(address to, uint amount) public {
        require(balances[to] >= amount);
        to.transfer(amount);
        balances[to] -= amount;
    }
}
