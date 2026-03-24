// SPDX-License-Identifier: MIT
// SWC-104: Unchecked Call Return Value
// Source: SmartBugs Curated Dataset
pragma solidity ^0.4.24;

contract UncheckedSend {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: send() return value is not checked
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        // Bug: send() can fail silently, ETH is lost but balance is already decreased
        msg.sender.send(amount);
    }

    function getBalance() public view returns (uint) {
        return address(this).balance;
    }
}
