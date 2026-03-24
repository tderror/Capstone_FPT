// SPDX-License-Identifier: MIT
// SWC-104: Unchecked Call Return Value
// Source: SmartBugs Curated Dataset
pragma solidity ^0.4.24;

contract UncheckedCall {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    function deposit() public payable {}

    // VULNERABLE: low-level call return value not checked
    function forward(address target, bytes data) public {
        // Bug: call() can fail but execution continues
        target.call(data);
    }

    // VULNERABLE: call.value return value not checked
    function pay(address recipient, uint amount) public {
        require(msg.sender == owner);
        // Bug: if recipient rejects ETH, this silently fails
        recipient.call.value(amount)("");
    }
}
