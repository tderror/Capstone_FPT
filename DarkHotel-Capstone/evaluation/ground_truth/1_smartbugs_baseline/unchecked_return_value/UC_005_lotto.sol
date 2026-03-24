// SPDX-License-Identifier: MIT
// SWC-104: Unchecked Call Return Value
// Source: SmartBugs Curated Dataset - Lotto variant
pragma solidity ^0.4.24;

contract Lotto {
    address public owner;
    uint public jackpot;
    bool public payedOut;

    constructor() public payable {
        owner = msg.sender;
        jackpot = msg.value;
    }

    // VULNERABLE: send() return value not checked
    function sendToWinner(address winner) public {
        require(msg.sender == owner);
        require(!payedOut);

        // Bug: if winner is a contract that can't receive ETH,
        // send returns false, payedOut is set to true, and jackpot is locked forever
        winner.send(jackpot);
        payedOut = true;
    }

    // VULNERABLE: send() return value not checked
    function withdrawLeftOver() public {
        require(msg.sender == owner);
        require(payedOut);

        // Bug: unchecked send - owner may not receive remaining balance
        msg.sender.send(address(this).balance);
    }
}
