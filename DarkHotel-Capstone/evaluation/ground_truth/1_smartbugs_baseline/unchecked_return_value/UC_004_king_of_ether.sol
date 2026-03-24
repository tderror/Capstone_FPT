// SPDX-License-Identifier: MIT
// SWC-104: Unchecked Call Return Value
// Source: SmartBugs Curated Dataset - King of the Ether variant
pragma solidity ^0.4.24;

contract KingOfEther {
    address public king;
    uint public prize;

    constructor() public payable {
        king = msg.sender;
        prize = msg.value;
    }

    // VULNERABLE: send() return not checked - previous king may never receive ETH
    function claimThrone() public payable {
        require(msg.value > prize);

        address previousKing = king;
        uint previousPrize = prize;

        king = msg.sender;
        prize = msg.value;

        // Bug: if previousKing is a contract that rejects ETH,
        // send() returns false but is not checked
        previousKing.send(previousPrize);
    }

    function getBalance() public view returns (uint) {
        return address(this).balance;
    }
}
