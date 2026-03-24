// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract TxOriginVulnerable {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    // VULNERABLE: Using tx.origin for authorization
    function withdraw() public {
        require(tx.origin == owner);
        msg.sender.transfer(address(this).balance);
    }

    function deposit() public payable {}
}
