// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract UnprotectedSelfDestruct {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    // VULNERABLE: No access control on selfdestruct
    function kill() public {
        selfdestruct(msg.sender);
    }

    function deposit() public payable {}
}
