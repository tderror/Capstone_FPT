// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract DefaultVisibility {
    address owner;

    constructor() public {
        owner = msg.sender;
    }

    // VULNERABLE: Missing visibility specifier (defaults to public)
    function _setOwner(address newOwner) {
        owner = newOwner;
    }

    function withdraw() public {
        require(msg.sender == owner);
        msg.sender.transfer(address(this).balance);
    }
}
