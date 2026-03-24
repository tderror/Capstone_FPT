// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract WrongConstructor {
    address public owner;

    // VULNERABLE: Typo in constructor name (pre-0.4.22)
    function WrongConstructr() public {
        owner = msg.sender;
    }

    function withdraw() public {
        require(msg.sender == owner);
        msg.sender.transfer(address(this).balance);
    }
}
