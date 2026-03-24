// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract ModifierReentrancy {
    mapping(address => uint) public tokenBalance;
    string constant name = "ModifierToken";

    modifier hasBalance {
        require(tokenBalance[msg.sender] > 0);
        _;
    }

    function airdrop() hasBalance public {
        // VULNERABLE: Modifier check before state update
        msg.sender.call.value(tokenBalance[msg.sender])();
        tokenBalance[msg.sender] = 0;
    }
}
