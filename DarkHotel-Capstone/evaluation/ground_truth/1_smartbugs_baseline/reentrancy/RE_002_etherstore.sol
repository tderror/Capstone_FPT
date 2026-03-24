// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract EtherStore {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds(uint _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);
        // VULNERABLE: Reentrancy - external call before state change
        require(msg.sender.call.value(_weiToWithdraw)());
        balances[msg.sender] -= _weiToWithdraw;
    }
}
