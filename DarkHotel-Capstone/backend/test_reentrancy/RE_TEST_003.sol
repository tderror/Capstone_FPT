// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

// EtherStore vulnerable pattern
contract EtherStore {
    mapping(address => uint256) public balances;

    function depositFunds() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds(uint256 _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);

        // VULNERABLE: send ETH before updating balance
        (bool success, ) = msg.sender.call{value: _weiToWithdraw}("");
        require(success, "Failed to send Ether");

        balances[msg.sender] -= _weiToWithdraw;
    }

    function collectEther() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0);

        // Another vulnerable pattern
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed");

        balances[msg.sender] = 0;
    }
}
