// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

// Cross-function reentrancy
contract CrossFunctionReentrancy {
    mapping(address => uint256) public shares;
    mapping(address => uint256) public withdrawAllowance;

    function deposit() external payable {
        shares[msg.sender] += msg.value;
    }

    function withdrawAll() external {
        uint256 share = shares[msg.sender];
        require(share > 0, "No shares");

        // VULNERABLE: call.value before state update
        (bool success, ) = msg.sender.call.value(share)("");
        require(success);

        // Attacker can call transfer() during callback
        shares[msg.sender] = 0;
    }

    function transfer(address to, uint256 amount) external {
        // This can be called during reentrancy!
        require(shares[msg.sender] >= amount);
        shares[msg.sender] -= amount;
        shares[to] += amount;
    }
}
