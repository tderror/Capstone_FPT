// SPDX-License-Identifier: MIT
pragma solidity ^0.5.0;

// Reward distribution with reentrancy
contract RewardPool {
    mapping(address => uint256) public rewards;
    mapping(address => bool) public hasClaimedBonus;

    function addReward(address user, uint256 amount) external {
        rewards[user] += amount;
    }

    function claimReward() external {
        uint256 reward = rewards[msg.sender];
        require(reward > 0, "No reward");

        // VULNERABLE: External call before state update
        (bool success, ) = msg.sender.call.value(reward)("");
        require(success, "Transfer failed");

        rewards[msg.sender] = 0;
    }

    function claimBonus() external {
        require(!hasClaimedBonus[msg.sender], "Already claimed");
        uint256 bonus = rewards[msg.sender] / 10;

        // VULNERABLE: State update after call
        msg.sender.call.value(bonus)("");
        hasClaimedBonus[msg.sender] = true;
    }

    function() external payable {}
}
