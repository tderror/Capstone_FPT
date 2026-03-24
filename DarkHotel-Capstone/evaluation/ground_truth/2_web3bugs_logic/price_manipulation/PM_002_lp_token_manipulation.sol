// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPool {
    function getReserves() external view returns (uint256, uint256);
    function totalSupply() external view returns (uint256);
}

contract VulnerableLPValuation {
    IPool public pool;
    mapping(address => uint256) public collateral;

    // VULNERABLE: LP token valuation based on spot reserves
    function getLPValue(uint256 lpAmount) public view returns (uint256) {
        (uint256 r0, uint256 r1) = pool.getReserves();
        uint256 totalSupply = pool.totalSupply();

        // Value = (reserve0 + reserve1) * lpAmount / totalSupply
        // Attacker can donate to pool to inflate reserves
        return (r0 + r1) * lpAmount / totalSupply;
    }

    function depositCollateral(uint256 lpAmount) external {
        uint256 value = getLPValue(lpAmount);
        collateral[msg.sender] += value;
    }
}
