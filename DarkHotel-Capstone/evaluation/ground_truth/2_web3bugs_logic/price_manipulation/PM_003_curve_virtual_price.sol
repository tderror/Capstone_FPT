// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ICurvePool {
    function get_virtual_price() external view returns (uint256);
    function remove_liquidity(uint256 amount, uint256[2] calldata min_amounts) external;
}

contract VulnerableCurveIntegration {
    ICurvePool public curvePool;
    mapping(address => uint256) public collateral;

    // VULNERABLE: Read-only reentrancy via get_virtual_price
    function getCollateralValue(address user) public view returns (uint256) {
        // During remove_liquidity callback, virtual_price is inflated
        return collateral[user] * curvePool.get_virtual_price() / 1e18;
    }

    function liquidate(address user) external {
        require(getCollateralValue(user) < getDebt(user), "Healthy");
        // Liquidation logic
    }

    function getDebt(address) internal pure returns (uint256) {
        return 1000e18;
    }
}
