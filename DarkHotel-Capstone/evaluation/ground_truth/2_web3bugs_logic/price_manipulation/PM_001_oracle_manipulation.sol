// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

contract VulnerableOracle {
    IUniswapV2Pair public pair;

    constructor(address _pair) {
        pair = IUniswapV2Pair(_pair);
    }

    // VULNERABLE: Using spot price from AMM reserves
    function getPrice() public view returns (uint256) {
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        return (uint256(reserve0) * 1e18) / uint256(reserve1);
    }

    function borrow(uint256 collateralAmount) external {
        uint256 price = getPrice();
        uint256 borrowLimit = collateralAmount * price / 1e18;
        // Attacker can manipulate reserves with flash loan
        // then borrow more than collateral is worth
    }
}
