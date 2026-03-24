/*
 * @source: https://github.com/SmartContractSecurity/SWC-registry
 * @category: SAFE (fixed version of SWC-101 vulnerable contract)
 * @fix: Uses SafeMath mul() with require(c / a == b) check
 */

//Single transaction overflow
//Post-transaction effect: overflow escapes to publicly-readable storage
//Safe version

pragma solidity ^0.4.19;

contract IntegerOverflowMul {
    uint public count = 2;

    function run(uint256 input) public {
        count = mul(count, input);
    }

    //from SafeMath
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
      if (a == 0) {
        return 0;
      }

      uint256 c = a * b;
      require(c / a == b);

      return c;
    }
}
