/*
 * @source: https://github.com/SmartContractSecurity/SWC-registry
 * @category: SAFE (fixed version of SWC-101 vulnerable contract)
 * @fix: Uses SafeMath sub() with require(b <= a) check
 */

//Single transaction overflow
//Post-transaction effect: overflow escapes to publicly-readable storage
//Safe version

pragma solidity ^0.4.19;

contract IntegerOverflowMinimal {
    uint public count = 1;

    function run(uint256 input) public {
        count = sub(count,input);
    }

    //from SafeMath
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);//SafeMath uses assert here
        return a - b;
    }
}
