// SPDX-License-Identifier: MIT
// SWC-104: Unchecked Call Return Value
// Source: SmartBugs Curated Dataset - based on returnvalue.sol
pragma solidity ^0.4.24;

contract ReturnValue {
    address public callee;

    constructor(address _callee) public {
        callee = _callee;
    }

    // VULNERABLE: callchecked uses require (SAFE)
    function callchecked() public {
        require(callee.call());
    }

    // VULNERABLE: callnotchecked ignores return value
    function callnotchecked() public {
        // Bug: return value of call is discarded
        callee.call();
    }
}
