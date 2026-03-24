// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IFlashBorrower {
    function onFlashLoan(uint256 amount) external;
}

contract VulnerableFlashLoan {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    // VULNERABLE: Flash loan with reentrancy vulnerability
    function flashLoan(uint256 amount) external {
        uint256 balanceBefore = address(this).balance;

        // Transfer funds to borrower
        payable(msg.sender).transfer(amount);

        // Callback - borrower can reenter here
        IFlashBorrower(msg.sender).onFlashLoan(amount);

        // Check repayment
        require(
            address(this).balance >= balanceBefore,
            "Flash loan not repaid"
        );
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        payable(msg.sender).transfer(amount);
    }
}
