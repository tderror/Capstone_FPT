// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

// NFT marketplace with reentrancy in withdrawal
contract VulnerableMarketplace {
    mapping(address => uint256) public pendingWithdrawals;
    mapping(uint256 => address) public nftOwner;
    mapping(uint256 => uint256) public nftPrice;

    function listNFT(uint256 tokenId, uint256 price) external {
        nftOwner[tokenId] = msg.sender;
        nftPrice[tokenId] = price;
    }

    function buyNFT(uint256 tokenId) external payable {
        require(msg.value >= nftPrice[tokenId], "Insufficient payment");
        address seller = nftOwner[tokenId];

        pendingWithdrawals[seller] += msg.value;
        nftOwner[tokenId] = msg.sender;
    }

    function withdraw() external {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        // VULNERABLE: External call before zeroing balance
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update after external call!
        pendingWithdrawals[msg.sender] = 0;
    }

    receive() external payable {}
}
