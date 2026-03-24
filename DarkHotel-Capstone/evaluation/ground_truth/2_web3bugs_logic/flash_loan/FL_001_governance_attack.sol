// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IToken {
    function balanceOf(address) external view returns (uint256);
}

contract VulnerableGovernance {
    IToken public token;

    struct Proposal {
        address target;
        bytes data;
        uint256 forVotes;
        uint256 againstVotes;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    uint256 public proposalCount;

    // VULNERABLE: Uses current balance for voting power
    function castVote(uint256 proposalId, bool support) external {
        require(!hasVoted[proposalId][msg.sender], "Already voted");

        // Attacker can flash loan tokens, vote, then return
        uint256 votes = token.balanceOf(msg.sender);

        if (support) {
            proposals[proposalId].forVotes += votes;
        } else {
            proposals[proposalId].againstVotes += votes;
        }

        hasVoted[proposalId][msg.sender] = true;
    }
}
