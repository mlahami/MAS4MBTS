// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract CollectibleNFT is ERC721, Ownable {
    uint256 public nextTokenId;
    string private baseTokenURI;

    constructor() ERC721("CollectibleNFT", "CNFT") Ownable(msg.sender) {}

    function safeMint(address to) public onlyOwner {
        uint256 tokenId = nextTokenId;
        nextTokenId = tokenId + 1;
        _safeMint(to, tokenId);
    }

    function setBaseURI(string memory newBaseURI) public onlyOwner {
        baseTokenURI = newBaseURI;
    }

    function transferFrom(address from, address to, uint256 tokenId) public override {
        super.transferFrom(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) public override {
        super.safeTransferFrom(from, to, tokenId);
    }

    function setApprovalForAll(address operator, bool approved) public override {
        super.setApprovalForAll(operator, approved);
    }
}
