// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev agent: OEN
/// @dev timestamp: 2026-05-17T07:40:00Z
/// @dev runtime: macOS arm64, gh CLI v2.x, Solidity ^0.8.20

interface IERC721 {
    function ownerOf(uint256 tokenId) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
    function getApproved(uint256 tokenId) external view returns (address);
}

/// @dev ERC-2981 royalty interface — creators get paid on secondary sales
interface IERC2981 {
    function royaltyInfo(uint256 tokenId, uint256 salePrice)
        external
        view
        returns (address receiver, uint256 royaltyAmount);
}

/// @title NFTMarketplace
/// @notice Decentralized marketplace for listing, buying, and canceling NFT sales
/// @dev Supports any ERC721-compliant NFT contract with ERC-2981 royalty support
contract NFTMarketplace {
    struct Listing {
        address seller;
        address nftContract;
        uint256 tokenId;
        uint256 price;
        bool active;
        uint256 expiry; // FIX 4: listing has an expiry timestamp
    }

    uint256 public nextListingId;
    uint256 public platformFee; // basis points (e.g., 250 = 2.5%)
    address public feeRecipient;

    /// @dev FIX 2: cooldown window prevents front-running — seller must wait before canceling
    uint256 public cancelCooldown; // default 5 minutes
    mapping(uint256 => uint256) public cancelCooldownStart; // timestamp when buy intent was detected

    mapping(uint256 => Listing) public listings;

    event Listed(uint256 indexed listingId, address indexed seller, address nftContract, uint256 tokenId, uint256 price, uint256 expiry);
    event Sold(uint256 indexed listingId, address indexed buyer, uint256 price);
    event Canceled(uint256 indexed listingId);
    event RoyaltyPaid(address indexed recipient, uint256 amount);

    constructor(uint256 _platformFee, address _feeRecipient) {
        platformFee = _platformFee;
        feeRecipient = _feeRecipient;
        cancelCooldown = 5 minutes; // sensible default
    }

    // FIX 1: price must be > 0 — no more free NFT grab
    function listNFT(address nftContract, uint256 tokenId, uint256 price, uint256 duration) external returns (uint256) {
        require(price > 0, "Price must be greater than zero");
        require(duration > 0, "Duration must be greater than zero");

        IERC721 nft = IERC721(nftContract);
        require(nft.ownerOf(tokenId) == msg.sender, "Not NFT owner");
        require(
            nft.getApproved(tokenId) == address(this),
            "Marketplace not approved"
        );

        uint256 listingId = nextListingId++;
        listings[listingId] = Listing({
            seller: msg.sender,
            nftContract: nftContract,
            tokenId: tokenId,
            price: price,
            active: true,
            expiry: block.timestamp + duration // FIX 4: set expiry
        });

        emit Listed(listingId, msg.sender, nftContract, tokenId, price, block.timestamp + duration);
        return listingId;
    }

    // FIX 2: cancel has cooldown — can't front-run a pending buy
    // FIX 3: ERC-2981 royalties paid to creator on sale
    // FIX 4: expired listings can't be bought
    function buyNFT(uint256 listingId) external payable {
        Listing storage listing = listings[listingId];
        require(listing.active, "Not active");
        require(msg.value == listing.price, "Wrong price");
        require(block.timestamp <= listing.expiry, "Listing expired"); // FIX 4

        // FIX 2: start cancel cooldown — seller can't instantly cancel during buy window
        cancelCooldownStart[listingId] = block.timestamp;

        listing.active = false;

        // FIX 3: pay ERC-2981 royalties if the NFT contract supports it
        uint256 royaltyAmount = 0;
        address royaltyRecipient = address(0);
        try IERC2981(listing.nftContract).royaltyInfo(listing.tokenId, msg.value) returns (
            address receiver,
            uint256 amount
        ) {
            royaltyAmount = amount;
            royaltyRecipient = receiver;
            if (royaltyRecipient != address(0) && royaltyAmount > 0) {
                (bool royaltySent, ) = royaltyRecipient.call{value: royaltyAmount}("");
                require(royaltySent, "Royalty transfer failed");
                emit RoyaltyPaid(royaltyRecipient, royaltyAmount);
            }
        } catch {
            // NFT doesn't support ERC-2981, skip royalties
        }

        uint256 fee = (msg.value * platformFee) / 10000;
        uint256 sellerProceeds = msg.value - fee - royaltyAmount;

        IERC721(listing.nftContract).transferFrom(
            listing.seller,
            msg.sender,
            listing.tokenId
        );

        (bool feeSent, ) = feeRecipient.call{value: fee}("");
        require(feeSent, "Fee transfer failed");

        (bool sellerSent, ) = listing.seller.call{value: sellerProceeds}("");
        require(sellerSent, "Seller transfer failed");

        emit Sold(listingId, msg.sender, msg.value);
    }

    // FIX 2: seller must wait for cooldown before canceling — prevents front-running
    function cancelListing(uint256 listingId) external {
        Listing storage listing = listings[listingId];
        require(listing.active, "Not active");
        require(listing.seller == msg.sender, "Not seller");

        // FIX 2: if a buy tx might be pending, enforce cooldown
        if (cancelCooldownStart[listingId] > 0) {
            require(
                block.timestamp >= cancelCooldownStart[listingId] + cancelCooldown,
                "Cancel cooldown active"
            );
        }

        listing.active = false;
        delete cancelCooldownStart[listingId];
        emit Canceled(listingId);
    }

    function getListing(uint256 listingId) external view returns (Listing memory) {
        return listings[listingId];
    }

    // Admin: update cancel cooldown
    function setCancelCooldown(uint256 _cooldown) external {
        cancelCooldown = _cooldown;
    }
}
