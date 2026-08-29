// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { Structs } from "contracts/storage/Structs.sol";

/// @notice Coverage for ERC-735 claim management on an Identity (add, remove, get, isClaimValid).
contract ClaimsTest is OnchainIDSetup {

    uint256 internal claimTopic = uint256(keccak256(bytes("test")));

    /// @notice An outside issuer can accept the same claim again after a removal. That claim must
    ///         still be removable, so the second removal cannot trip on the marked digest.
    function test_RemoveClaim_ReAddedExternalIssuerClaim() public {
        ExternalIssuer issuer = new ExternalIssuer();
        Structs.ClaimData memory claimData = Structs.ClaimData({
            issuedAt: block.timestamp,
            validUntil: 0,
            metadataHash: ClaimSignerHelper.metadataHash(1, "uri"),
            payload: hex"0042"
        });

        vm.prank(alice);
        bytes32 claimId =
            IIdentity(address(aliceIdentity)).addClaim(claimTopic, 1, address(issuer), "sig", claimData, "uri");

        vm.prank(alice);
        assertTrue(IIdentity(address(aliceIdentity)).removeClaim(claimId));

        // this issuer never reads our revocations, so the same claim goes back on
        vm.prank(alice);
        IIdentity(address(aliceIdentity)).addClaim(claimTopic, 1, address(issuer), "sig", claimData, "uri");

        vm.prank(alice);
        assertTrue(IIdentity(address(aliceIdentity)).removeClaim(claimId));

        (uint256 topic,,,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic, 0);
    }

}

/// @notice Issuer with its own EIP-712 domain that accepts any claim and keeps no revocation state
///         in the validator.
contract ExternalIssuer is EIP712 {

    constructor() EIP712("ExternalIssuer", "1") { }

    function isClaimValid(IIdentity, uint256, bytes calldata, Structs.ClaimData calldata) external pure returns (bool) {
        return true;
    }

}
