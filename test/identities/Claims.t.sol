// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Structs } from "contracts/storage/Structs.sol";

/// @notice Coverage for ERC-735 claim management on an Identity (add, remove, get, isClaimValid).
contract ClaimsTest is OnchainIDSetup {

    uint256 internal claimTopic = uint256(keccak256(bytes("test")));

    function _claimData(bytes memory payload) internal view returns (Structs.ClaimData memory) {
        return Structs.ClaimData({ issuedAt: block.timestamp, validUntil: 0, payload: payload });
    }

    // ============ Dynamic field caps ============
    // Caps are checked before the issuer call, so the revert cases need no valid signature.

    function test_RevertAddClaim_WhenSignatureExceedsCap() public {
        bytes memory signature = new bytes(Structs.MAX_CLAIM_SIGNATURE_LENGTH + 1);

        vm.prank(alice);
        vm.expectRevert(Errors.ClaimSignatureTooLong.selector);
        IIdentity(address(aliceIdentity))
            .addClaim(claimTopic, 1, address(aliceIdentity), signature, _claimData("payload"), "uri");
    }

    function test_RevertAddClaim_WhenPayloadExceedsCap() public {
        bytes memory payload = new bytes(Structs.MAX_CLAIM_PAYLOAD_LENGTH + 1);

        vm.prank(alice);
        vm.expectRevert(Errors.ClaimPayloadTooLong.selector);
        IIdentity(address(aliceIdentity))
            .addClaim(claimTopic, 1, address(aliceIdentity), "sig", _claimData(payload), "uri");
    }

    function test_RevertAddClaim_WhenUriExceedsCap() public {
        string memory uri = string(new bytes(Structs.MAX_CLAIM_URI_LENGTH + 1));

        vm.prank(alice);
        vm.expectRevert(Errors.ClaimUriTooLong.selector);
        IIdentity(address(aliceIdentity))
            .addClaim(claimTopic, 1, address(aliceIdentity), "sig", _claimData("payload"), uri);
    }

    /// @notice A claim with payload and uri at the cap is accepted and stays removable.
    function test_AddClaim_AcceptsFieldsAtCap() public {
        Structs.ClaimData memory claimData = _claimData(new bytes(Structs.MAX_CLAIM_PAYLOAD_LENGTH));
        string memory uri = string(new bytes(Structs.MAX_CLAIM_URI_LENGTH));

        vm.prank(alice);
        aliceIdentity.addKey(ClaimSignerHelper.addressToKey(alice), KeyPurposes.CLAIM_SIGNER, KeyTypes.ECDSA);

        bytes memory signature = ClaimSignerHelper.signClaim(
            alicePk, alice, address(aliceIdentity), address(aliceIdentity), claimTopic, claimData
        );

        vm.prank(alice);
        bytes32 claimId = IIdentity(address(aliceIdentity))
            .addClaim(claimTopic, 1, address(aliceIdentity), signature, claimData, uri);

        (uint256 topic,,,, Structs.ClaimData memory data,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic, claimTopic);
        assertEq(data.payload.length, Structs.MAX_CLAIM_PAYLOAD_LENGTH);

        vm.prank(alice);
        assertTrue(IIdentity(address(aliceIdentity)).removeClaim(claimId));
    }

}
