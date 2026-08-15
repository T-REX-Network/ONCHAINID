// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { Constants } from "../utils/Constants.sol";
import { IClaimIssuer } from "contracts/interface/IClaimIssuer.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Structs } from "contracts/storage/Structs.sol";

/// @notice Coverage for `addClaimTo`. The target's claim-key policy must be evaluated against the
///         issuer identity (the `_issuer` the flow authenticated), never against the shared
///         ERC734Validator singleton that physically carries the call.
contract ClaimToTest is OnchainIDSetup {

    uint256 internal constant TOPIC = Constants.CLAIM_TOPIC_42;

    event ClaimAddedTo(address indexed identity, uint256 topic, bytes signature, Structs.ClaimData data);

    /// @dev Signs a claim about `subject` with the issuer's CLAIM_SIGNER over the issuer's domain.
    function _buildIssuerClaim(address subject)
        internal
        view
        returns (bytes memory signature, Structs.ClaimData memory data)
    {
        data = Structs.ClaimData({ issuedAt: block.timestamp, validUntil: 0, payload: hex"1337" });
        signature = ClaimSignerHelper.signClaim(
            claimIssuerOwnerPk, claimIssuerOwner, address(claimIssuer), subject, TOPIC, data
        );
    }

    /// @dev Grants `purpose` for `grantee` on alice's identity, as alice.
    function _grantOnAlice(address grantee, uint256 purpose) internal {
        vm.prank(alice);
        aliceIdentity.addKeyWithData(
            ClaimSignerHelper.addressToKey(grantee), purpose, KeyTypes.ECDSA, abi.encodePacked(grantee), ""
        );
    }

    /// @notice The documented flow: the target grants CLAIM_SIGNER to the issuer identity, and the
    ///         issuer's manager pushes a claim through `addClaimTo`.
    function test_addClaimTo_writesClaim_whenTargetGrantsIssuerClaimSigner() public {
        _grantOnAlice(address(claimIssuer), KeyPurposes.CLAIM_SIGNER);
        (bytes memory signature, Structs.ClaimData memory data) = _buildIssuerClaim(address(aliceIdentity));

        vm.expectEmit(true, false, false, true);
        emit ClaimAddedTo(address(aliceIdentity), TOPIC, signature, data);
        vm.prank(claimIssuerOwner);
        IClaimIssuer(address(claimIssuer))
            .addClaimTo(TOPIC, 1, signature, data, "uri", IIdentity(address(aliceIdentity)));

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), TOPIC);
        (uint256 topic,, address issuer,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic, TOPIC);
        assertEq(issuer, address(claimIssuer));
    }

    /// @notice A CLAIM_ADDER grant for the issuer is also enough: `addClaim` accepts either
    ///         claim purpose for adds.
    function test_addClaimTo_writesClaim_whenTargetGrantsIssuerClaimAdder() public {
        _grantOnAlice(address(claimIssuer), KeyPurposes.CLAIM_ADDER);
        (bytes memory signature, Structs.ClaimData memory data) = _buildIssuerClaim(address(aliceIdentity));

        vm.prank(claimIssuerOwner);
        IClaimIssuer(address(claimIssuer))
            .addClaimTo(TOPIC, 1, signature, data, "uri", IIdentity(address(aliceIdentity)));

        bytes32 claimId = ClaimSignerHelper.computeClaimId(address(claimIssuer), TOPIC);
        (uint256 topic,,,,,) = IIdentity(address(aliceIdentity)).getClaim(claimId);
        assertEq(topic, TOPIC);
    }

    /// @notice A target that granted nothing rejects the issuer.
    function test_addClaimTo_reverts_whenTargetHasNoGrantForIssuer() public {
        (bytes memory signature, Structs.ClaimData memory data) = _buildIssuerClaim(address(bobIdentity));

        vm.prank(claimIssuerOwner);
        vm.expectRevert(Errors.SenderDoesNotHaveClaimSignerKey.selector);
        IClaimIssuer(address(claimIssuer)).addClaimTo(TOPIC, 1, signature, data, "uri", IIdentity(address(bobIdentity)));
    }

    /// @notice M-02 regression: a claim key granted to the shared module singleton must not admit
    ///         an issuer the target never authorized. Before the fix the singleton was the
    ///         ERC-2771 caller seen by the target, so this grant admitted every issuer at once.
    function test_addClaimTo_reverts_whenOnlySingletonHoldsClaimKey() public {
        _grantOnAlice(address(onchainidSetup.signatureValidator), KeyPurposes.CLAIM_SIGNER);
        (bytes memory signature, Structs.ClaimData memory data) = _buildIssuerClaim(address(aliceIdentity));

        vm.prank(claimIssuerOwner);
        vm.expectRevert(Errors.SenderDoesNotHaveClaimSignerKey.selector);
        IClaimIssuer(address(claimIssuer))
            .addClaimTo(TOPIC, 1, signature, data, "uri", IIdentity(address(aliceIdentity)));
    }

    /// @notice Only a MANAGEMENT key of the issuer identity may trigger `addClaimTo`.
    function test_addClaimTo_reverts_whenCallerLacksManagementOnIssuer() public {
        _grantOnAlice(address(claimIssuer), KeyPurposes.CLAIM_SIGNER);
        (bytes memory signature, Structs.ClaimData memory data) = _buildIssuerClaim(address(aliceIdentity));

        vm.prank(bob);
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        IClaimIssuer(address(claimIssuer))
            .addClaimTo(TOPIC, 1, signature, data, "uri", IIdentity(address(aliceIdentity)));
    }

}
