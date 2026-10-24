// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { InteroperableAddress } from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import { IIdentityFactory } from "contracts/factory/IIdentityFactory.sol";
import { IdentityFactory } from "contracts/factory/IdentityFactory.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Structs } from "contracts/storage/Structs.sol";

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";

/// @notice Once a type's single-binding flag is true it stays true, including before any
///         identity of that type exists. The role and the self-deploy flag can still change.
///         A signing type is not locked.
contract SingleBindingPolicyTest is OnchainIDSetup {

    function test_singleBindingFlagCannotBeCleared() public {
        (address asset, bytes memory tokenEnvelope) = _freshAsset("clear");
        (uint64 roleId, bool selfDeployable,,) = _factory().getIdentityTypePolicy(IdentityTypes.ASSET);

        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.SingleBindingPolicyLocked.selector, IdentityTypes.ASSET));
        _factory().setIdentityTypePolicy(IdentityTypes.ASSET, roleId, selfDeployable, false);

        _assertActiveBinding(asset, tokenEnvelope);

        // Revoke reads the flag on the identity's type. It is still true.
        vm.prank(asset);
        vm.expectRevert(abi.encodeWithSelector(Errors.CannotRevokeFromNonSigningIdentity.selector, asset));
        _factory().revokeAccount(tokenEnvelope);
        _assertActiveBinding(asset, tokenEnvelope);
    }

    function test_singleBindingFlagCannotBeRemoved() public {
        (address asset, bytes memory tokenEnvelope) = _freshAsset("remove");

        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.SingleBindingPolicyLocked.selector, IdentityTypes.ASSET));
        _factory().removeIdentityTypePolicy(IdentityTypes.ASSET);

        (,,, bool registered) = _factory().getIdentityTypePolicy(IdentityTypes.ASSET);
        assertTrue(registered);
        assertEq(_factory().identityTypeOf(asset), IdentityTypes.ASSET);
        _assertActiveBinding(asset, tokenEnvelope);
    }

    /// @notice Role 7 is a real restricted role. The single-binding role in the test
    ///         setup is one below the public role, so incrementing it would trip the
    ///         public-role check instead of this one.
    function test_roleCanChangeWhileTheFlagStaysTrue() public {
        (uint64 roleId, bool selfDeployable,,) = _factory().getIdentityTypePolicy(IdentityTypes.ASSET);
        assertTrue(roleId != 7);

        vm.prank(deployer);
        _factory().setIdentityTypePolicy(IdentityTypes.ASSET, 7, !selfDeployable, true);

        (uint64 newRole, bool newSelfDeployable, bool singleBinding, bool registered) =
            _factory().getIdentityTypePolicy(IdentityTypes.ASSET);
        assertEq(newRole, 7);
        assertEq(newSelfDeployable, !selfDeployable);
        assertTrue(singleBinding);
        assertTrue(registered);
    }

    function test_signingTypePolicyCanStillChangeAndBeRemoved() public {
        vm.prank(deployer);
        _factory().setIdentityTypePolicy(IdentityTypes.INDIVIDUAL, 7, true, false);

        (uint64 roleId,, bool singleBinding, bool registered) =
            _factory().getIdentityTypePolicy(IdentityTypes.INDIVIDUAL);
        assertEq(roleId, 7);
        assertFalse(singleBinding);
        assertTrue(registered);

        vm.prank(deployer);
        _factory().removeIdentityTypePolicy(IdentityTypes.INDIVIDUAL);
        (,,, registered) = _factory().getIdentityTypePolicy(IdentityTypes.INDIVIDUAL);
        assertFalse(registered);
    }

    /// @notice No identity of this type is deployed. Setting the flag is what locks it.
    function test_flagLocksAsSoonAsItIsSetTrue() public {
        (uint64 roleId, bool selfDeployable, bool singleBinding, bool registered) =
            _factory().getIdentityTypePolicy(IdentityTypes.PUBLIC_AUTHORITY);
        assertFalse(singleBinding);
        assertTrue(registered);

        vm.prank(deployer);
        _factory().setIdentityTypePolicy(IdentityTypes.PUBLIC_AUTHORITY, 7, selfDeployable, true);

        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.SingleBindingPolicyLocked.selector, IdentityTypes.PUBLIC_AUTHORITY)
        );
        _factory().setIdentityTypePolicy(IdentityTypes.PUBLIC_AUTHORITY, roleId, selfDeployable, false);

        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.SingleBindingPolicyLocked.selector, IdentityTypes.PUBLIC_AUTHORITY)
        );
        _factory().removeIdentityTypePolicy(IdentityTypes.PUBLIC_AUTHORITY);

        (uint64 lockedRole,, bool lockedBinding, bool stillRegistered) =
            _factory().getIdentityTypePolicy(IdentityTypes.PUBLIC_AUTHORITY);
        assertEq(lockedRole, 7);
        assertTrue(lockedBinding);
        assertTrue(stillRegistered);
    }

    function _freshAsset(string memory salt) internal returns (address asset, bytes memory tokenEnvelope) {
        address token = makeAddr(salt);
        vm.prank(deployer);
        asset = _factory().createIdentityFor(token, IdentityTypes.ASSET, salt, _keys(tokenOwner));
        tokenEnvelope = InteroperableAddress.formatEvmV1(block.chainid, token);
        _assertActiveBinding(asset, tokenEnvelope);
    }

    function _assertActiveBinding(address asset, bytes memory tokenEnvelope) internal view {
        (address resolved, IIdentityFactory.AccountStatus status) =
            _factory().getIdentityIncludingRevoked(tokenEnvelope);
        assertEq(resolved, asset);
        assertEq(uint256(status), uint256(IIdentityFactory.AccountStatus.Active));
        assertEq(_factory().getAccountsCount(asset), 1);
        assertEq(_factory().getIdentity(tokenEnvelope), asset);
    }

    function _factory() internal view returns (IdentityFactory) {
        return onchainidSetup.idFactory;
    }

    function _keys(address account) internal pure returns (Structs.KeyParam[] memory keys) {
        bytes memory signer = abi.encodePacked(account);
        keys = new Structs.KeyParam[](1);
        keys[0] = Structs.KeyParam({
            keyHash: keccak256(signer),
            purpose: KeyPurposes.MANAGEMENT,
            keyType: KeyTypes.ECDSA,
            signerData: signer,
            clientData: ""
        });
    }

}
