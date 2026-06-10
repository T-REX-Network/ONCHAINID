// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { IdentityHelper } from "../helpers/IdentityHelper.sol";
import { Errors as OZErrors } from "@openzeppelin/contracts/utils/Errors.sol";
import { Identity } from "contracts/Identity.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Structs } from "contracts/storage/Structs.sol";
import { Test } from "forge-std/Test.sol";

/// @notice Tests for the asset-identity (ex `createTokenIdentity`) path on {IdentityFactory}.
///         The legacy `addTokenFactory`/`removeTokenFactory`/`isTokenFactory` surface no longer
///         exists; "is this caller allowed to mint asset identities" is now a question for the
///         attached AccessManager. The deployer-as-admin can either mint asset identities
///         directly (because admins bypass the type role) or grant a `ROLE_TOKEN_FACTORY` to a
///         specific address and let that address mint.
contract TokenOidTest is Test {

    /// @dev Local role id used by tests that need a non-admin token-factory caller.
    uint64 internal constant ROLE_TOKEN_FACTORY = 1;

    IdentityHelper.OnchainIDSetup internal setup;

    address internal deployer;
    address internal alice;
    address internal bob;

    Structs.ModuleInstall[] internal _emptyModules;

    function setUp() public {
        deployer = makeAddr("tokenOidDeployer");
        alice = makeAddr("tokenOidAlice");
        bob = makeAddr("tokenOidBob");

        vm.startPrank(deployer);
        setup = IdentityHelper.deployFactory(deployer);
        vm.stopPrank();
    }

    // ---- helpers ----

    function _makeECDSAKey(address addr, uint256 purpose) internal pure returns (Structs.KeyParam memory) {
        return Structs.KeyParam({
            keyHash: keccak256(abi.encodePacked(addr)),
            purpose: purpose,
            keyType: KeyTypes.ECDSA,
            signerData: abi.encodePacked(addr),
            clientData: ""
        });
    }

    function _makeMgmtKey(address addr) internal pure returns (Structs.KeyParam[] memory keys) {
        keys = new Structs.KeyParam[](1);
        keys[0] = _makeECDSAKey(addr, KeyPurposes.MANAGEMENT);
    }

    /// @dev Switch the ASSET identity type from PUBLIC_ROLE (the default test-helper config) to
    ///      `ROLE_TOKEN_FACTORY`, mirroring a production deployment where only role holders may
    ///      mint asset identities.
    function _restrictAssetToTokenFactoryRole() internal {
        vm.prank(deployer);
        setup.idFactory.setIdentityTypeRole(IdentityTypes.ASSET, ROLE_TOKEN_FACTORY);
    }

    // ============ AccessManager-gated asset creation ============

    /// @notice Without the ASSET role, a non-admin caller cannot mint an asset identity.
    function test_createAssetIdentity_revertWhenCallerLacksRole() public {
        _restrictAssetToTokenFactoryRole();

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.NotAuthorizedForIdentityType.selector, alice, IdentityTypes.ASSET, ROLE_TOKEN_FACTORY
            )
        );
        setup.idFactory.createIdentityFor(alice, IdentityTypes.ASSET, "TST", _makeMgmtKey(alice), _emptyModules);
    }

    /// @notice Once granted the ASSET role, a non-admin caller can mint asset identities.
    function test_createAssetIdentity_succeedsWhenCallerHasRole() public {
        _restrictAssetToTokenFactoryRole();

        // deployer is the AccessManager admin; grant alice the ASSET role.
        vm.prank(deployer);
        setup.accessManager.grantRole(ROLE_TOKEN_FACTORY, alice, 0);

        address token = makeAddr("tokenAddr");
        vm.prank(alice);
        address identity = setup.idFactory
            .createIdentityFor(token, IdentityTypes.ASSET, "factorySalt", _makeMgmtKey(bob), _emptyModules);

        assertTrue(identity != address(0), "Identity should be deployed");
        assertEq(setup.idFactory.getTokenIdentity(token), identity, "Token should map to identity");
        assertEq(setup.idFactory.getToken(identity), token, "Identity should map to token");
    }

    /// @notice AccessManager admins are NOT auto-members of arbitrary roles. After the
    ///         deployer restricts ASSET to ROLE_TOKEN_FACTORY, they must grant themselves
    ///         that role explicitly to keep minting. This codifies least-privilege:
    ///         "admin" only governs the role graph; it does not bypass it.
    function test_createAssetIdentity_adminMustGrantSelfRoleToMint() public {
        _restrictAssetToTokenFactoryRole();

        address token = makeAddr("adminToken");

        // Without the role: the deployer (admin) cannot mint asset identities.
        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.NotAuthorizedForIdentityType.selector, deployer, IdentityTypes.ASSET, ROLE_TOKEN_FACTORY
            )
        );
        setup.idFactory.createIdentityFor(token, IdentityTypes.ASSET, "adminSalt", _makeMgmtKey(bob), _emptyModules);

        // Grant themselves the role, then minting works.
        vm.prank(deployer);
        setup.accessManager.grantRole(ROLE_TOKEN_FACTORY, deployer, 0);

        vm.prank(deployer);
        address identity = setup.idFactory
        .createIdentityFor(token, IdentityTypes.ASSET, "adminSalt", _makeMgmtKey(bob), _emptyModules);

        assertTrue(identity != address(0));
        assertEq(setup.idFactory.getTokenIdentity(token), identity);
    }

    // ============ createIdentity (ASSET) — basic validation ============

    function test_createAssetIdentity_revertTokenZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(Errors.ZeroAddress.selector);
        setup.idFactory.createIdentityFor(address(0), IdentityTypes.ASSET, "TST", _makeMgmtKey(alice), _emptyModules);
    }

    function test_createAssetIdentity_revertEmptySalt() public {
        vm.prank(deployer);
        vm.expectRevert(Errors.EmptyString.selector);
        setup.idFactory.createIdentityFor(alice, IdentityTypes.ASSET, "", _makeMgmtKey(alice), _emptyModules);
    }

    function test_createAssetIdentity_revertEmptyKeys() public {
        vm.prank(deployer);
        vm.expectRevert(Errors.EmptyListOfKeys.selector);
        setup.idFactory.createIdentityFor(alice, IdentityTypes.ASSET, "TST", new Structs.KeyParam[](0), _emptyModules);
    }

    /// @notice At least one MANAGEMENT key must be supplied — bootstrap removal rejects it otherwise.
    function test_createAssetIdentity_revertNoManagementKey() public {
        Structs.KeyParam[] memory actionOnly = new Structs.KeyParam[](1);
        actionOnly[0] = _makeECDSAKey(bob, KeyPurposes.ACTION);

        vm.prank(deployer);
        vm.expectRevert(Errors.CannotRemoveLastManagementKey.selector);
        setup.idFactory.createIdentityFor(alice, IdentityTypes.ASSET, "TST", actionOnly, _emptyModules);
    }

    function test_createAssetIdentity_shouldCreateAndRevertDuplicate() public {
        vm.prank(deployer);
        setup.idFactory.createIdentityFor(alice, IdentityTypes.ASSET, "salt1", _makeMgmtKey(bob), _emptyModules);

        address tokenIdentityAddr = setup.idFactory.getTokenIdentity(alice);
        assertTrue(tokenIdentityAddr != address(0));
        assertEq(setup.idFactory.getToken(tokenIdentityAddr), alice);

        // Same token address should revert before reaching Create3.
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.TokenAlreadyLinked.selector, alice));
        setup.idFactory.createIdentityFor(alice, IdentityTypes.ASSET, "salt2", _makeMgmtKey(alice), _emptyModules);

        // Same salt (with a different token) should revert at Create3 with FailedDeployment().
        vm.prank(deployer);
        vm.expectRevert(OZErrors.FailedDeployment.selector);
        setup.idFactory.createIdentityFor(bob, IdentityTypes.ASSET, "salt1", _makeMgmtKey(alice), _emptyModules);
    }

    /// @notice Asset identity with multiple key types should set all keys.
    function test_createAssetIdentity_withMultipleKeys_shouldSetKeys() public {
        address claimAdder = makeAddr("tokenClaimAdder");

        Structs.KeyParam[] memory keys = new Structs.KeyParam[](2);
        keys[0] = _makeECDSAKey(bob, KeyPurposes.MANAGEMENT);
        keys[1] = _makeECDSAKey(claimAdder, KeyPurposes.CLAIM_ADDER);

        address token = makeAddr("tokenWithKeys");
        vm.prank(deployer);
        address identityAddr =
            setup.idFactory.createIdentityFor(token, IdentityTypes.ASSET, "saltKeys", keys, _emptyModules);

        Identity identity = Identity(payable(identityAddr));

        assertTrue(
            identity.keyHasPurpose(ClaimSignerHelper.addressToKey(claimAdder), KeyPurposes.CLAIM_ADDER),
            "claimAdder should have CLAIM_ADDER purpose"
        );
        assertTrue(
            identity.keyHasPurpose(ClaimSignerHelper.addressToKey(bob), KeyPurposes.MANAGEMENT),
            "bob should have MANAGEMENT purpose"
        );
    }

}
