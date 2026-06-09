// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { IdentityHelper } from "../helpers/IdentityHelper.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Errors as OZErrors } from "@openzeppelin/contracts/utils/Errors.sol";
import { Identity } from "contracts/Identity.sol";
import { IdFactory } from "contracts/factory/IdFactory.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Structs } from "contracts/storage/Structs.sol";
import { Test } from "forge-std/Test.sol";

contract TokenOidTest is Test {

    IdentityHelper.OnchainIDSetup internal setup;

    address internal deployer;
    address internal alice;
    address internal bob;

    Structs.ModuleInstall[] internal _modules;

    function setUp() public {
        deployer = makeAddr("tokenOidDeployer");
        alice = makeAddr("tokenOidAlice");
        bob = makeAddr("tokenOidBob");

        vm.startPrank(deployer);
        setup = IdentityHelper.deployFactory(deployer);
        vm.stopPrank();

        Structs.ModuleInstall[] memory defaults = IdentityHelper.defaultModules(setup);
        for (uint256 i = 0; i < defaults.length; i++) {
            _modules.push(defaults[i]);
        }
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

    // ============ addTokenFactory ============

    function test_addTokenFactory_revertNotOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        setup.idFactory.addTokenFactory(alice);
    }

    function test_addTokenFactory_revertZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(Errors.ZeroAddress.selector);
        setup.idFactory.addTokenFactory(address(0));
    }

    function test_addTokenFactory_shouldAdd() public {
        vm.prank(deployer);
        setup.idFactory.addTokenFactory(alice);
        assertTrue(setup.idFactory.isTokenFactory(alice));
    }

    function test_addTokenFactory_revertAlreadyFactory() public {
        vm.prank(deployer);
        setup.idFactory.addTokenFactory(alice);

        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.AlreadyAFactory.selector, alice));
        setup.idFactory.addTokenFactory(alice);
    }

    // ============ removeTokenFactory ============

    function test_removeTokenFactory_revertNotOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        setup.idFactory.removeTokenFactory(bob);
    }

    function test_removeTokenFactory_revertZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(Errors.ZeroAddress.selector);
        setup.idFactory.removeTokenFactory(address(0));
    }

    function test_removeTokenFactory_revertNotFactory() public {
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.NotAFactory.selector, bob));
        setup.idFactory.removeTokenFactory(bob);
    }

    function test_removeTokenFactory_shouldRemove() public {
        vm.prank(deployer);
        setup.idFactory.addTokenFactory(alice);

        vm.prank(deployer);
        setup.idFactory.removeTokenFactory(alice);
        assertFalse(setup.idFactory.isTokenFactory(alice));
    }

    // ============ createTokenIdentity ============

    function test_createTokenIdentity_revertNotAuthorized() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        setup.idFactory.createIdentity(alice, IdentityTypes.ASSET, "TST", _makeMgmtKey(alice), _modules);
    }

    function test_createTokenIdentity_revertTokenZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(Errors.ZeroAddress.selector);
        setup.idFactory.createIdentity(address(0), IdentityTypes.ASSET, "TST", _makeMgmtKey(alice), _modules);
    }

    /// @notice For a token identity, the factory auto-injects the token contract address
    ///         (`_account`) as a MANAGEMENT key. Empty user-supplied keys still produce a valid
    ///         identity — the token-as-MANAGEMENT key is unusable on its own (contracts don't
    ///         sign), so callers who want operational control supply their own keys via `_keys`.
    function test_createTokenIdentity_autoInjectsTokenAsManagement() public {
        vm.prank(deployer);
        address identity =
            setup.idFactory.createIdentity(alice, IdentityTypes.ASSET, "TST", new Structs.KeyParam[](0), _modules);
        bytes32 aliceKey = keccak256(abi.encodePacked(alice));
        assertTrue(
            Identity(payable(identity)).keyHasPurpose(aliceKey, KeyPurposes.MANAGEMENT),
            "token contract should be auto-injected as MANAGEMENT key"
        );
    }

    /// @notice Token factory should be able to create token identity
    function test_createTokenIdentity_viaTokenFactory_shouldCreate() public {
        vm.prank(deployer);
        setup.idFactory.addTokenFactory(alice);

        address token = makeAddr("tokenAddr");
        vm.prank(alice);
        address identity =
            setup.idFactory.createIdentity(token, IdentityTypes.ASSET, "factorySalt", _makeMgmtKey(bob), _modules);

        assertTrue(identity != address(0), "Identity should be deployed");
        assertEq(setup.idFactory.getIdentity(token), identity, "Token should map to identity");
        assertEq(setup.idFactory.getToken(identity), token, "Identity should map to token");
    }

    function test_createTokenIdentity_shouldCreateAndRevertDuplicate() public {
        vm.prank(deployer);
        setup.idFactory.createIdentity(alice, IdentityTypes.ASSET, "salt1", _makeMgmtKey(bob), _modules);

        address tokenIdentityAddr = setup.idFactory.getIdentity(alice);
        assertTrue(tokenIdentityAddr != address(0));
        assertEq(setup.idFactory.getToken(tokenIdentityAddr), alice);

        // Same salt should revert at Create3 with FailedDeployment() (bob's MANAGEMENT key is auto-injected).
        vm.prank(deployer);
        vm.expectRevert(OZErrors.FailedDeployment.selector);
        setup.idFactory.createIdentity(bob, IdentityTypes.ASSET, "salt1", new Structs.KeyParam[](0), _modules);

        // Same token address should revert (alice's MANAGEMENT key is auto-injected by the factory).
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.AccountAlreadyLinkedToIdentity.selector, alice));
        setup.idFactory.createIdentity(alice, IdentityTypes.ASSET, "salt2", new Structs.KeyParam[](0), _modules);
    }

    /// @notice createTokenIdentity with multiple key types should set all keys
    function test_createTokenIdentity_withMultipleKeys_shouldSetKeys() public {
        address claimAdder = makeAddr("tokenClaimAdder");

        Structs.KeyParam[] memory keys = new Structs.KeyParam[](2);
        keys[0] = _makeECDSAKey(bob, KeyPurposes.MANAGEMENT);
        keys[1] = _makeECDSAKey(claimAdder, KeyPurposes.CLAIM_ADDER);

        address token = makeAddr("tokenWithKeys");
        vm.prank(deployer);
        address identityAddr = setup.idFactory.createIdentity(token, IdentityTypes.ASSET, "saltKeys", keys, _modules);

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
