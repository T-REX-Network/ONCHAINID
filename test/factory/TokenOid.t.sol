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

/// @notice Tests for the asset-identity path on {IdentityFactory}. Whether a caller can
///         mint asset identities depends on the per-type role configured on the factory
///         via `setIdentityTypeRole`. ASSET is open by default; production deployments
///         gate it behind a TOKEN_FACTORY role.
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

    /// @dev Gate the ASSET type behind `ROLE_TOKEN_FACTORY`, mirroring a production
    ///      deployment where only registered token factories may mint asset identities.
    function _restrictAssetToTokenFactoryRole() internal {
        vm.prank(deployer);
        setup.idFactory.setIdentityTypeRole(IdentityTypes.ASSET, ROLE_TOKEN_FACTORY);
    }

    // ============ Per-identity-type gated asset creation ============

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

        vm.prank(deployer);
        setup.accessManager.grantRole(ROLE_TOKEN_FACTORY, alice, 0);

        address token = makeAddr("tokenAddr");
        vm.prank(alice);
        address identity = setup.idFactory
            .createIdentityFor(token, IdentityTypes.ASSET, "factorySalt", _makeMgmtKey(bob), _emptyModules);

        assertTrue(identity != address(0), "Identity should be deployed");
        assertEq(setup.idFactory.getIdentity(abi.encodePacked(token)), identity, "Token should map to identity");
        bytes[] memory accs = setup.idFactory.getAccounts(identity);
        assertEq(accs.length, 1, "Asset identity has exactly one wallet");
        assertEq(address(bytes20(accs[0])), token, "Identity's sole wallet is the token");
    }

    /// @notice AccessManager admins are NOT auto-members of arbitrary roles. After the
    ///         deployer gates ASSET behind ROLE_TOKEN_FACTORY, they must grant themselves
    ///         that role explicitly to keep minting.
    function test_createAssetIdentity_adminMustGrantSelfRoleToMint() public {
        _restrictAssetToTokenFactoryRole();

        address token = makeAddr("adminToken");

        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.NotAuthorizedForIdentityType.selector, deployer, IdentityTypes.ASSET, ROLE_TOKEN_FACTORY
            )
        );
        setup.idFactory.createIdentityFor(token, IdentityTypes.ASSET, "adminSalt", _makeMgmtKey(bob), _emptyModules);

        vm.prank(deployer);
        setup.accessManager.grantRole(ROLE_TOKEN_FACTORY, deployer, 0);

        vm.prank(deployer);
        address identity = setup.idFactory
        .createIdentityFor(token, IdentityTypes.ASSET, "adminSalt", _makeMgmtKey(bob), _emptyModules);

        assertTrue(identity != address(0));
        assertEq(setup.idFactory.getIdentity(abi.encodePacked(token)), identity);
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

        address tokenIdentityAddr = setup.idFactory.getIdentity(abi.encodePacked(alice));
        assertTrue(tokenIdentityAddr != address(0));
        bytes[] memory accs = setup.idFactory.getAccounts(tokenIdentityAddr);
        assertEq(accs.length, 1);
        assertEq(address(bytes20(accs[0])), alice);

        // Re-using the same token address now reverts via the wallet sticky-binding
        // rule (tokens and wallets share one keyspace), not the old token-collision error.
        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.WalletBoundToAnotherIdentity.selector, abi.encodePacked(alice), tokenIdentityAddr
            )
        );
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

    // ============ ACCESS_MANAGER as MGMT key (AssetID governance pattern) ============

    /// @dev Build a single MGMT key entry tagged as `ACCESS_MANAGER`. signerData is the AM
    ///      address packed as 20 bytes so its keyHash matches `keccak256(abi.encodePacked(am))`
    ///      (what `onlyManager` compares against when `msg.sender == am`).
    function _makeAccessManagerMgmtKey(address am) internal pure returns (Structs.KeyParam[] memory keys) {
        keys = new Structs.KeyParam[](1);
        keys[0] = Structs.KeyParam({
            keyHash: keccak256(abi.encodePacked(am)),
            purpose: KeyPurposes.MANAGEMENT,
            keyType: KeyTypes.ACCESS_MANAGER,
            signerData: abi.encodePacked(am),
            clientData: ""
        });
    }

    /// @notice An AssetID can be deployed with an AccessManager registered as its MANAGEMENT
    ///         key, tagged with the new `ACCESS_MANAGER` type so off-chain readers know the
    ///         key is a contract governed by a role table, not an EOA.
    function test_assetIdentity_canRegisterAccessManagerAsMgmtKey() public {
        address am = makeAddr("assetGovernor");
        address token = makeAddr("amGovernedToken");

        vm.prank(deployer);
        address identityAddr = setup.idFactory
            .createIdentityFor(token, IdentityTypes.ASSET, "amKey", _makeAccessManagerMgmtKey(am), _emptyModules);

        Identity identity = Identity(payable(identityAddr));
        bytes32 amKeyHash = keccak256(abi.encodePacked(am));

        (uint256[] memory purposes, uint256 keyType, bytes32 storedKey) = identity.getKey(amKeyHash);
        assertEq(keyType, KeyTypes.ACCESS_MANAGER, "key should be tagged ACCESS_MANAGER");
        assertEq(storedKey, amKeyHash, "stored key hash should match");
        assertEq(purposes.length, 1, "exactly one purpose");
        assertEq(purposes[0], KeyPurposes.MANAGEMENT, "the purpose is MANAGEMENT");
        assertTrue(identity.keyHasPurpose(amKeyHash, KeyPurposes.MANAGEMENT), "AM passes MANAGEMENT check");
    }

    /// @notice The AccessManager, registered as a MGMT key, can drive the AssetID directly.
    ///         `am.execute(identity, addKey(...))` lands at the identity with
    ///         `msg.sender == am`, satisfying `onlyManager`. We simulate that with vm.prank.
    function test_assetIdentity_accessManagerCanCallOnlyManager() public {
        address am = makeAddr("assetGovernor2");
        address token = makeAddr("amGovernedToken2");

        vm.prank(deployer);
        address identityAddr = setup.idFactory
            .createIdentityFor(token, IdentityTypes.ASSET, "amGov", _makeAccessManagerMgmtKey(am), _emptyModules);

        Identity identity = Identity(payable(identityAddr));

        // AM (as msg.sender) can add a new CLAIM_SIGNER key. This is what
        // `am.execute(identity, addKey(...))` produces on-chain.
        address claimSigner = makeAddr("claimSignerEoa");
        bytes32 claimSignerKey = keccak256(abi.encodePacked(claimSigner));

        vm.prank(am);
        identity.addKey(claimSignerKey, KeyPurposes.CLAIM_SIGNER, KeyTypes.ECDSA);

        assertTrue(
            identity.keyHasPurpose(claimSignerKey, KeyPurposes.CLAIM_SIGNER),
            "AM-added claim signer should be registered"
        );

        // An unrelated EOA holds no key on the identity and cannot drive it.
        address stranger = makeAddr("stranger");
        vm.prank(stranger);
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        identity.addKey(keccak256(abi.encodePacked(stranger)), KeyPurposes.CLAIM_SIGNER, KeyTypes.ECDSA);
    }

}
