// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { MockERC1271Wallet } from "../mocks/MockERC1271Wallet.sol";
import { Constants } from "../utils/Constants.sol";
import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import { MODULE_TYPE_VALIDATOR } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { UpgradeableBeacon } from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import { Errors as OZErrors } from "@openzeppelin/contracts/utils/Errors.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { Identity } from "contracts/Identity.sol";
import { IIdentityFactory } from "contracts/factory/IIdentityFactory.sol";
import { IdentityFactory } from "contracts/factory/IdentityFactory.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Structs } from "contracts/storage/Structs.sol";
import { Vm } from "forge-std/Vm.sol";
import { RevertingIdentity } from "test/mocks/RevertingIdentity.sol";

contract IdentityFactoryTest is OnchainIDSetup {

    bytes32 internal constant _LINK_ACCOUNT_TYPEHASH =
        keccak256("LinkAccount(bytes account,address identity,uint256 nonce,uint256 expiry)");

    // ---- generic helpers ----

    function _makeECDSAKey(address addr, uint256 purpose) internal pure returns (Structs.KeyParam memory) {
        return Structs.KeyParam({
            keyHash: keccak256(abi.encodePacked(addr)),
            purpose: purpose,
            keyType: KeyTypes.ECDSA,
            signerData: abi.encodePacked(addr),
            clientData: ""
        });
    }

    function _makeSingleMgmtKeys(address addr) internal pure returns (Structs.KeyParam[] memory keys) {
        keys = new Structs.KeyParam[](1);
        keys[0] = _makeECDSAKey(addr, KeyPurposes.MANAGEMENT);
    }

    /// @dev Minimal module bundle that satisfies Identity.initialize's "needs a validator
    ///      or an executor" invariant. Returns a fresh single-validator array each call so
    ///      tests don't share calldata-aliased state. `initData` seeds the validator's
    ///      per-account signer registry; factory tests don't sign through the validator,
    ///      so any 20-byte signer blob passes the length check (alice is a convenient EOA).
    function _defaultModules() internal view returns (Structs.ModuleInstall[] memory mods) {
        mods = new Structs.ModuleInstall[](1);
        mods[0] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_VALIDATOR,
            module: address(onchainidSetup.signatureValidator),
            initData: abi.encodePacked(alice),
            purpose: 0
        });
    }

    /// @dev Wrap an EVM address as the registry's bytes-shape (just abi.encodePacked).
    function _asAccount(address addr) internal pure returns (bytes memory) {
        return abi.encodePacked(addr);
    }

    function _domainSeparator(address verifyingContract) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("IdentityFactory")),
                keccak256(bytes("1")),
                block.chainid,
                verifyingContract
            )
        );
    }

    function _linkDigest(
        address verifyingContract,
        bytes memory account,
        address identity,
        uint256 nonce,
        uint256 expiry
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(_LINK_ACCOUNT_TYPEHASH, keccak256(account), identity, nonce, expiry));
        return MessageHashUtils.toTypedDataHash(_domainSeparator(verifyingContract), structHash);
    }

    function _signLink(uint256 signerPk, bytes memory account, address identity, uint256 nonce, uint256 expiry)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = _linkDigest(address(onchainidSetup.idFactory), account, identity, nonce, expiry);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _execLink(
        Identity identity,
        address mgmtKey,
        bytes memory account,
        bytes memory signature,
        uint256 nonce,
        uint256 expiry
    ) internal {
        bytes memory call = abi.encodeCall(IIdentityFactory.linkAccount, (account, signature, nonce, expiry));
        vm.prank(mgmtKey);
        IKeyExecutor(address(identity)).execute(address(onchainidSetup.idFactory), 0, call);
    }

    function _execRevoke(Identity identity, address mgmtKey, bytes memory account) internal {
        bytes memory call = abi.encodeCall(IIdentityFactory.revokeAccount, (account));
        vm.prank(mgmtKey);
        IKeyExecutor(address(identity)).execute(address(onchainidSetup.idFactory), 0, call);
    }

    // ============ constructor ============

    function test_revertBecauseAuthorityIsZeroAddress() public {
        vm.expectRevert(Errors.ZeroAddress.selector);
        new IdentityFactory(address(0), address(onchainidSetup.accessManager));
    }

    // ============ Per-identity-type gating ============

    /// @dev Configure a fresh AM role as the gate for an identity type. Keeps
    ///      `selfDeployable = true` so existing `createIdentityFor` tests aren't
    ///      affected by the self-deploy gate.
    function _restrictTypeToFreshRole(uint256 identityType) internal returns (uint64 role) {
        role = 999;
        vm.prank(deployer);
        onchainidSetup.idFactory.setIdentityTypePolicy(identityType, role, true);
    }

    function test_createIdentityFor_revertWhenCallerLacksTypeRole() public {
        _restrictTypeToFreshRole(IdentityTypes.CLAIM_ISSUER);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.NotAuthorizedForIdentityType.selector, alice, IdentityTypes.CLAIM_ISSUER, uint64(999)
            )
        );
        onchainidSetup.idFactory
            .createIdentityFor(
                david, IdentityTypes.CLAIM_ISSUER, "noRole", _makeSingleMgmtKeys(david), _defaultModules()
            );
    }

    function test_createIdentityFor_adminMustGrantSelfRoleToCall() public {
        uint64 role = _restrictTypeToFreshRole(IdentityTypes.CLAIM_ISSUER);

        // OZ AccessManager has no admin bypass on hasRole — admin sets the role graph
        // but must still hold the role to call.
        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.NotAuthorizedForIdentityType.selector, deployer, IdentityTypes.CLAIM_ISSUER, role
            )
        );
        onchainidSetup.idFactory
            .createIdentityFor(
                david, IdentityTypes.CLAIM_ISSUER, "adminNoRole", _makeSingleMgmtKeys(david), _defaultModules()
            );

        // Once admin grants themselves the role, the call succeeds.
        vm.prank(deployer);
        onchainidSetup.accessManager.grantRole(role, deployer, 0);
        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentityFor(
                david, IdentityTypes.CLAIM_ISSUER, "adminWithRole", _makeSingleMgmtKeys(david), _defaultModules()
            );
        assertTrue(identityAddr != address(0));
    }

    function test_createIdentityFor_nonAdminWithTypeRoleCanCall() public {
        uint64 role = _restrictTypeToFreshRole(IdentityTypes.CLAIM_ISSUER);

        vm.prank(deployer);
        onchainidSetup.accessManager.grantRole(role, alice, 0);

        Structs.KeyParam[] memory keys = _makeSingleMgmtKeys(david);
        vm.prank(alice);
        address identityAddr = onchainidSetup.idFactory
            .createIdentityFor(david, IdentityTypes.CLAIM_ISSUER, "aliceRole", keys, _defaultModules());
        assertTrue(identityAddr != address(0));
    }

    /// @notice Types registered with PUBLIC_ROLE are deployable by anyone.
    function test_createIdentityFor_publicRoleTypeIsOpen() public {
        // The test helper registers INDIVIDUAL with PUBLIC_ROLE at setUp.
        vm.prank(alice);
        address identityAddr = onchainidSetup.idFactory
            .createIdentityFor(
                david, IdentityTypes.INDIVIDUAL, "openType", _makeSingleMgmtKeys(david), _defaultModules()
            );
        assertTrue(identityAddr != address(0));
    }

    /// @notice Unregistered types revert. This closes the bypass where a caller could
    ///         pick a random uint and slip past the gating.
    function test_createIdentityFor_revertOnUnregisteredType() public {
        uint256 unknownType = 99999999;
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Errors.UnknownIdentityType.selector, unknownType));
        onchainidSetup.idFactory
            .createIdentityFor(david, unknownType, "unknown", _makeSingleMgmtKeys(david), _defaultModules());
    }

    /// @notice createIdentity reverts when the per-type policy has `selfDeployable = false`.
    ///         Closes the bypass where any EOA could self-mint a role-gated type and
    ///         sidestep the createIdentityFor role check.
    function test_createIdentity_revertsWhenNotSelfDeployable() public {
        vm.prank(deployer);
        onchainidSetup.idFactory.setIdentityTypePolicy(IdentityTypes.CLAIM_ISSUER, 999, false);

        address selfDeployer = makeAddr("selfIssuerEoa");
        vm.prank(selfDeployer);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.IdentityTypeNotSelfDeployable.selector, IdentityTypes.CLAIM_ISSUER)
        );
        onchainidSetup.idFactory
            .createIdentity(
                IdentityTypes.CLAIM_ISSUER, "selfIssuer", _makeSingleMgmtKeys(selfDeployer), _defaultModules()
            );
    }

    function test_setIdentityTypePolicy_emitsEventAndUpdatesView() public {
        vm.prank(deployer);
        vm.expectEmit(true, true, false, true, address(onchainidSetup.idFactory));
        emit IIdentityFactory.IdentityTypePolicySet(IdentityTypes.CLAIM_ISSUER, 123, false);
        onchainidSetup.idFactory.setIdentityTypePolicy(IdentityTypes.CLAIM_ISSUER, 123, false);
        (uint64 roleId, bool selfDeployable) =
            onchainidSetup.idFactory.getIdentityTypePolicy(IdentityTypes.CLAIM_ISSUER);
        assertEq(roleId, 123);
        assertEq(selfDeployable, false);
    }

    function test_setIdentityTypePolicy_revertForNonAdmin() public {
        vm.prank(alice);
        vm.expectRevert(); // AccessManagerUnauthorizedAccount
        onchainidSetup.idFactory.setIdentityTypePolicy(IdentityTypes.CLAIM_ISSUER, 7, true);
    }

    /// @notice createIdentity rejects unregistered types up front (same as createIdentityFor).
    function test_createIdentity_revertOnUnregisteredType() public {
        uint256 unknownType = 99999999;
        address selfDeployer = makeAddr("selfDeployerUnknownType");
        vm.prank(selfDeployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.UnknownIdentityType.selector, unknownType));
        onchainidSetup.idFactory
            .createIdentity(unknownType, "unknownSelf", _makeSingleMgmtKeys(selfDeployer), _defaultModules());
    }

    /// @notice createIdentity succeeds when the policy explicitly opts the type into self-deploy.
    function test_createIdentity_succeedsWhenSelfDeployable() public {
        vm.prank(deployer);
        onchainidSetup.idFactory.setIdentityTypePolicy(IdentityTypes.CLAIM_ISSUER, 999, true);

        address selfDeployer = makeAddr("selfIssuerOptedIn");
        vm.prank(selfDeployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentity(
                IdentityTypes.CLAIM_ISSUER, "selfIssuerOk", _makeSingleMgmtKeys(selfDeployer), _defaultModules()
            );
        assertTrue(identityAddr != address(0));
        assertEq(onchainidSetup.idFactory.getIdentity(_asAccount(selfDeployer)), identityAddr);
    }

    /// @notice The selfDeployable flag does not affect createIdentityFor. A type can be
    ///         open for admin-driven deploys while being closed to self-deploy.
    function test_createIdentityFor_unaffectedBySelfDeployable() public {
        uint64 publicRole = onchainidSetup.accessManager.PUBLIC_ROLE();
        vm.prank(deployer);
        onchainidSetup.idFactory.setIdentityTypePolicy(IdentityTypes.INDIVIDUAL, publicRole, false);

        vm.prank(alice);
        address identityAddr = onchainidSetup.idFactory
            .createIdentityFor(
                david, IdentityTypes.INDIVIDUAL, "selfDeployOffButForOk", _makeSingleMgmtKeys(david), _defaultModules()
            );
        assertTrue(identityAddr != address(0));
    }

    /// @notice Regression guard: ASSET-typed self-deploy must revert. Closes the bug where
    ///         any EOA could mint an ASSET identity bound to themselves.
    function test_createIdentity_assetTypeRevertsForEoa() public {
        // Apply the production policy for ASSET (matches DeployOnchainID defaults).
        uint64 publicRole = onchainidSetup.accessManager.PUBLIC_ROLE();
        vm.prank(deployer);
        onchainidSetup.idFactory.setIdentityTypePolicy(IdentityTypes.ASSET, publicRole, false);

        address eoa = makeAddr("eoaTryingToMintAsset");
        vm.prank(eoa);
        vm.expectRevert(abi.encodeWithSelector(Errors.IdentityTypeNotSelfDeployable.selector, IdentityTypes.ASSET));
        onchainidSetup.idFactory
            .createIdentity(IdentityTypes.ASSET, "assetEoa", _makeSingleMgmtKeys(eoa), _defaultModules());
    }

    // ============ createIdentityFor (validation) ============

    function test_revertBecauseAccountCannotBeZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(Errors.ZeroAddress.selector);
        onchainidSetup.idFactory
            .createIdentityFor(
                address(0), IdentityTypes.INDIVIDUAL, "salt1", _makeSingleMgmtKeys(address(0)), _defaultModules()
            );
    }

    function test_revertBecauseSaltCannotBeEmpty() public {
        vm.prank(deployer);
        vm.expectRevert(Errors.EmptyString.selector);
        onchainidSetup.idFactory
            .createIdentityFor(david, IdentityTypes.INDIVIDUAL, "", _makeSingleMgmtKeys(david), _defaultModules());
    }

    function test_revertBecauseSaltAlreadyUsed() public {
        // Same salt, keys, and modules deploy to the same address, so the second call collides.
        Structs.KeyParam[] memory keys = _makeSingleMgmtKeys(carol);
        Structs.ModuleInstall[] memory modules = _defaultModules();

        vm.prank(deployer);
        onchainidSetup.idFactory.createIdentityFor(carol, IdentityTypes.INDIVIDUAL, "saltUsed", keys, modules);

        vm.prank(deployer);
        vm.expectRevert(OZErrors.FailedDeployment.selector);
        onchainidSetup.idFactory.createIdentityFor(david, IdentityTypes.INDIVIDUAL, "saltUsed", keys, modules);
    }

    /// @notice Same _salt string with different keys yields a different identity address.
    ///         Closes the cross-chain front-running surface where someone reuses an
    ///         expected salt with their own keys to land on the victim's address.
    function test_createIdentityFor_sameSaltDifferentKeysGivesDifferentAddress() public {
        Structs.ModuleInstall[] memory modules = _defaultModules();

        vm.prank(deployer);
        address first = onchainidSetup.idFactory
            .createIdentityFor(carol, IdentityTypes.INDIVIDUAL, "saltShared", _makeSingleMgmtKeys(carol), modules);

        vm.prank(deployer);
        address second = onchainidSetup.idFactory
            .createIdentityFor(david, IdentityTypes.INDIVIDUAL, "saltShared", _makeSingleMgmtKeys(david), modules);

        assertTrue(first != address(0));
        assertTrue(second != address(0));
        assertTrue(first != second, "different bootstrap config must land at a different address");
    }

    function test_createIdentity_revertWhenAccountAlreadyBoundElsewhere() public {
        bytes memory aliceAcc = _asAccount(alice);
        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.WalletBoundToAnotherIdentity.selector, aliceAcc, address(aliceIdentity))
        );
        onchainidSetup.idFactory
            .createIdentityFor(
                alice, IdentityTypes.INDIVIDUAL, "newSalt", _makeSingleMgmtKeys(alice), _defaultModules()
            );
    }

    function test_revertBecauseEmptyKeys() public {
        vm.prank(deployer);
        vm.expectRevert(Errors.EmptyListOfKeys.selector);
        onchainidSetup.idFactory
            .createIdentityFor(david, IdentityTypes.INDIVIDUAL, "salt1", new Structs.KeyParam[](0), _defaultModules());
    }

    function test_revertBecauseNoManagementKey() public {
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1);
        keys[0] = _makeECDSAKey(david, KeyPurposes.ACTION);
        vm.prank(deployer);
        vm.expectRevert(Errors.NoManagementKeyInKeys.selector);
        onchainidSetup.idFactory.createIdentityFor(david, IdentityTypes.INDIVIDUAL, "salt1", keys, _defaultModules());
    }

    // ============ createIdentityFor auto-link ============

    function test_createIdentity_autoLinksAccountAsActive() public {
        bytes memory davidAcc = _asAccount(david);
        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentityFor(
                david, IdentityTypes.INDIVIDUAL, "davidSalt", _makeSingleMgmtKeys(david), _defaultModules()
            );

        assertEq(onchainidSetup.idFactory.getIdentity(davidAcc), identityAddr);
        assertEq(
            uint256(onchainidSetup.idFactory.getAccountStatus(davidAcc)), uint256(IIdentityFactory.AccountStatus.Active)
        );
        bytes[] memory accs = onchainidSetup.idFactory.getAccounts(identityAddr);
        assertEq(accs.length, 1);
        assertEq(keccak256(accs[0]), keccak256(davidAcc));
    }

    function test_createIdentity_setsIsFactoryIdentity() public {
        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentityFor(
                david, IdentityTypes.INDIVIDUAL, "isFactorySalt", _makeSingleMgmtKeys(david), _defaultModules()
            );
        assertTrue(onchainidSetup.idFactory.isFactoryIdentity(identityAddr));
    }

    // ============ linkAccount — EIP-712 EOA path ============

    function test_linkAccount_eoaSignerLinksThroughIdentity() public {
        bytes memory davidAcc = _asAccount(david);
        uint256 expiry = block.timestamp + 1 hours;
        uint256 nonce = onchainidSetup.idFactory.nonceForAccount(davidAcc);
        bytes memory sig = _signLink(davidPk, davidAcc, address(aliceIdentity), nonce, expiry);

        _execLink(aliceIdentity, alice, davidAcc, sig, nonce, expiry);

        assertEq(onchainidSetup.idFactory.getIdentity(davidAcc), address(aliceIdentity));
        assertEq(onchainidSetup.idFactory.nonceForAccount(davidAcc), nonce + 1);
    }

    function test_linkAccount_revertExpiredSignature() public {
        bytes memory davidAcc = _asAccount(david);
        uint256 expiry = block.timestamp - 1;
        bytes memory sig = _signLink(davidPk, davidAcc, address(aliceIdentity), 0, expiry);

        _execLink(aliceIdentity, alice, davidAcc, sig, 0, expiry);
        assertEq(
            uint256(onchainidSetup.idFactory.getAccountStatus(davidAcc)),
            uint256(IIdentityFactory.AccountStatus.None),
            "expired link must not register"
        );
    }

    function test_linkAccount_revertExpiryZero() public {
        bytes memory davidAcc = _asAccount(david);
        bytes memory sig = _signLink(davidPk, davidAcc, address(aliceIdentity), 0, 0);

        vm.prank(address(aliceIdentity));
        vm.expectRevert(abi.encodeWithSelector(Errors.ExpiredSignature.selector, uint256(0)));
        onchainidSetup.idFactory.linkAccount(davidAcc, sig, 0, 0);
    }

    function test_linkAccount_revertWrongNonce() public {
        bytes memory davidAcc = _asAccount(david);
        uint256 expiry = block.timestamp + 1 hours;
        bytes memory sig = _signLink(davidPk, davidAcc, address(aliceIdentity), 5, expiry);

        vm.prank(address(aliceIdentity));
        vm.expectRevert(); // OZ Nonces.InvalidAccountNonce
        onchainidSetup.idFactory.linkAccount(davidAcc, sig, 5, expiry);
    }

    function test_linkAccount_revertReplay() public {
        bytes memory davidAcc = _asAccount(david);
        uint256 expiry = block.timestamp + 1 hours;
        uint256 nonce = onchainidSetup.idFactory.nonceForAccount(davidAcc);
        bytes memory sig = _signLink(davidPk, davidAcc, address(aliceIdentity), nonce, expiry);

        _execLink(aliceIdentity, alice, davidAcc, sig, nonce, expiry);

        vm.prank(address(aliceIdentity));
        vm.expectRevert();
        onchainidSetup.idFactory.linkAccount(davidAcc, sig, nonce, expiry);
    }

    function test_linkAccount_revertSignatureNamesWrongIdentity() public {
        bytes memory davidAcc = _asAccount(david);
        uint256 expiry = block.timestamp + 1 hours;
        uint256 nonce = onchainidSetup.idFactory.nonceForAccount(davidAcc);
        bytes memory sig = _signLink(davidPk, davidAcc, address(bobIdentity), nonce, expiry);

        vm.prank(address(aliceIdentity));
        vm.expectRevert(Errors.InvalidSignature.selector);
        onchainidSetup.idFactory.linkAccount(davidAcc, sig, nonce, expiry);
    }

    // ============ linkAccount — ERC-1271 smart-wallet path ============

    function test_linkAccount_erc1271SmartWallet() public {
        MockERC1271Wallet sw = new MockERC1271Wallet(carol);
        bytes memory swAcc = _asAccount(address(sw));
        uint256 expiry = block.timestamp + 1 hours;
        uint256 nonce = onchainidSetup.idFactory.nonceForAccount(swAcc);
        bytes memory sig = _signLink(carolPk, swAcc, address(aliceIdentity), nonce, expiry);

        _execLink(aliceIdentity, alice, swAcc, sig, nonce, expiry);

        assertEq(onchainidSetup.idFactory.getIdentity(swAcc), address(aliceIdentity));
    }

    // ============ _isFactoryIdentity gate ============

    function test_linkAccount_revertWhenCallerIsNotFactoryIdentity() public {
        bytes memory davidAcc = _asAccount(david);
        uint256 expiry = block.timestamp + 1 hours;
        bytes memory sig = _signLink(davidPk, davidAcc, alice, 0, expiry);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Errors.NotFactoryIdentity.selector, alice));
        onchainidSetup.idFactory.linkAccount(davidAcc, sig, 0, expiry);
    }

    // ============ wallet / token collision (now via sticky binding) ============

    /// @notice Tokens and wallets share one keyspace. Re-using an address that's
    ///         already an ASSET identity's auto-linked wallet reverts via the
    ///         sticky-binding rule — no separate token-collision branch needed.
    function test_createIdentity_revertWhenAccountIsAlreadyToken() public {
        address existingTokenIdentity = onchainidSetup.idFactory.getIdentity(abi.encodePacked(Constants.TOKEN_ADDRESS));
        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(
                Errors.WalletBoundToAnotherIdentity.selector,
                abi.encodePacked(Constants.TOKEN_ADDRESS),
                existingTokenIdentity
            )
        );
        onchainidSetup.idFactory
            .createIdentityFor(
                Constants.TOKEN_ADDRESS,
                IdentityTypes.INDIVIDUAL,
                "tokenAsAccount",
                _makeSingleMgmtKeys(Constants.TOKEN_ADDRESS),
                _defaultModules()
            );
    }

    // ============ Sticky binding & terminal revocation ============

    function test_revokeAccount_byIdentity_marksRevokedAndClearsActive() public {
        bytes memory davidAcc = _asAccount(david);
        uint256 expiry = block.timestamp + 1 hours;
        uint256 nonce = onchainidSetup.idFactory.nonceForAccount(davidAcc);
        bytes memory sig = _signLink(davidPk, davidAcc, address(aliceIdentity), nonce, expiry);
        _execLink(aliceIdentity, alice, davidAcc, sig, nonce, expiry);

        _execRevoke(aliceIdentity, alice, davidAcc);

        assertEq(onchainidSetup.idFactory.getIdentity(davidAcc), address(0));
        (address bound, IIdentityFactory.AccountStatus status) =
            onchainidSetup.idFactory.getIdentityIncludingRevoked(davidAcc);
        assertEq(bound, address(aliceIdentity));
        assertEq(uint256(status), uint256(IIdentityFactory.AccountStatus.Revoked));

        bytes[] memory active = onchainidSetup.idFactory.getAccounts(address(aliceIdentity));
        assertEq(active.length, 1);
    }

    function test_revokeAccount_revertWhenCallerIsNotBoundIdentity() public {
        bytes memory davidAcc = _asAccount(david);
        uint256 expiry = block.timestamp + 1 hours;
        uint256 nonce = onchainidSetup.idFactory.nonceForAccount(davidAcc);
        bytes memory sig = _signLink(davidPk, davidAcc, address(aliceIdentity), nonce, expiry);
        _execLink(aliceIdentity, alice, davidAcc, sig, nonce, expiry);

        vm.prank(address(bobIdentity));
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletNotLinkedToIdentity.selector, davidAcc));
        onchainidSetup.idFactory.revokeAccount(davidAcc);
    }

    function test_linkAccount_revertWhenWalletAlreadyRevoked() public {
        bytes memory davidAcc = _asAccount(david);
        uint256 expiry = block.timestamp + 1 hours;
        uint256 nonce = onchainidSetup.idFactory.nonceForAccount(davidAcc);
        bytes memory sig = _signLink(davidPk, davidAcc, address(aliceIdentity), nonce, expiry);
        _execLink(aliceIdentity, alice, davidAcc, sig, nonce, expiry);
        _execRevoke(aliceIdentity, alice, davidAcc);

        uint256 nonce2 = onchainidSetup.idFactory.nonceForAccount(davidAcc);
        uint256 expiry2 = block.timestamp + 1 hours;
        bytes memory sig2 = _signLink(davidPk, davidAcc, address(aliceIdentity), nonce2, expiry2);

        vm.prank(address(aliceIdentity));
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletAlreadyRevoked.selector, davidAcc));
        onchainidSetup.idFactory.linkAccount(davidAcc, sig2, nonce2, expiry2);
    }

    function test_linkAccount_revertWhenWalletBoundToAnotherIdentity() public {
        bytes memory davidAcc = _asAccount(david);
        uint256 expiry = block.timestamp + 1 hours;
        uint256 nonce = onchainidSetup.idFactory.nonceForAccount(davidAcc);
        bytes memory sig = _signLink(davidPk, davidAcc, address(aliceIdentity), nonce, expiry);
        _execLink(aliceIdentity, alice, davidAcc, sig, nonce, expiry);

        uint256 nonce2 = onchainidSetup.idFactory.nonceForAccount(davidAcc);
        uint256 expiry2 = block.timestamp + 1 hours;
        bytes memory sig2 = _signLink(davidPk, davidAcc, address(bobIdentity), nonce2, expiry2);

        vm.prank(address(bobIdentity));
        vm.expectRevert(
            abi.encodeWithSelector(Errors.WalletBoundToAnotherIdentity.selector, davidAcc, address(aliceIdentity))
        );
        onchainidSetup.idFactory.linkAccount(davidAcc, sig2, nonce2, expiry2);
    }

    function test_revokeAccount_revertWhenNotActive() public {
        bytes memory davidAcc = _asAccount(david);
        vm.prank(address(aliceIdentity));
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletNotLinkedToIdentity.selector, davidAcc));
        onchainidSetup.idFactory.revokeAccount(davidAcc);
    }

    // ============ getAccounts pagination ============

    function test_getAccounts_paginated() public {
        bytes memory davidAcc = _asAccount(david);
        bytes memory carolAcc = _asAccount(carol);
        uint256 ex = block.timestamp + 1 hours;
        uint256 nd = onchainidSetup.idFactory.nonceForAccount(davidAcc);
        _execLink(aliceIdentity, alice, davidAcc, _signLink(davidPk, davidAcc, address(aliceIdentity), nd, ex), nd, ex);
        uint256 nc = onchainidSetup.idFactory.nonceForAccount(carolAcc);
        _execLink(aliceIdentity, alice, carolAcc, _signLink(carolPk, carolAcc, address(aliceIdentity), nc, ex), nc, ex);

        bytes[] memory all = onchainidSetup.idFactory.getAccounts(address(aliceIdentity));
        assertEq(all.length, 3);

        bytes[] memory page = onchainidSetup.idFactory.getAccounts(address(aliceIdentity), 1, 3);
        assertEq(page.length, 2);
    }

    // ============ unified token + wallet resolution ============

    /// @notice Tokens share the wallet keyspace — the same getIdentity(bytes) call works.
    function test_getIdentity_resolvesToken() public view {
        address identity = onchainidSetup.idFactory.getIdentity(abi.encodePacked(Constants.TOKEN_ADDRESS));
        assertTrue(identity != address(0));
    }

    function test_getIdentity_resolvesEvmWallet() public view {
        address identity = onchainidSetup.idFactory.getIdentity(_asAccount(alice));
        assertEq(identity, address(aliceIdentity));
    }

    function test_getIdentity_unknownWalletReturnsZero() public {
        assertEq(onchainidSetup.idFactory.getIdentity(_asAccount(makeAddr("unknown"))), address(0));
    }

    function test_getIdentity_unknownTokenReturnsZero() public {
        assertEq(onchainidSetup.idFactory.getIdentity(abi.encodePacked(makeAddr("unknownToken"))), address(0));
    }

    // ============ createIdentityFor with new identity types ============

    function test_createIdentity_smartContractType_shouldSetType() public {
        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentityFor(
                david, IdentityTypes.SMART_CONTRACT, "saltSmartContract", _makeSingleMgmtKeys(david), _defaultModules()
            );
        Identity identity = Identity(payable(identityAddr));
        assertEq(identity.getIdentityType(), IdentityTypes.SMART_CONTRACT);
    }

    function test_createIdentity_publicAuthorityType_shouldSetType() public {
        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentityFor(
                david, IdentityTypes.PUBLIC_AUTHORITY, "saltPublicAuth", _makeSingleMgmtKeys(david), _defaultModules()
            );
        Identity identity = Identity(payable(identityAddr));
        assertEq(identity.getIdentityType(), IdentityTypes.PUBLIC_AUTHORITY);
    }

    // ============ createIdentityFor with module installation ============

    function test_createIdentity_withModules_shouldInstallValidator() public {
        Structs.ModuleInstall[] memory modules = new Structs.ModuleInstall[](1);
        modules[0] = Structs.ModuleInstall({
            moduleType: 1, // MODULE_TYPE_VALIDATOR
            module: address(onchainidSetup.signatureValidator),
            initData: abi.encodePacked(david),
            purpose: 0
        });
        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentityFor(david, IdentityTypes.INDIVIDUAL, "saltWithModules", _makeSingleMgmtKeys(david), modules);

        Identity identity = Identity(payable(identityAddr));
        assertTrue(identity.isModuleInstalled(1, address(onchainidSetup.signatureValidator), ""));
    }

    // ============ Factory's own bootstrap key removed ============

    function test_createIdentity_factoryKeyRemoved() public {
        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentityFor(
                david, IdentityTypes.INDIVIDUAL, "saltFactoryKey", _makeSingleMgmtKeys(david), _defaultModules()
            );
        Identity identity = Identity(payable(identityAddr));
        assertFalse(
            identity.keyHasPurpose(
                ClaimSignerHelper.addressToKey(address(onchainidSetup.idFactory)), KeyPurposes.MANAGEMENT
            )
        );
    }

    // ============ CREATE3 failure ============

    function test_createIdentity_revertWhenCreate2Fails() public {
        RevertingIdentity revertingImpl = new RevertingIdentity();
        UpgradeableBeacon badBeacon = new UpgradeableBeacon(address(revertingImpl), deployer);

        AccessManager am = new AccessManager(deployer);
        IdentityFactory badFactory = new IdentityFactory(address(badBeacon), address(am));

        // deployer is AM admin — bypasses the `restricted` gate on createIdentityFor.
        vm.prank(deployer);
        vm.expectRevert();
        badFactory.createIdentityFor(
            david, IdentityTypes.INDIVIDUAL, "salt1", _makeSingleMgmtKeys(david), _defaultModules()
        );
    }

    // ============ createIdentity (self-deploy) ============

    function test_createIdentity_selfDeployByEoa() public {
        address eoa = makeAddr("selfDeployEoa");
        vm.prank(eoa);
        address identityAddr = onchainidSetup.idFactory
            .createIdentity(IdentityTypes.INDIVIDUAL, "selfDeploySalt", _makeSingleMgmtKeys(eoa), _defaultModules());
        assertTrue(identityAddr != address(0));
        assertEq(onchainidSetup.idFactory.getIdentity(_asAccount(eoa)), identityAddr, "self-deployer auto-linked");
    }

    // ============ IdentityInitialized event ============

    function test_createIdentity_emitsIdentityInitialized() public {
        address eoa = makeAddr("eventEoa");
        // Precompute the proxy address so we can scope vm.expectEmit to it.
        // Easier: emit-watch any address, then check after.
        vm.recordLogs();
        vm.prank(eoa);
        address identityAddr = onchainidSetup.idFactory
            .createIdentity(IdentityTypes.INDIVIDUAL, "evtSalt", _makeSingleMgmtKeys(eoa), _defaultModules());

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 expectedTopic0 = keccak256("IdentityInitialized(uint256)");
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == identityAddr && logs[i].topics[0] == expectedTopic0) {
                assertEq(uint256(logs[i].topics[1]), IdentityTypes.INDIVIDUAL, "type topic should match");
                found = true;
                break;
            }
        }
        assertTrue(found, "IdentityInitialized event not emitted by the new identity");
    }

}
