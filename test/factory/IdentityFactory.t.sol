// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { MockERC1271Wallet } from "../mocks/MockERC1271Wallet.sol";
import { Constants } from "../utils/Constants.sol";
import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
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

    // ============ AccessManager gating ============

    function test_createIdentity_revertWhenTypeNotOpened() public {
        uint256 unopenedType = 9999;
        vm.prank(deployer);
        onchainidSetup.idFactory.setIdentityTypeRole(unopenedType, 0);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.NotAuthorizedForIdentityType.selector, alice, unopenedType, uint64(0))
        );
        onchainidSetup.idFactory
            .createIdentityFor(
                david, unopenedType, "salt9999", _makeSingleMgmtKeys(david), new Structs.ModuleInstall[](0)
            );
    }

    function test_createIdentity_adminCanCreateClosedType() public {
        uint256 unopenedType = 9999;
        vm.startPrank(deployer);
        onchainidSetup.idFactory.setIdentityTypeRole(unopenedType, 0);
        onchainidSetup.idFactory.setCanDeployFor(unopenedType, true);
        vm.stopPrank();

        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentityFor(
                david, unopenedType, "saltAdminClosed", _makeSingleMgmtKeys(david), new Structs.ModuleInstall[](0)
            );
        assertTrue(identityAddr != address(0));
    }

    function test_createIdentity_nonAdminWithRoleCanCreate() public {
        uint64 issuerRole = 42;
        vm.startPrank(deployer);
        onchainidSetup.idFactory.setIdentityTypeRole(IdentityTypes.CLAIM_ISSUER, issuerRole);
        onchainidSetup.accessManager.grantRole(issuerRole, alice, 0);
        vm.stopPrank();

        Structs.KeyParam[] memory keys = _makeSingleMgmtKeys(david);
        vm.prank(alice);
        address identityAddr = onchainidSetup.idFactory
            .createIdentityFor(
                david, IdentityTypes.CLAIM_ISSUER, "saltAliceIssuer", keys, new Structs.ModuleInstall[](0)
            );
        assertTrue(identityAddr != address(0));
    }

    function test_setIdentityTypeRole_revertForNonAdmin() public {
        vm.prank(alice);
        vm.expectRevert();
        onchainidSetup.idFactory.setIdentityTypeRole(IdentityTypes.INDIVIDUAL, 7);
    }

    function test_setIdentityTypeRole_emitsEvent() public {
        vm.prank(deployer);
        vm.expectEmit(true, true, false, false, address(onchainidSetup.idFactory));
        emit IIdentityFactory.IdentityTypeRoleSet(IdentityTypes.INDIVIDUAL, 123);
        onchainidSetup.idFactory.setIdentityTypeRole(IdentityTypes.INDIVIDUAL, 123);
        assertEq(onchainidSetup.idFactory.getIdentityTypeRole(IdentityTypes.INDIVIDUAL), 123);
    }

    function test_setCanDeployFor_revertForNonAdmin() public {
        vm.prank(alice);
        vm.expectRevert();
        onchainidSetup.idFactory.setCanDeployFor(IdentityTypes.INDIVIDUAL, true);
    }

    // ============ createIdentityFor (validation) ============

    function test_revertBecauseAccountCannotBeZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(Errors.ZeroAddress.selector);
        onchainidSetup.idFactory
            .createIdentityFor(
                address(0),
                IdentityTypes.INDIVIDUAL,
                "salt1",
                _makeSingleMgmtKeys(address(0)),
                new Structs.ModuleInstall[](0)
            );
    }

    function test_revertBecauseSaltCannotBeEmpty() public {
        vm.prank(deployer);
        vm.expectRevert(Errors.EmptyString.selector);
        onchainidSetup.idFactory
            .createIdentityFor(
                david, IdentityTypes.INDIVIDUAL, "", _makeSingleMgmtKeys(david), new Structs.ModuleInstall[](0)
            );
    }

    function test_revertBecauseSaltAlreadyUsed() public {
        vm.prank(deployer);
        onchainidSetup.idFactory
            .createIdentityFor(
                carol, IdentityTypes.INDIVIDUAL, "saltUsed", _makeSingleMgmtKeys(carol), new Structs.ModuleInstall[](0)
            );

        vm.prank(deployer);
        vm.expectRevert(OZErrors.FailedDeployment.selector);
        onchainidSetup.idFactory
            .createIdentityFor(
                david, IdentityTypes.INDIVIDUAL, "saltUsed", _makeSingleMgmtKeys(david), new Structs.ModuleInstall[](0)
            );
    }

    function test_createIdentity_revertWhenAccountAlreadyBoundElsewhere() public {
        bytes memory aliceAcc = _asAccount(alice);
        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.WalletBoundToAnotherIdentity.selector, aliceAcc, address(aliceIdentity))
        );
        onchainidSetup.idFactory
            .createIdentityFor(
                alice, IdentityTypes.INDIVIDUAL, "newSalt", _makeSingleMgmtKeys(alice), new Structs.ModuleInstall[](0)
            );
    }

    function test_revertBecauseEmptyKeys() public {
        vm.prank(deployer);
        vm.expectRevert(Errors.EmptyListOfKeys.selector);
        onchainidSetup.idFactory
            .createIdentityFor(
                david, IdentityTypes.INDIVIDUAL, "salt1", new Structs.KeyParam[](0), new Structs.ModuleInstall[](0)
            );
    }

    function test_revertBecauseNoManagementKey() public {
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1);
        keys[0] = _makeECDSAKey(david, KeyPurposes.ACTION);
        vm.prank(deployer);
        vm.expectRevert(Errors.CannotRemoveLastManagementKey.selector);
        onchainidSetup.idFactory
            .createIdentityFor(david, IdentityTypes.INDIVIDUAL, "salt1", keys, new Structs.ModuleInstall[](0));
    }

    // ============ createIdentityFor auto-link ============

    function test_createIdentity_autoLinksAccountAsActive() public {
        bytes memory davidAcc = _asAccount(david);
        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentityFor(
                david, IdentityTypes.INDIVIDUAL, "davidSalt", _makeSingleMgmtKeys(david), new Structs.ModuleInstall[](0)
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
                david,
                IdentityTypes.INDIVIDUAL,
                "isFactorySalt",
                _makeSingleMgmtKeys(david),
                new Structs.ModuleInstall[](0)
            );
        assertTrue(onchainidSetup.idFactory.isFactoryIdentity(identityAddr));
    }

    // ============ linkAccount — EIP-712 EOA path ============

    function test_linkAccount_eoaSignerLinksThroughIdentity() public {
        bytes memory davidAcc = _asAccount(david);
        uint256 expiry = block.timestamp + 1 hours;
        uint256 nonce = onchainidSetup.idFactory.noncesForAccount(davidAcc);
        bytes memory sig = _signLink(davidPk, davidAcc, address(aliceIdentity), nonce, expiry);

        _execLink(aliceIdentity, alice, davidAcc, sig, nonce, expiry);

        assertEq(onchainidSetup.idFactory.getIdentity(davidAcc), address(aliceIdentity));
        assertEq(onchainidSetup.idFactory.noncesForAccount(davidAcc), nonce + 1);
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
        uint256 nonce = onchainidSetup.idFactory.noncesForAccount(davidAcc);
        bytes memory sig = _signLink(davidPk, davidAcc, address(aliceIdentity), nonce, expiry);

        _execLink(aliceIdentity, alice, davidAcc, sig, nonce, expiry);

        vm.prank(address(aliceIdentity));
        vm.expectRevert();
        onchainidSetup.idFactory.linkAccount(davidAcc, sig, nonce, expiry);
    }

    function test_linkAccount_revertSignatureNamesWrongIdentity() public {
        bytes memory davidAcc = _asAccount(david);
        uint256 expiry = block.timestamp + 1 hours;
        uint256 nonce = onchainidSetup.idFactory.noncesForAccount(davidAcc);
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
        uint256 nonce = onchainidSetup.idFactory.noncesForAccount(swAcc);
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
                new Structs.ModuleInstall[](0)
            );
    }

    // ============ Sticky binding & terminal revocation ============

    function test_revokeAccount_byIdentity_marksRevokedAndClearsActive() public {
        bytes memory davidAcc = _asAccount(david);
        uint256 expiry = block.timestamp + 1 hours;
        uint256 nonce = onchainidSetup.idFactory.noncesForAccount(davidAcc);
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
        uint256 nonce = onchainidSetup.idFactory.noncesForAccount(davidAcc);
        bytes memory sig = _signLink(davidPk, davidAcc, address(aliceIdentity), nonce, expiry);
        _execLink(aliceIdentity, alice, davidAcc, sig, nonce, expiry);

        vm.prank(address(bobIdentity));
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletNotLinkedToIdentity.selector, davidAcc));
        onchainidSetup.idFactory.revokeAccount(davidAcc);
    }

    function test_linkAccount_revertWhenWalletAlreadyRevoked() public {
        bytes memory davidAcc = _asAccount(david);
        uint256 expiry = block.timestamp + 1 hours;
        uint256 nonce = onchainidSetup.idFactory.noncesForAccount(davidAcc);
        bytes memory sig = _signLink(davidPk, davidAcc, address(aliceIdentity), nonce, expiry);
        _execLink(aliceIdentity, alice, davidAcc, sig, nonce, expiry);
        _execRevoke(aliceIdentity, alice, davidAcc);

        uint256 nonce2 = onchainidSetup.idFactory.noncesForAccount(davidAcc);
        uint256 expiry2 = block.timestamp + 1 hours;
        bytes memory sig2 = _signLink(davidPk, davidAcc, address(aliceIdentity), nonce2, expiry2);

        vm.prank(address(aliceIdentity));
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletAlreadyRevoked.selector, davidAcc));
        onchainidSetup.idFactory.linkAccount(davidAcc, sig2, nonce2, expiry2);
    }

    function test_linkAccount_revertWhenWalletBoundToAnotherIdentity() public {
        bytes memory davidAcc = _asAccount(david);
        uint256 expiry = block.timestamp + 1 hours;
        uint256 nonce = onchainidSetup.idFactory.noncesForAccount(davidAcc);
        bytes memory sig = _signLink(davidPk, davidAcc, address(aliceIdentity), nonce, expiry);
        _execLink(aliceIdentity, alice, davidAcc, sig, nonce, expiry);

        uint256 nonce2 = onchainidSetup.idFactory.noncesForAccount(davidAcc);
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
        uint256 nd = onchainidSetup.idFactory.noncesForAccount(davidAcc);
        _execLink(aliceIdentity, alice, davidAcc, _signLink(davidPk, davidAcc, address(aliceIdentity), nd, ex), nd, ex);
        uint256 nc = onchainidSetup.idFactory.noncesForAccount(carolAcc);
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
                david,
                IdentityTypes.SMART_CONTRACT,
                "saltSmartContract",
                _makeSingleMgmtKeys(david),
                new Structs.ModuleInstall[](0)
            );
        Identity identity = Identity(payable(identityAddr));
        assertEq(identity.getIdentityType(), IdentityTypes.SMART_CONTRACT);
    }

    function test_createIdentity_publicAuthorityType_shouldSetType() public {
        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentityFor(
                david,
                IdentityTypes.PUBLIC_AUTHORITY,
                "saltPublicAuth",
                _makeSingleMgmtKeys(david),
                new Structs.ModuleInstall[](0)
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
            initData: "",
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
                david,
                IdentityTypes.INDIVIDUAL,
                "saltFactoryKey",
                _makeSingleMgmtKeys(david),
                new Structs.ModuleInstall[](0)
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
        vm.startPrank(deployer);
        IdentityFactory badFactory = new IdentityFactory(address(badBeacon), address(am));
        badFactory.setIdentityTypeRole(IdentityTypes.INDIVIDUAL, type(uint64).max);
        badFactory.setCanDeployFor(IdentityTypes.INDIVIDUAL, true);
        vm.stopPrank();

        vm.expectRevert();
        badFactory.createIdentityFor(
            david, IdentityTypes.INDIVIDUAL, "salt1", _makeSingleMgmtKeys(david), new Structs.ModuleInstall[](0)
        );
    }

    // ============ createIdentity (self-deploy) ============

    function test_createIdentity_selfDeployByEoa() public {
        address eoa = makeAddr("selfDeployEoa");
        vm.prank(eoa);
        address identityAddr = onchainidSetup.idFactory
            .createIdentity(
                IdentityTypes.INDIVIDUAL, "selfDeploySalt", _makeSingleMgmtKeys(eoa), new Structs.ModuleInstall[](0)
            );
        assertTrue(identityAddr != address(0));
        assertEq(onchainidSetup.idFactory.getIdentity(_asAccount(eoa)), identityAddr, "self-deployer auto-linked");
    }

}
