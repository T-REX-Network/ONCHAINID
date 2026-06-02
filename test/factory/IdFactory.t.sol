// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { Constants } from "../utils/Constants.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Errors as OZErrors } from "@openzeppelin/contracts/utils/Errors.sol";
import { Identity } from "contracts/Identity.sol";
import { IdFactory } from "contracts/factory/IdFactory.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { ImplementationAuthority } from "contracts/proxy/ImplementationAuthority.sol";
import { Structs } from "contracts/storage/Structs.sol";
import { RevertingIdentity } from "test/mocks/RevertingIdentity.sol";

contract IdFactoryTest is OnchainIDSetup {

    // ---- helpers ----

    function _makeECDSAKey(address addr, uint256 purpose) internal pure returns (Structs.KeyParam memory) {
        // clientData is empty for ECDSA keys — only needed for non-ECDSA keys (e.g. WebAuthn credentialId)
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

    // ============ createIdentity ============

    function test_revertBecauseAuthorityIsZeroAddress() public {
        vm.expectRevert(Errors.ZeroAddress.selector);
        new IdFactory(address(0), deployer);
    }

    function test_revertBecauseSenderNotAllowedToCreateIdentities() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        onchainidSetup.idFactory
            .createIdentity(
                address(0),
                IdentityTypes.INDIVIDUAL,
                "salt1",
                _makeSingleMgmtKeys(address(0)),
                new Structs.ModuleInstall[](0)
            );
    }

    function test_revertBecauseWalletCannotBeZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(Errors.ZeroAddress.selector);
        onchainidSetup.idFactory
            .createIdentity(
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
            .createIdentity(
                david, IdentityTypes.INDIVIDUAL, "", _makeSingleMgmtKeys(david), new Structs.ModuleInstall[](0)
            );
    }

    function test_revertBecauseSaltAlreadyUsed() public {
        vm.prank(deployer);
        onchainidSetup.idFactory
            .createIdentity(
                carol, IdentityTypes.INDIVIDUAL, "saltUsed", _makeSingleMgmtKeys(carol), new Structs.ModuleInstall[](0)
            );

        vm.prank(deployer);
        // Salt-collision now bubbles up from Create3 as FailedDeployment().
        vm.expectRevert(OZErrors.FailedDeployment.selector);
        onchainidSetup.idFactory
            .createIdentity(
                david, IdentityTypes.INDIVIDUAL, "saltUsed", _makeSingleMgmtKeys(david), new Structs.ModuleInstall[](0)
            );
    }

    function test_revertBecauseWalletAlreadyLinked() public {
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletAlreadyLinkedToIdentity.selector, alice));
        onchainidSetup.idFactory
            .createIdentity(
                alice, IdentityTypes.INDIVIDUAL, "newSalt", _makeSingleMgmtKeys(alice), new Structs.ModuleInstall[](0)
            );
    }

    function test_revertBecauseEmptyKeys() public {
        Structs.KeyParam[] memory emptyKeys = new Structs.KeyParam[](0);
        vm.prank(deployer);
        vm.expectRevert(Errors.EmptyListOfKeys.selector);
        onchainidSetup.idFactory
            .createIdentity(david, IdentityTypes.INDIVIDUAL, "salt1", emptyKeys, new Structs.ModuleInstall[](0));
    }

    function test_revertBecauseNoManagementKey() public {
        // Only an ACTION key, no MANAGEMENT — bootstrap removal at the end of _setupIdentity reverts.
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1);
        keys[0] = _makeECDSAKey(david, KeyPurposes.ACTION);
        vm.prank(deployer);
        vm.expectRevert(Errors.CannotRemoveLastManagementKey.selector);
        onchainidSetup.idFactory
            .createIdentity(david, IdentityTypes.INDIVIDUAL, "salt1", keys, new Structs.ModuleInstall[](0));
    }

    // ============ linkWallet ============

    function test_linkWallet_revertForZeroAddress() public {
        vm.prank(alice);
        vm.expectRevert(Errors.ZeroAddress.selector);
        onchainidSetup.idFactory.linkWallet(address(0));
    }

    function test_linkWallet_revertForSenderNotLinked() public {
        vm.prank(david);
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletNotLinkedToIdentity.selector, david));
        onchainidSetup.idFactory.linkWallet(david);
    }

    function test_linkWallet_revertForNewWalletAlreadyLinked() public {
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletAlreadyLinkedToIdentity.selector, alice));
        onchainidSetup.idFactory.linkWallet(alice);
    }

    function test_linkWallet_revertForNewWalletLinkedToToken() public {
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(Errors.TokenAlreadyLinked.selector, Constants.TOKEN_ADDRESS));
        onchainidSetup.idFactory.linkWallet(Constants.TOKEN_ADDRESS);
    }

    function test_linkWallet_shouldLinkNewWallet() public {
        vm.prank(alice);
        onchainidSetup.idFactory.linkWallet(david);

        address[] memory wallets = onchainidSetup.idFactory.getWallets(address(aliceIdentity));
        assertEq(wallets.length, 2);
        assertEq(wallets[0], alice);
        assertEq(wallets[1], david);
    }

    // ============ unlinkWallet ============

    function test_unlinkWallet_revertForZeroAddress() public {
        vm.prank(alice);
        vm.expectRevert(Errors.ZeroAddress.selector);
        onchainidSetup.idFactory.unlinkWallet(address(0));
    }

    function test_unlinkWallet_revertForUnlinkingSelf() public {
        vm.prank(alice);
        vm.expectRevert(Errors.CannotBeCalledOnSenderAddress.selector);
        onchainidSetup.idFactory.unlinkWallet(alice);
    }

    function test_unlinkWallet_revertForSenderNotLinked() public {
        vm.prank(david);
        vm.expectRevert(Errors.OnlyLinkedWalletCanUnlink.selector);
        onchainidSetup.idFactory.unlinkWallet(alice);
    }

    function test_unlinkWallet_shouldUnlink() public {
        vm.prank(alice);
        onchainidSetup.idFactory.linkWallet(david);

        vm.prank(alice);
        onchainidSetup.idFactory.unlinkWallet(david);

        address[] memory wallets = onchainidSetup.idFactory.getWallets(address(aliceIdentity));
        assertEq(wallets.length, 1);
        assertEq(wallets[0], alice);
    }

    // ============ getIdentity ============

    /// @notice getIdentity should return token identity for token addresses
    function test_getIdentity_forTokenAddress_shouldReturnTokenIdentity() public view {
        address identity = onchainidSetup.idFactory.getIdentity(Constants.TOKEN_ADDRESS);
        assertTrue(identity != address(0), "Token identity should exist");
    }

    /// @notice getIdentity should return user identity for wallet addresses
    function test_getIdentity_forUserWallet_shouldReturnUserIdentity() public view {
        address identity = onchainidSetup.idFactory.getIdentity(alice);
        assertEq(identity, address(aliceIdentity), "Should return alice's identity");
    }

    /// @notice getIdentity should return zero for unknown addresses
    function test_getIdentity_forUnknownAddress_shouldReturnZero() public {
        address identity = onchainidSetup.idFactory.getIdentity(makeAddr("unknown"));
        assertEq(identity, address(0), "Should return zero address");
    }

    // ============ linkWallet - max wallets ============

    /// @notice Linking more than 100 extra wallets should revert
    function test_linkWallet_revertForMaxWalletsExceeded() public {
        // alice already has 1 wallet linked. Link 100 more to reach the limit of 101.
        for (uint256 i = 0; i < 100; i++) {
            address newWallet = vm.addr(1000 + i);
            vm.prank(alice);
            onchainidSetup.idFactory.linkWallet(newWallet);
        }

        // The 102nd wallet should revert (101 wallets already linked)
        address overflowWallet = makeAddr("overflowWallet");
        vm.prank(alice);
        vm.expectRevert(Errors.MaxWalletsPerIdentityExceeded.selector);
        onchainidSetup.idFactory.linkWallet(overflowWallet);
    }

    // ============ unlinkWallet - swap-and-pop ============

    /// @notice Unlinking a wallet that is not the last in the array exercises swap-and-pop
    function test_unlinkWallet_shouldSwapAndPop() public {
        // Link carol and david to alice's identity
        vm.prank(alice);
        onchainidSetup.idFactory.linkWallet(carol);
        vm.prank(alice);
        onchainidSetup.idFactory.linkWallet(david);

        // wallets = [alice, carol, david]
        // Unlink carol (middle element) -- triggers swap with david
        vm.prank(alice);
        onchainidSetup.idFactory.unlinkWallet(carol);

        address[] memory wallets = onchainidSetup.idFactory.getWallets(address(aliceIdentity));
        assertEq(wallets.length, 2, "Should have 2 wallets");
        assertEq(wallets[0], alice, "First wallet should be alice");
        assertEq(wallets[1], david, "Second wallet should be david (swapped)");
    }

    // ============ createIdentity with management keys (non-wallet) ============

    function test_createIdentity_withNonWalletManagementKeys_revertZeroAddress() public {
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1);
        keys[0] = _makeECDSAKey(alice, KeyPurposes.MANAGEMENT);

        vm.prank(deployer);
        vm.expectRevert(Errors.ZeroAddress.selector);
        onchainidSetup.idFactory
            .createIdentity(address(0), IdentityTypes.INDIVIDUAL, "salt1", keys, new Structs.ModuleInstall[](0));
    }

    function test_createIdentity_withNonWalletManagementKeys_revertEmptySalt() public {
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1);
        keys[0] = _makeECDSAKey(alice, KeyPurposes.MANAGEMENT);

        vm.prank(deployer);
        vm.expectRevert(Errors.EmptyString.selector);
        onchainidSetup.idFactory
            .createIdentity(david, IdentityTypes.INDIVIDUAL, "", keys, new Structs.ModuleInstall[](0));
    }

    function test_createIdentity_withNonWalletManagementKeys_revertSaltTaken() public {
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1);
        keys[0] = _makeECDSAKey(alice, KeyPurposes.MANAGEMENT);

        vm.prank(deployer);
        onchainidSetup.idFactory
            .createIdentity(david, IdentityTypes.INDIVIDUAL, "sharedSalt", keys, new Structs.ModuleInstall[](0));

        address anotherWallet = makeAddr("anotherWallet");
        vm.prank(deployer);
        // Salt-collision now bubbles up from Create3 as FailedDeployment().
        vm.expectRevert(OZErrors.FailedDeployment.selector);
        onchainidSetup.idFactory
            .createIdentity(anotherWallet, IdentityTypes.INDIVIDUAL, "sharedSalt", keys, new Structs.ModuleInstall[](0));
    }

    function test_createIdentity_withNonWalletManagementKeys_revertWalletAlreadyLinked() public {
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1);
        keys[0] = _makeECDSAKey(carol, KeyPurposes.MANAGEMENT);

        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletAlreadyLinkedToIdentity.selector, alice));
        onchainidSetup.idFactory
            .createIdentity(alice, IdentityTypes.INDIVIDUAL, "uniqueSalt", keys, new Structs.ModuleInstall[](0));
    }

    function test_createIdentity_withNonWalletManagementKeys_shouldDeployAndSetKeys() public {
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1);
        keys[0] = _makeECDSAKey(alice, KeyPurposes.MANAGEMENT);

        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentity(david, IdentityTypes.INDIVIDUAL, "salt1", keys, new Structs.ModuleInstall[](0));

        Identity identity = Identity(payable(identityAddr));

        // Raw abi.encode (not hashed) should return false
        assertFalse(
            identity.keyHasPurpose(bytes32(uint256(uint160(address(onchainidSetup.idFactory)))), KeyPurposes.MANAGEMENT)
        );
        assertFalse(identity.keyHasPurpose(bytes32(uint256(uint160(david))), KeyPurposes.MANAGEMENT));
        assertFalse(identity.keyHasPurpose(bytes32(uint256(uint160(alice))), KeyPurposes.MANAGEMENT));

        // Proper keccak256 hashed key SHOULD be a management key
        assertTrue(identity.keyHasPurpose(ClaimSignerHelper.addressToKey(alice), KeyPurposes.MANAGEMENT));
    }

    // ============ createIdentity with claimAdders ============

    /// @notice createIdentity with claimAdders should set CLAIM_ADDER keys on the identity
    function test_createIdentity_withClaimAdders_shouldSetClaimAdderKeys() public {
        address claimAdder1 = makeAddr("claimAdder1");
        address claimAdder2 = makeAddr("claimAdder2");

        Structs.KeyParam[] memory keys = new Structs.KeyParam[](3);
        keys[0] = _makeECDSAKey(david, KeyPurposes.MANAGEMENT);
        keys[1] = _makeECDSAKey(claimAdder1, KeyPurposes.CLAIM_ADDER);
        keys[2] = _makeECDSAKey(claimAdder2, KeyPurposes.CLAIM_ADDER);

        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentity(david, IdentityTypes.INDIVIDUAL, "saltWithAdders", keys, new Structs.ModuleInstall[](0));

        Identity identity = Identity(payable(identityAddr));

        // Verify CLAIM_ADDER keys are set
        assertTrue(
            identity.keyHasPurpose(ClaimSignerHelper.addressToKey(claimAdder1), KeyPurposes.CLAIM_ADDER),
            "claimAdder1 should have CLAIM_ADDER purpose"
        );
        assertTrue(
            identity.keyHasPurpose(ClaimSignerHelper.addressToKey(claimAdder2), KeyPurposes.CLAIM_ADDER),
            "claimAdder2 should have CLAIM_ADDER purpose"
        );

        // Verify management key is still set for wallet
        assertTrue(
            identity.keyHasPurpose(ClaimSignerHelper.addressToKey(david), KeyPurposes.MANAGEMENT),
            "david should have MANAGEMENT purpose"
        );
    }

    /// @notice createIdentity with management keys and claimAdders should set CLAIM_ADDER keys
    function test_createIdentity_withMgmtKeysAndClaimAdders_shouldSetClaimAdderKeys() public {
        address claimAdder = makeAddr("claimAdder");

        Structs.KeyParam[] memory keys = new Structs.KeyParam[](2);
        keys[0] = _makeECDSAKey(alice, KeyPurposes.MANAGEMENT);
        keys[1] = _makeECDSAKey(claimAdder, KeyPurposes.CLAIM_ADDER);

        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentity(david, IdentityTypes.INDIVIDUAL, "saltMgmtAdders", keys, new Structs.ModuleInstall[](0));

        Identity identity = Identity(payable(identityAddr));

        // Verify CLAIM_ADDER key is set
        assertTrue(
            identity.keyHasPurpose(ClaimSignerHelper.addressToKey(claimAdder), KeyPurposes.CLAIM_ADDER),
            "claimAdder should have CLAIM_ADDER purpose"
        );

        // Verify management key is set
        assertTrue(
            identity.keyHasPurpose(ClaimSignerHelper.addressToKey(alice), KeyPurposes.MANAGEMENT),
            "alice should have MANAGEMENT purpose"
        );
    }

    /// @notice Factory's own management key should be removed after identity creation
    function test_createIdentity_factoryKeyRemoved() public {
        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentity(
                david,
                IdentityTypes.INDIVIDUAL,
                "saltFactoryKey",
                _makeSingleMgmtKeys(david),
                new Structs.ModuleInstall[](0)
            );

        Identity identity = Identity(payable(identityAddr));

        // Factory should NOT have management key
        assertFalse(
            identity.keyHasPurpose(
                ClaimSignerHelper.addressToKey(address(onchainidSetup.idFactory)), KeyPurposes.MANAGEMENT
            ),
            "Factory should not have MANAGEMENT key after creation"
        );
    }

    // ============ createIdentity with new identity types ============

    /// @notice createIdentity with SMART_CONTRACT type should deploy and set type
    function test_createIdentity_smartContractType_shouldSetType() public {
        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentity(
                david,
                IdentityTypes.SMART_CONTRACT,
                "saltSmartContract",
                _makeSingleMgmtKeys(david),
                new Structs.ModuleInstall[](0)
            );

        Identity identity = Identity(payable(identityAddr));
        assertEq(identity.getIdentityType(), IdentityTypes.SMART_CONTRACT, "Identity type should be SMART_CONTRACT");
    }

    /// @notice createIdentity with PUBLIC_AUTHORITY type should deploy and set type
    function test_createIdentity_publicAuthorityType_shouldSetType() public {
        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentity(
                david,
                IdentityTypes.PUBLIC_AUTHORITY,
                "saltPublicAuth",
                _makeSingleMgmtKeys(david),
                new Structs.ModuleInstall[](0)
            );

        Identity identity = Identity(payable(identityAddr));
        assertEq(identity.getIdentityType(), IdentityTypes.PUBLIC_AUTHORITY, "Identity type should be PUBLIC_AUTHORITY");
    }

    // ============ createIdentity with module installation ============

    /// @notice createIdentity with modules should install the ERC-7579 validator module
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
            .createIdentity(david, IdentityTypes.INDIVIDUAL, "saltWithModules", _makeSingleMgmtKeys(david), modules);

        Identity identity = Identity(payable(identityAddr));
        assertTrue(
            identity.isModuleInstalled(1, address(onchainidSetup.signatureValidator), ""),
            "ERC7579Signature validator should be installed"
        );
    }

    // ============ _deploy CREATE2 failure ============

    /// @notice CREATE2 failure triggers assembly revert when proxy constructor reverts
    function test_createIdentity_revertWhenCreate2Fails() public {
        // Deploy a factory with a reverting implementation
        RevertingIdentity revertingImpl = new RevertingIdentity();
        ImplementationAuthority badAuthority = new ImplementationAuthority(address(revertingImpl), deployer);
        IdFactory badFactory = new IdFactory(address(badAuthority), deployer);

        // createIdentity will try CREATE2 with IdentityProxy whose constructor
        // delegatecalls initialize() on RevertingIdentity, which reverts,
        // causing CREATE2 to return address(0) and triggering assembly revert
        vm.expectRevert();
        badFactory.createIdentity(
            david, IdentityTypes.INDIVIDUAL, "salt1", _makeSingleMgmtKeys(david), new Structs.ModuleInstall[](0)
        );
    }

    // ============ Accessor edge cases (formerly IdFactory.branches.t.sol) ============

    // ---- getToken accessor ----

    function test_getToken_forTokenIdentity_returnsTokenAddress() public view {
        // The fixture creates a token identity for Constants.TOKEN_ADDRESS in setUp.
        address tokenIdentity = onchainidSetup.idFactory.getIdentity(Constants.TOKEN_ADDRESS);
        assertEq(
            onchainidSetup.idFactory.getToken(tokenIdentity),
            Constants.TOKEN_ADDRESS,
            "getToken should return the token address for a token identity"
        );
    }

    function test_getToken_forUserIdentity_returnsZero() public view {
        // A user identity has no associated token; the lookup table returns address(0).
        assertEq(onchainidSetup.idFactory.getToken(address(aliceIdentity)), address(0));
    }

    function test_getToken_forUnknownIdentity_returnsZero() public {
        assertEq(onchainidSetup.idFactory.getToken(makeAddr("unknown-identity")), address(0));
    }

    // ---- getWallets edge cases ----

    function test_getWallets_forUnknownIdentity_returnsEmpty() public {
        address[] memory wallets = onchainidSetup.idFactory.getWallets(makeAddr("unknown-id"));
        assertEq(wallets.length, 0);
    }

    function test_getWallets_forFreshIdentity_returnsExactlyOne() public view {
        address[] memory wallets = onchainidSetup.idFactory.getWallets(address(aliceIdentity));
        assertEq(wallets.length, 1, "alice has exactly one wallet at setup");
        assertEq(wallets[0], alice);
    }

    // ---- createIdentity duplicate-salt branch with non-default salt ----

    /// @notice Confirms the salt collision detection actually trips after a successful create.
    ///         Existing `test_revertBecauseSaltAlreadyUsed` covers the same arm — this is the
    ///         cross-test that the Create3 deploy at the same salt reverts on the second call.
    function test_createIdentity_secondCallSameSalt_revertsAfterFirstSucceeds() public {
        vm.prank(deployer);
        onchainidSetup.idFactory
            .createIdentity(
                carol,
                IdentityTypes.INDIVIDUAL,
                "branchSalt",
                _makeSingleMgmtKeys(carol),
                new Structs.ModuleInstall[](0)
            );

        // Second attempt with the same salt MUST revert — collision now bubbles up from Create3.
        address newWallet = makeAddr("second-wallet");
        vm.prank(deployer);
        vm.expectRevert(OZErrors.FailedDeployment.selector);
        onchainidSetup.idFactory
            .createIdentity(
                newWallet,
                IdentityTypes.INDIVIDUAL,
                "branchSalt",
                _makeSingleMgmtKeys(newWallet),
                new Structs.ModuleInstall[](0)
            );
    }

    // ---- linkWallet — new wallet is a token address ----

    /// @notice The `linkWallet` revert path when the new wallet is already a token address
    ///         (IdFactory.sol:137). Exercises the `_tokenIdentity[_newWallet] != address(0)` arm.
    function test_linkWallet_newWalletIsToken_reverts() public {
        // alice is already linked to aliceIdentity. Try to link the token address — which has
        // a token identity but no user identity, so the user check passes but the token check trips.
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Errors.TokenAlreadyLinked.selector, Constants.TOKEN_ADDRESS));
        onchainidSetup.idFactory.linkWallet(Constants.TOKEN_ADDRESS);
    }

    // ---- unlinkWallet edge cases ----

    /// @notice Single-element wallet array: the unlinkWallet for-loop iterates exactly once
    ///         before breaking. Exercises the "i==0" branch.
    function test_unlinkWallet_singleWallet_clearsList() public {
        // alice has only her own wallet (per setup). Link a side wallet, then unlink it via alice.
        vm.prank(alice);
        onchainidSetup.idFactory.linkWallet(makeAddr("temp-w"));
        vm.prank(alice);
        onchainidSetup.idFactory.unlinkWallet(makeAddr("temp-w"));

        address[] memory wallets = onchainidSetup.idFactory.getWallets(address(aliceIdentity));
        assertEq(wallets.length, 1);
        assertEq(wallets[0], alice);
    }

    /// @notice Multiple wallets, unlink the LAST one — no swap, pop only.
    function test_unlinkWallet_lastInArray_popOnly() public {
        vm.prank(alice);
        onchainidSetup.idFactory.linkWallet(carol);
        vm.prank(alice);
        onchainidSetup.idFactory.linkWallet(david);
        // wallets = [alice, carol, david]; unlink david — last element, no swap needed.
        vm.prank(alice);
        onchainidSetup.idFactory.unlinkWallet(david);

        address[] memory wallets = onchainidSetup.idFactory.getWallets(address(aliceIdentity));
        assertEq(wallets.length, 2);
        assertEq(wallets[0], alice);
        assertEq(wallets[1], carol);
    }

    /// @notice Pins the `delete _userIdentity[_oldWallet]` write in `unlinkWallet` at
    ///         `IdFactory.sol:150`. Existing tests check `getWallets` post-unlink (which
    ///         iterates the `_wallets[identity]` array) but never read `_userIdentity` or
    ///         the public `getIdentity(oldWallet)` accessor afterward. If that `delete` were
    ///         absent, every caller resolving wallet→identity via `getIdentity` would still
    ///         see the unlinked wallet as belonging to alice.
    function test_unlinkWallet_clearsUserIdentityReverseMap() public {
        // Link carol so we have a non-self wallet to unlink. `unlinkWallet` rejects unlinking
        // the same address as msg.sender (CannotBeCalledOnSenderAddress), so we link a side
        // wallet then unlink it via alice.
        vm.prank(alice);
        onchainidSetup.idFactory.linkWallet(carol);
        assertEq(onchainidSetup.idFactory.getIdentity(carol), address(aliceIdentity), "linked");

        vm.prank(alice);
        onchainidSetup.idFactory.unlinkWallet(carol);

        // After unlink, the reverse map MUST be cleared: `getIdentity(carol)` returns zero.
        assertEq(onchainidSetup.idFactory.getIdentity(carol), address(0), "unlinked wallet must no longer resolve");
    }

}
