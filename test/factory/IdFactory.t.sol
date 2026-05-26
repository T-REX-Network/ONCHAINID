// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { Constants } from "../utils/Constants.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Nonces } from "@openzeppelin/contracts/utils/Nonces.sol";
import { Identity } from "contracts/Identity.sol";
import { IIdFactory } from "contracts/factory/IIdFactory.sol";
import { IdFactory } from "contracts/factory/IdFactory.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { ImplementationAuthority } from "contracts/proxy/ImplementationAuthority.sol";
import { RevertingIdentity } from "test/mocks/RevertingIdentity.sol";

contract IdFactoryTest is OnchainIDSetup {

    bytes32 private constant _LINK_WALLET_TYPEHASH =
        keccak256("LinkWallet(address wallet,address identity,uint256 nonce,uint256 expiry)");

    /// @dev Builds the EIP-712 domain separator matching IdFactory("IdentityFactory", "1")
    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("IdentityFactory"),
                keccak256("1"),
                block.chainid,
                address(onchainidSetup.idFactory)
            )
        );
    }

    /// @dev Builds an EIP-712 signature for linkWalletWithSignature
    function _signLinkWallet(uint256 signerPk, address wallet, address identity, uint256 nonce, uint256 expiry)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(abi.encode(_LINK_WALLET_TYPEHASH, wallet, identity, nonce, expiry));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Helper: sign and call linkWalletWithSignature via execute()
    function _linkWalletWithSig(Identity identity, address walletOwner, address wallet, uint256 walletPk) internal {
        // Sign the EIP-712 message
        uint256 nonce = onchainidSetup.idFactory.nonces(wallet);
        uint256 expiry = block.timestamp + 1 hours;
        bytes memory signature = _signLinkWallet(walletPk, wallet, address(identity), nonce, expiry);

        // Call linkWalletWithSignature via identity.execute()
        bytes memory callData =
            abi.encodeWithSelector(IIdFactory.linkWalletWithSignature.selector, wallet, signature, nonce, expiry);
        vm.prank(walletOwner);
        identity.execute(address(onchainidSetup.idFactory), 0, callData);
    }

    // ============ createIdentity ============

    function test_revertBecauseAuthorityIsZeroAddress() public {
        vm.expectRevert(Errors.ZeroAddress.selector);
        new IdFactory(address(0), address(this));
    }

    function test_revertBecauseSenderNotAllowedToCreateIdentities() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        onchainidSetup.idFactory.createIdentity(address(0), "salt1", IdentityTypes.INDIVIDUAL, new address[](0));
    }

    function test_revertBecauseWalletCannotBeZeroAddress() public {
        vm.prank(deployer);
        vm.expectRevert(Errors.ZeroAddress.selector);
        onchainidSetup.idFactory.createIdentity(address(0), "salt1", IdentityTypes.INDIVIDUAL, new address[](0));
    }

    function test_revertBecauseSaltCannotBeEmpty() public {
        vm.prank(deployer);
        vm.expectRevert(Errors.EmptyString.selector);
        onchainidSetup.idFactory.createIdentity(david, "", IdentityTypes.INDIVIDUAL, new address[](0));
    }

    function test_revertBecauseSaltAlreadyUsed() public {
        vm.prank(deployer);
        onchainidSetup.idFactory.createIdentity(carol, "saltUsed", IdentityTypes.INDIVIDUAL, new address[](0));

        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.SaltTaken.selector, "OIDsaltUsed"));
        onchainidSetup.idFactory.createIdentity(david, "saltUsed", IdentityTypes.INDIVIDUAL, new address[](0));
    }

    function test_revertBecauseWalletAlreadyLinked() public {
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletAlreadyLinkedToIdentity.selector, alice));
        onchainidSetup.idFactory.createIdentity(alice, "newSalt", IdentityTypes.INDIVIDUAL, new address[](0));
    }

    // ============ unlinkWallet ============

    function test_unlinkWallet_revertForZeroAddress() public {
        // address(0) is never linked, so the address(0) != msg.sender / linked-wallet checks reject it
        vm.prank(alice);
        vm.expectRevert(Errors.OnlyLinkedWalletCanUnlink.selector);
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
        _linkWalletWithSig(aliceIdentity, alice, david, davidPk);

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

    // ============ unlinkWallet - swap-and-pop ============

    /// @notice Unlinking a wallet that is not the last in the array exercises swap-and-pop
    function test_unlinkWallet_shouldSwapAndPop() public {
        // Link carol and david to alice's identity
        _linkWalletWithSig(aliceIdentity, alice, carol, carolPk);
        _linkWalletWithSig(aliceIdentity, alice, david, davidPk);

        // wallets = [alice, carol, david]
        // Unlink carol (middle element) — triggers swap with david
        vm.prank(alice);
        onchainidSetup.idFactory.unlinkWallet(carol);

        address[] memory wallets = onchainidSetup.idFactory.getWallets(address(aliceIdentity));
        assertEq(wallets.length, 2, "Should have 2 wallets");
        assertEq(wallets[0], alice, "First wallet should be alice");
        assertEq(wallets[1], david, "Second wallet should be david (swapped)");
    }

    // ============ createIdentityWithManagementKeys ============

    function test_createIdentityWithManagementKeys_revertZeroAddress() public {
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = ClaimSignerHelper.addressToKey(alice);

        vm.prank(deployer);
        vm.expectRevert(Errors.ZeroAddress.selector);
        onchainidSetup.idFactory
            .createIdentityWithManagementKeys(address(0), "salt1", keys, IdentityTypes.INDIVIDUAL, new address[](0));
    }

    function test_createIdentityWithManagementKeys_revertEmptySalt() public {
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = ClaimSignerHelper.addressToKey(alice);

        vm.prank(deployer);
        vm.expectRevert(Errors.EmptyString.selector);
        onchainidSetup.idFactory
            .createIdentityWithManagementKeys(david, "", keys, IdentityTypes.INDIVIDUAL, new address[](0));
    }

    function test_createIdentityWithManagementKeys_revertSaltTaken() public {
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = ClaimSignerHelper.addressToKey(alice);

        vm.prank(deployer);
        onchainidSetup.idFactory
            .createIdentityWithManagementKeys(david, "sharedSalt", keys, IdentityTypes.INDIVIDUAL, new address[](0));

        address anotherWallet = makeAddr("anotherWallet");
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.SaltTaken.selector, "OIDsharedSalt"));
        onchainidSetup.idFactory
            .createIdentityWithManagementKeys(
                anotherWallet, "sharedSalt", keys, IdentityTypes.INDIVIDUAL, new address[](0)
            );
    }

    function test_createIdentityWithManagementKeys_revertWalletAlreadyLinked() public {
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = ClaimSignerHelper.addressToKey(carol);

        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletAlreadyLinkedToIdentity.selector, alice));
        onchainidSetup.idFactory
            .createIdentityWithManagementKeys(alice, "uniqueSalt", keys, IdentityTypes.INDIVIDUAL, new address[](0));
    }

    function test_createIdentityWithManagementKeys_revertNoKeys() public {
        bytes32[] memory keys = new bytes32[](0);

        vm.prank(deployer);
        vm.expectRevert(Errors.EmptyListOfKeys.selector);
        onchainidSetup.idFactory
            .createIdentityWithManagementKeys(david, "salt1", keys, IdentityTypes.INDIVIDUAL, new address[](0));
    }

    function test_createIdentityWithManagementKeys_revertWalletInKeys() public {
        bytes32[] memory keys = new bytes32[](2);
        keys[0] = ClaimSignerHelper.addressToKey(alice);
        keys[1] = ClaimSignerHelper.addressToKey(david);

        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletAlsoListedInManagementKeys.selector, david));
        onchainidSetup.idFactory
            .createIdentityWithManagementKeys(david, "salt1", keys, IdentityTypes.INDIVIDUAL, new address[](0));
    }

    function test_createIdentityWithManagementKeys_shouldDeployAndSetKeys() public {
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = ClaimSignerHelper.addressToKey(alice);

        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentityWithManagementKeys(david, "salt1", keys, IdentityTypes.INDIVIDUAL, new address[](0));

        Identity identity = Identity(identityAddr);

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
        address[] memory claimAdders = new address[](2);
        claimAdders[0] = claimAdder1;
        claimAdders[1] = claimAdder2;

        vm.prank(deployer);
        address identityAddr =
            onchainidSetup.idFactory.createIdentity(david, "saltWithAdders", IdentityTypes.INDIVIDUAL, claimAdders);

        Identity identity = Identity(identityAddr);

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

    /// @notice createIdentityWithManagementKeys with claimAdders should set CLAIM_ADDER keys
    function test_createIdentityWithManagementKeys_withClaimAdders_shouldSetClaimAdderKeys() public {
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = ClaimSignerHelper.addressToKey(alice);

        address claimAdder = makeAddr("claimAdder");
        address[] memory claimAdders = new address[](1);
        claimAdders[0] = claimAdder;

        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentityWithManagementKeys(david, "saltMgmtAdders", keys, IdentityTypes.INDIVIDUAL, claimAdders);

        Identity identity = Identity(identityAddr);

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
        .createIdentity(david, "saltFactoryKey", IdentityTypes.INDIVIDUAL, new address[](0));

        Identity identity = Identity(identityAddr);

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
            .createIdentity(david, "saltSmartContract", IdentityTypes.SMART_CONTRACT, new address[](0));

        Identity identity = Identity(identityAddr);
        assertEq(identity.getIdentityType(), IdentityTypes.SMART_CONTRACT, "Identity type should be SMART_CONTRACT");
    }

    /// @notice createIdentity with PUBLIC_AUTHORITY type should deploy and set type
    function test_createIdentity_publicAuthorityType_shouldSetType() public {
        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentity(david, "saltPublicAuth", IdentityTypes.PUBLIC_AUTHORITY, new address[](0));

        Identity identity = Identity(identityAddr);
        assertEq(identity.getIdentityType(), IdentityTypes.PUBLIC_AUTHORITY, "Identity type should be PUBLIC_AUTHORITY");
    }

    // ============ _deploy CREATE3 failure ============

    /// @notice CREATE3 deployment failure bubbles up when the IdentityProxy constructor reverts
    function test_createIdentity_revertWhenDeploymentFails() public {
        // Deploy a factory with a reverting implementation
        RevertingIdentity revertingImpl = new RevertingIdentity();
        ImplementationAuthority badAuthority = new ImplementationAuthority(address(revertingImpl), address(this));
        IdFactory badFactory = new IdFactory(address(badAuthority), address(this));

        // createIdentity uses CREATE3: a CREATE2 proxy is deployed first, then the proxy
        // performs CREATE of IdentityProxy. IdentityProxy's constructor delegatecalls
        // initialize() on RevertingIdentity which reverts, so the inner CREATE fails and
        // Create3.deploy bubbles the revert.
        vm.expectRevert();
        badFactory.createIdentity(david, "salt1", IdentityTypes.INDIVIDUAL, new address[](0));
    }

    // ============ linkWalletWithSignature ============

    /// @notice Successful path: wallet signs EIP-712 message, identity links wallet via execute()
    function test_linkWalletWithSignature_shouldLink() public {
        _linkWalletWithSig(aliceIdentity, alice, david, davidPk);

        address[] memory wallets = onchainidSetup.idFactory.getWallets(address(aliceIdentity));
        assertEq(wallets.length, 2);
        assertEq(wallets[0], alice);
        assertEq(wallets[1], david);
        assertEq(onchainidSetup.idFactory.getIdentity(david), address(aliceIdentity));
    }

    /// @notice Nonce should increment after a successful link
    function test_linkWalletWithSignature_shouldIncrementNonce() public {
        assertEq(onchainidSetup.idFactory.nonces(david), 0);

        _linkWalletWithSig(aliceIdentity, alice, david, davidPk);

        assertEq(onchainidSetup.idFactory.nonces(david), 1);
    }

    /// @notice Wallet address cannot be zero — ECDSA recovery never produces address(0) for a valid sig
    function test_linkWalletWithSignature_revertForZeroAddress() public {
        uint256 expiry = block.timestamp + 1 hours;
        bytes memory signature = _signLinkWallet(davidPk, address(0), address(aliceIdentity), 0, expiry);

        vm.prank(address(aliceIdentity));
        vm.expectRevert(Errors.InvalidSignature.selector);
        onchainidSetup.idFactory.linkWalletWithSignature(address(0), signature, 0, expiry);
    }

    /// @notice Expired signature should revert
    function test_linkWalletWithSignature_revertForExpiredSignature() public {
        uint256 expiry = block.timestamp - 1; // already expired
        bytes memory signature = _signLinkWallet(davidPk, david, address(aliceIdentity), 0, expiry);

        vm.prank(address(aliceIdentity));
        vm.expectRevert(abi.encodeWithSelector(Errors.ExpiredSignature.selector, signature));
        onchainidSetup.idFactory.linkWalletWithSignature(david, signature, 0, expiry);
    }

    /// @notice Invalid signature (wrong signer) should revert
    function test_linkWalletWithSignature_revertForInvalidSignature() public {
        uint256 expiry = block.timestamp + 1 hours;
        // Sign with carol's key instead of david's
        bytes memory badSignature = _signLinkWallet(carolPk, david, address(aliceIdentity), 0, expiry);

        vm.prank(address(aliceIdentity));
        vm.expectRevert(Errors.InvalidSignature.selector);
        onchainidSetup.idFactory.linkWalletWithSignature(david, badSignature, 0, expiry);
    }

    /// @notice Wrong nonce should revert
    function test_linkWalletWithSignature_revertForInvalidNonce() public {
        uint256 expiry = block.timestamp + 1 hours;
        uint256 wrongNonce = 42;
        bytes memory signature = _signLinkWallet(davidPk, david, address(aliceIdentity), wrongNonce, expiry);

        vm.prank(address(aliceIdentity));
        // OZ Nonces: InvalidAccountNonce(account, currentNonce)
        vm.expectRevert(abi.encodeWithSelector(Nonces.InvalidAccountNonce.selector, david, 0));
        onchainidSetup.idFactory.linkWalletWithSignature(david, signature, wrongNonce, expiry);
    }

    /// @notice Replay attack: link -> unlink -> replay same signature should revert
    function test_linkWalletWithSignature_revertForReplayAttack() public {
        // Step 1: Create and use a valid signature (nonce=0)
        uint256 expiry = block.timestamp + 1 hours;
        uint256 nonce0 = 0;
        bytes memory signature0 = _signLinkWallet(davidPk, david, address(aliceIdentity), nonce0, expiry);

        bytes memory linkCallData =
            abi.encodeWithSelector(IIdFactory.linkWalletWithSignature.selector, david, signature0, nonce0, expiry);
        vm.prank(alice);
        aliceIdentity.execute(address(onchainidSetup.idFactory), 0, linkCallData);

        // Verify link succeeded
        assertEq(onchainidSetup.idFactory.getIdentity(david), address(aliceIdentity));
        assertEq(onchainidSetup.idFactory.nonces(david), 1);

        // Step 3: Unlink david via identity
        bytes memory unlinkCallData = abi.encodeWithSelector(IIdFactory.unlinkWalletByIdentity.selector, david);
        vm.prank(alice);
        aliceIdentity.execute(address(onchainidSetup.idFactory), 0, unlinkCallData);

        // Verify unlink succeeded
        assertEq(onchainidSetup.idFactory.getIdentity(david), address(0));

        // Step 4: Attempt to replay the same signature (nonce=0, but current nonce is 1)
        vm.prank(alice);
        aliceIdentity.execute(address(onchainidSetup.idFactory), 0, linkCallData);

        // Verify the replay was rejected — david is still NOT linked
        assertEq(onchainidSetup.idFactory.getIdentity(david), address(0));

        // Step 5: A fresh signature with nonce=1 should work
        uint256 nonce1 = 1;
        bytes memory signature1 = _signLinkWallet(davidPk, david, address(aliceIdentity), nonce1, expiry);
        bytes memory freshCallData =
            abi.encodeWithSelector(IIdFactory.linkWalletWithSignature.selector, david, signature1, nonce1, expiry);
        vm.prank(alice);
        aliceIdentity.execute(address(onchainidSetup.idFactory), 0, freshCallData);

        // Verify fresh signature succeeded
        assertEq(onchainidSetup.idFactory.getIdentity(david), address(aliceIdentity));
        assertEq(onchainidSetup.idFactory.nonces(david), 2);
    }

    /// @notice Wallet bound to a different identity should revert
    function test_linkWalletWithSignature_revertForWalletBoundToAnotherIdentity() public {
        // bob is already linked to bob's identity via factory setup
        uint256 expiry = block.timestamp + 1 hours;
        bytes memory signature = _signLinkWallet(bobPk, bob, address(aliceIdentity), 0, expiry);

        vm.prank(address(aliceIdentity));
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletBoundToAnotherIdentity.selector, bob, address(bobIdentity)));
        onchainidSetup.idFactory.linkWalletWithSignature(bob, signature, 0, expiry);
    }

    /// @notice Wallet that is a token address should revert
    function test_linkWalletWithSignature_revertForTokenAddress() public {
        // Register david as a token identity so _tokenIdentity[david] != address(0)
        vm.prank(deployer);
        onchainidSetup.idFactory.createTokenIdentity(david, tokenOwner, "tokenDavid", new address[](0));

        // Sign and attempt to link
        uint256 expiry = block.timestamp + 1 hours;
        bytes memory signature = _signLinkWallet(davidPk, david, address(aliceIdentity), 0, expiry);

        vm.prank(address(aliceIdentity));
        vm.expectRevert(abi.encodeWithSelector(Errors.TokenAlreadyLinked.selector, david));
        onchainidSetup.idFactory.linkWalletWithSignature(david, signature, 0, expiry);
    }

    /// @notice Max wallets exceeded should revert
    function test_linkWalletWithSignature_revertForMaxWallets() public {
        // Fill alice's identity to max wallets (101) by linking 100 more via signature
        for (uint256 i = 0; i < 100; i++) {
            uint256 pk = 1000 + i;
            address newWallet = vm.addr(pk);
            _linkWalletWithSig(aliceIdentity, alice, newWallet, pk);
        }

        // Now try to link one more via signature
        uint256 expiry = block.timestamp + 1 hours;
        bytes memory signature = _signLinkWallet(davidPk, david, address(aliceIdentity), 0, expiry);

        vm.prank(address(aliceIdentity));
        vm.expectRevert(Errors.MaxWalletsPerIdentityExceeded.selector);
        onchainidSetup.idFactory.linkWalletWithSignature(david, signature, 0, expiry);
    }

    /// @notice Direct EOA call should fail because signature binds wallet to EOA address (not an identity)
    function test_linkWalletWithSignature_revertForWrongIdentityInSignature() public {
        uint256 expiry = block.timestamp + 1 hours;
        // Sign for david binding to aliceIdentity, but call from bob (EOA)
        // Signature was created for identity=aliceIdentity, but msg.sender=bob — signature mismatch
        bytes memory signature = _signLinkWallet(davidPk, david, address(aliceIdentity), 0, expiry);

        vm.prank(bob);
        vm.expectRevert();
        onchainidSetup.idFactory.linkWalletWithSignature(david, signature, 0, expiry);
    }

    // ============ unlinkWalletByIdentity ============

    /// @notice Happy path: identity unlinks a wallet via execute()
    function test_unlinkWalletByIdentity_shouldUnlink() public {
        // First link david via signature
        _linkWalletWithSig(aliceIdentity, alice, david, davidPk);
        assertEq(onchainidSetup.idFactory.getIdentity(david), address(aliceIdentity));

        // Unlink david via identity
        bytes memory callData = abi.encodeWithSelector(IIdFactory.unlinkWalletByIdentity.selector, david);
        vm.prank(alice);
        aliceIdentity.execute(address(onchainidSetup.idFactory), 0, callData);

        // Verify david is unlinked
        assertEq(onchainidSetup.idFactory.getIdentity(david), address(0));
        address[] memory wallets = onchainidSetup.idFactory.getWallets(address(aliceIdentity));
        assertEq(wallets.length, 1);
        assertEq(wallets[0], alice);
    }

    /// @notice Zero address is never linked, so unlinking it surfaces WalletNotLinkedToIdentity
    function test_unlinkWalletByIdentity_revertForZeroAddress() public {
        vm.prank(address(aliceIdentity));
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletNotLinkedToIdentity.selector, address(0)));
        onchainidSetup.idFactory.unlinkWalletByIdentity(address(0));
    }

    /// @notice Wallet not linked to the calling identity should revert
    function test_unlinkWalletByIdentity_revertForWalletNotLinkedToIdentity() public {
        // Try to unlink bob from alice's identity - bob is linked to bob's identity
        vm.prank(address(aliceIdentity));
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletNotLinkedToIdentity.selector, bob));
        onchainidSetup.idFactory.unlinkWalletByIdentity(bob);
    }

    /// @notice Direct EOA call should fail if wallet is linked to a different identity
    function test_unlinkWalletByIdentity_revertForNonIdentityCaller() public {
        // alice is linked to aliceIdentity. If david (EOA) calls unlinkWalletByIdentity(alice),
        // it should revert because _userIdentity[alice] != david
        vm.prank(david);
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletNotLinkedToIdentity.selector, alice));
        onchainidSetup.idFactory.unlinkWalletByIdentity(alice);
    }

    // ============ Re-link restriction tests ============

    /// @notice createIdentity: previously linked wallet cannot create a new identity
    function test_createIdentity_revertForPreviouslyLinkedWallet() public {
        // Link david to alice's identity via signature
        _linkWalletWithSig(aliceIdentity, alice, david, davidPk);

        // Unlink david
        bytes memory unlinkCallData = abi.encodeWithSelector(IIdFactory.unlinkWalletByIdentity.selector, david);
        vm.prank(alice);
        aliceIdentity.execute(address(onchainidSetup.idFactory), 0, unlinkCallData);

        // Try to create a new identity for david — should revert
        // because _userIdentity[david] != address(0) (still bound to alice's identity)
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletAlreadyLinkedToIdentity.selector, david));
        onchainidSetup.idFactory.createIdentity(david, "davidSalt", IdentityTypes.INDIVIDUAL, new address[](0));
    }

    /// @notice createIdentityWithManagementKeys: previously linked wallet cannot create a new identity
    function test_createIdentityWithManagementKeys_revertForPreviouslyLinkedWallet() public {
        // Link david to alice's identity via signature
        _linkWalletWithSig(aliceIdentity, alice, david, davidPk);

        // Unlink david
        bytes memory unlinkCallData = abi.encodeWithSelector(IIdFactory.unlinkWalletByIdentity.selector, david);
        vm.prank(alice);
        aliceIdentity.execute(address(onchainidSetup.idFactory), 0, unlinkCallData);

        // Try to create a new identity for david — should revert
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = ClaimSignerHelper.addressToKey(alice);

        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletAlreadyLinkedToIdentity.selector, david));
        onchainidSetup.idFactory
            .createIdentityWithManagementKeys(david, "davidSalt", keys, IdentityTypes.INDIVIDUAL, new address[](0));
    }

    /// @notice linkWalletWithSignature: unlinked wallet can be re-linked to the same identity
    function test_linkWalletWithSignature_shouldAllowRelinkToSameIdentity() public {
        // Link david to alice's identity via signature
        _linkWalletWithSig(aliceIdentity, alice, david, davidPk);
        assertEq(onchainidSetup.idFactory.getIdentity(david), address(aliceIdentity));

        // Unlink david via identity
        bytes memory unlinkCallData = abi.encodeWithSelector(IIdFactory.unlinkWalletByIdentity.selector, david);
        vm.prank(alice);
        aliceIdentity.execute(address(onchainidSetup.idFactory), 0, unlinkCallData);
        assertEq(onchainidSetup.idFactory.getIdentity(david), address(0));

        // Re-link david to the SAME identity via signature — should succeed
        _linkWalletWithSig(aliceIdentity, alice, david, davidPk);
        assertEq(onchainidSetup.idFactory.getIdentity(david), address(aliceIdentity));
    }

    /// @notice linkWalletWithSignature: unlinked wallet cannot be linked to a different identity
    function test_linkWalletWithSignature_revertForRelinkToDifferentIdentity() public {
        // Link david to alice's identity via signature
        _linkWalletWithSig(aliceIdentity, alice, david, davidPk);

        // Unlink david via identity
        bytes memory unlinkCallData = abi.encodeWithSelector(IIdFactory.unlinkWalletByIdentity.selector, david);
        vm.prank(alice);
        aliceIdentity.execute(address(onchainidSetup.idFactory), 0, unlinkCallData);

        // Try to link david to bob's identity via signature — should fail
        uint256 nonce = onchainidSetup.idFactory.nonces(david);
        uint256 expiry = block.timestamp + 1 hours;
        bytes memory signature = _signLinkWallet(davidPk, david, address(bobIdentity), nonce, expiry);

        bytes memory callData =
            abi.encodeWithSelector(IIdFactory.linkWalletWithSignature.selector, david, signature, nonce, expiry);
        vm.prank(bob);
        bobIdentity.execute(address(onchainidSetup.idFactory), 0, callData);

        // Verify david was NOT linked to bob's identity
        assertEq(onchainidSetup.idFactory.getIdentity(david), address(0));
    }

    /// @notice getIdentity should return zero for an unlinked wallet
    function test_getIdentity_shouldReturnZeroForUnlinkedWallet() public {
        // Link david to alice's identity via signature
        _linkWalletWithSig(aliceIdentity, alice, david, davidPk);
        assertEq(onchainidSetup.idFactory.getIdentity(david), address(aliceIdentity));

        // Unlink david
        vm.prank(alice);
        onchainidSetup.idFactory.unlinkWallet(david);

        // getIdentity should return address(0) even though _userIdentity[david] still stores aliceIdentity
        assertEq(onchainidSetup.idFactory.getIdentity(david), address(0));
    }

    /// @notice unlinkWallet: trying to unlink an unlinked wallet (bound but not active) should revert
    function test_unlinkWallet_revertForUnlinkedTarget() public {
        // Link david and carol to alice's identity via signature
        _linkWalletWithSig(aliceIdentity, alice, david, davidPk);
        _linkWalletWithSig(aliceIdentity, alice, carol, carolPk);

        // Unlink david (now bound but not active)
        vm.prank(alice);
        onchainidSetup.idFactory.unlinkWallet(david);

        // carol tries to unlink david — david is bound but not actively linked, _unlinkWallet's remove() rejects
        vm.prank(carol);
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletNotLinkedToIdentity.selector, david));
        onchainidSetup.idFactory.unlinkWallet(david);
    }

    /// @notice linkWalletWithSignature: wallet already actively linked to same identity should revert
    function test_linkWalletWithSignature_revertForWalletAlreadyActivelyLinked() public {
        // Link david to alice's identity via signature
        _linkWalletWithSig(aliceIdentity, alice, david, davidPk);
        assertEq(onchainidSetup.idFactory.getIdentity(david), address(aliceIdentity));

        // Try to link david again via signature — already actively linked
        uint256 nonce = onchainidSetup.idFactory.nonces(david);
        uint256 expiry = block.timestamp + 1 hours;
        bytes memory signature = _signLinkWallet(davidPk, david, address(aliceIdentity), nonce, expiry);

        vm.prank(address(aliceIdentity));
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletAlreadyLinkedToIdentity.selector, david));
        onchainidSetup.idFactory.linkWalletWithSignature(david, signature, nonce, expiry);
    }

    /// @notice unlinkWalletByIdentity: trying to unlink a previously linked but now unlinked wallet should revert
    function test_unlinkWalletByIdentity_revertForUnlinkedWallet() public {
        // Link david to alice's identity via signature
        _linkWalletWithSig(aliceIdentity, alice, david, davidPk);

        // Unlink david via identity
        bytes memory unlinkCallData = abi.encodeWithSelector(IIdFactory.unlinkWalletByIdentity.selector, david);
        vm.prank(alice);
        aliceIdentity.execute(address(onchainidSetup.idFactory), 0, unlinkCallData);

        // Try to unlink david again — already unlinked but still bound, reverts WalletNotLinkedToIdentity
        vm.prank(address(aliceIdentity));
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletNotLinkedToIdentity.selector, david));
        onchainidSetup.idFactory.unlinkWalletByIdentity(david);
    }

    /// @notice unlinkWallet: unlinked sender cannot unlink another wallet
    function test_unlinkWallet_revertForUnlinkedSender() public {
        // Link david and carol to alice's identity via signature
        _linkWalletWithSig(aliceIdentity, alice, david, davidPk);
        _linkWalletWithSig(aliceIdentity, alice, carol, carolPk);

        // Unlink david
        vm.prank(alice);
        onchainidSetup.idFactory.unlinkWallet(david);

        // david (now unlinked but still bound) tries to unlink carol — should revert
        vm.prank(david);
        vm.expectRevert(Errors.OnlyLinkedWalletCanUnlink.selector);
        onchainidSetup.idFactory.unlinkWallet(carol);
    }

    // ============ factory-identity gate ============

    /// @notice linkWalletWithSignature must reject callers that aren't identities deployed by this factory
    function test_linkWalletWithSignature_revertForNonFactoryIdentity() public {
        // Build a valid signature naming a non-factory contract as the identity
        address fakeIdentity = makeAddr("fakeIdentity");
        uint256 expiry = block.timestamp + 1 hours;
        bytes memory signature = _signLinkWallet(davidPk, david, fakeIdentity, 0, expiry);

        // Direct call from fakeIdentity should revert with NotFactoryIdentity
        vm.prank(fakeIdentity);
        vm.expectRevert(abi.encodeWithSelector(Errors.NotFactoryIdentity.selector, fakeIdentity));
        onchainidSetup.idFactory.linkWalletWithSignature(david, signature, 0, expiry);
    }

    // ============ token-wallet collision guard ============

    /// @notice createIdentity must reject a wallet that's already registered as a token
    function test_createIdentity_revertForTokenRegisteredWallet() public {
        // Constants.TOKEN_ADDRESS was registered as a token identity in setUp
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.TokenAlreadyLinked.selector, Constants.TOKEN_ADDRESS));
        onchainidSetup.idFactory
            .createIdentity(Constants.TOKEN_ADDRESS, "tokenWalletSalt", IdentityTypes.INDIVIDUAL, new address[](0));
    }

    /// @notice createIdentityWithManagementKeys must reject a wallet that's already registered as a token
    function test_createIdentityWithManagementKeys_revertForTokenRegisteredWallet() public {
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = ClaimSignerHelper.addressToKey(alice);

        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.TokenAlreadyLinked.selector, Constants.TOKEN_ADDRESS));
        onchainidSetup.idFactory
            .createIdentityWithManagementKeys(
                Constants.TOKEN_ADDRESS, "tokenWalletSalt", keys, IdentityTypes.INDIVIDUAL, new address[](0)
            );
    }

}
