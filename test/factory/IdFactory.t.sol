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
import { ERC7579Signature } from "contracts/modules/validators/ERC7579Signature.sol";
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
        new IdFactory(address(0), deployer, address(0), address(0), address(0));
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

    function test_revertBecauseAccountCannotBeZeroAddress() public {
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

    function test_revertBecauseSaltAlreadyUsed() public {
        vm.prank(deployer);
        onchainidSetup.idFactory
            .createIdentity(
                carol, IdentityTypes.INDIVIDUAL, "saltUsed", new Structs.KeyParam[](0), new Structs.ModuleInstall[](0)
            );

        vm.prank(deployer);
        // Salt-collision now bubbles up from Create3 as FailedDeployment().
        vm.expectRevert(OZErrors.FailedDeployment.selector);
        onchainidSetup.idFactory
            .createIdentity(
                david, IdentityTypes.INDIVIDUAL, "saltUsed", new Structs.KeyParam[](0), new Structs.ModuleInstall[](0)
            );
    }

    function test_revertBecauseAccountAlreadyLinked() public {
        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.AccountAlreadyLinkedToIdentity.selector, alice));
        onchainidSetup.idFactory
            .createIdentity(
                alice, IdentityTypes.INDIVIDUAL, "newSalt", new Structs.KeyParam[](0), new Structs.ModuleInstall[](0)
            );
    }

    /// @notice The factory auto-injects `_account` as a MANAGEMENT key, so an empty user-supplied
    ///         `_keys` array still produces a fully-initialized identity.
    function test_createIdentity_autoInjectsAccountAsManagement() public {
        Structs.KeyParam[] memory emptyKeys = new Structs.KeyParam[](0);
        vm.prank(deployer);
        address identity = onchainidSetup.idFactory
            .createIdentity(david, IdentityTypes.INDIVIDUAL, "salt1", emptyKeys, new Structs.ModuleInstall[](0));
        bytes32 davidKey = keccak256(abi.encodePacked(david));
        assertTrue(
            Identity(payable(identity)).keyHasPurpose(davidKey, KeyPurposes.MANAGEMENT),
            "_account should be auto-injected as MANAGEMENT key"
        );
    }

    // ============ linkAccount ============

    function test_linkAccount_revertForZeroAddress() public {
        vm.prank(alice);
        vm.expectRevert(Errors.ZeroAddress.selector);
        onchainidSetup.idFactory.linkAccount(address(0));
    }

    function test_linkAccount_revertForSenderNotLinked() public {
        vm.prank(david);
        vm.expectRevert(abi.encodeWithSelector(Errors.AccountNotLinkedToIdentity.selector, david));
        onchainidSetup.idFactory.linkAccount(david);
    }

    function test_linkAccount_revertForNewAccountAlreadyLinked() public {
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(Errors.AccountAlreadyLinkedToIdentity.selector, alice));
        onchainidSetup.idFactory.linkAccount(alice);
    }

    function test_linkAccount_revertForNewAccountLinkedToToken() public {
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(Errors.AccountAlreadyLinkedToIdentity.selector, Constants.TOKEN_ADDRESS));
        onchainidSetup.idFactory.linkAccount(Constants.TOKEN_ADDRESS);
    }

    function test_linkAccount_shouldLinkNewAccount() public {
        vm.prank(alice);
        onchainidSetup.idFactory.linkAccount(david);

        address[] memory accounts = onchainidSetup.idFactory.getAccounts(address(aliceIdentity));
        assertEq(accounts.length, 2);
        assertEq(accounts[0], alice);
        assertEq(accounts[1], david);
    }

    // ============ unlinkAccount ============

    function test_unlinkAccount_revertForZeroAddress() public {
        vm.prank(alice);
        vm.expectRevert(Errors.ZeroAddress.selector);
        onchainidSetup.idFactory.unlinkAccount(address(0));
    }

    function test_unlinkAccount_revertForUnlinkingSelf() public {
        vm.prank(alice);
        vm.expectRevert(Errors.CannotBeCalledOnSenderAddress.selector);
        onchainidSetup.idFactory.unlinkAccount(alice);
    }

    function test_unlinkAccount_revertForSenderNotLinked() public {
        vm.prank(david);
        vm.expectRevert(Errors.OnlyLinkedAccountCanUnlink.selector);
        onchainidSetup.idFactory.unlinkAccount(alice);
    }

    function test_unlinkAccount_revertForBothUnlinked() public {
        address unlinkedTarget = makeAddr("unlinkedTarget");
        vm.prank(david);
        vm.expectRevert(abi.encodeWithSelector(Errors.AccountNotLinkedToIdentity.selector, unlinkedTarget));
        onchainidSetup.idFactory.unlinkAccount(unlinkedTarget);
    }

    function test_unlinkAccount_shouldUnlink() public {
        vm.prank(alice);
        onchainidSetup.idFactory.linkAccount(david);

        vm.prank(alice);
        onchainidSetup.idFactory.unlinkAccount(david);

        address[] memory accounts = onchainidSetup.idFactory.getAccounts(address(aliceIdentity));
        assertEq(accounts.length, 1);
        assertEq(accounts[0], alice);
    }

    // ============ getIdentity ============

    /// @notice getIdentity should return token identity for token addresses
    function test_getIdentity_forTokenAddress_shouldReturnTokenIdentity() public view {
        address identity = onchainidSetup.idFactory.getIdentity(Constants.TOKEN_ADDRESS);
        assertTrue(identity != address(0), "Token identity should exist");
    }

    /// @notice getIdentity should return user identity for account addresses
    function test_getIdentity_forUserAccount_shouldReturnUserIdentity() public view {
        address identity = onchainidSetup.idFactory.getIdentity(alice);
        assertEq(identity, address(aliceIdentity), "Should return alice's identity");
    }

    /// @notice getIdentity should return zero for unknown addresses
    function test_getIdentity_forUnknownAddress_shouldReturnZero() public {
        address identity = onchainidSetup.idFactory.getIdentity(makeAddr("unknown"));
        assertEq(identity, address(0), "Should return zero address");
    }

    // ============ unlinkAccount - swap-and-pop ============

    /// @notice Unlinking a account that is not the last in the array exercises swap-and-pop
    function test_unlinkAccount_shouldSwapAndPop() public {
        // Link carol and david to alice's identity
        vm.prank(alice);
        onchainidSetup.idFactory.linkAccount(carol);
        vm.prank(alice);
        onchainidSetup.idFactory.linkAccount(david);

        // accounts = [alice, carol, david]
        // Unlink carol (middle element) -- triggers swap with david
        vm.prank(alice);
        onchainidSetup.idFactory.unlinkAccount(carol);

        address[] memory accounts = onchainidSetup.idFactory.getAccounts(address(aliceIdentity));
        assertEq(accounts.length, 2, "Should have 2 accounts");
        assertEq(accounts[0], alice, "First account should be alice");
        assertEq(accounts[1], david, "Second account should be david (swapped)");
    }

    // ============ createIdentity with management keys (non-account) ============

    function test_createIdentity_withNonAccountManagementKeys_revertZeroAddress() public {
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1);
        keys[0] = _makeECDSAKey(alice, KeyPurposes.MANAGEMENT);

        vm.prank(deployer);
        vm.expectRevert(Errors.ZeroAddress.selector);
        onchainidSetup.idFactory
            .createIdentity(address(0), IdentityTypes.INDIVIDUAL, "salt1", keys, new Structs.ModuleInstall[](0));
    }

    function test_createIdentity_withNonAccountManagementKeys_revertSaltTaken() public {
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1);
        keys[0] = _makeECDSAKey(alice, KeyPurposes.MANAGEMENT);

        vm.prank(deployer);
        onchainidSetup.idFactory
            .createIdentity(david, IdentityTypes.INDIVIDUAL, "sharedSalt", keys, new Structs.ModuleInstall[](0));

        address anotherAccount = makeAddr("anotherAccount");
        vm.prank(deployer);
        // Salt-collision now bubbles up from Create3 as FailedDeployment().
        vm.expectRevert(OZErrors.FailedDeployment.selector);
        onchainidSetup.idFactory
            .createIdentity(
                anotherAccount, IdentityTypes.INDIVIDUAL, "sharedSalt", keys, new Structs.ModuleInstall[](0)
            );
    }

    function test_createIdentity_withNonAccountManagementKeys_revertAccountAlreadyLinked() public {
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1);
        keys[0] = _makeECDSAKey(carol, KeyPurposes.MANAGEMENT);

        vm.prank(deployer);
        vm.expectRevert(abi.encodeWithSelector(Errors.AccountAlreadyLinkedToIdentity.selector, alice));
        onchainidSetup.idFactory
            .createIdentity(alice, IdentityTypes.INDIVIDUAL, "uniqueSalt", keys, new Structs.ModuleInstall[](0));
    }

    function test_createIdentity_withNonAccountManagementKeys_shouldDeployAndSetKeys() public {
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

        // david's MANAGEMENT key is auto-injected by the factory; we only add the CLAIM_ADDER keys.
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](2);
        keys[0] = _makeECDSAKey(claimAdder1, KeyPurposes.CLAIM_ADDER);
        keys[1] = _makeECDSAKey(claimAdder2, KeyPurposes.CLAIM_ADDER);

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

        // Verify management key is still set for account
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
                new Structs.KeyParam[](0),
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
                new Structs.KeyParam[](0),
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
                new Structs.KeyParam[](0),
                new Structs.ModuleInstall[](0)
            );

        Identity identity = Identity(payable(identityAddr));
        assertEq(identity.getIdentityType(), IdentityTypes.PUBLIC_AUTHORITY, "Identity type should be PUBLIC_AUTHORITY");
    }

    // ============ createIdentity with module installation ============

    /// @notice User-supplied modules are appended after the factory's auto-installed default set,
    ///         so a fresh validator passed via `_modules` ends up installed alongside the defaults.
    function test_createIdentity_withModules_shouldInstallUserSuppliedModule() public {
        // Deploy a SECOND validator distinct from the one the factory auto-installs.
        address additionalValidator = address(new ERC7579Signature());

        Structs.ModuleInstall[] memory modules = new Structs.ModuleInstall[](1);
        modules[0] = Structs.ModuleInstall({
            moduleType: 1, // MODULE_TYPE_VALIDATOR
            module: additionalValidator,
            initData: "",
            purpose: 0
        });

        vm.prank(deployer);
        address identityAddr = onchainidSetup.idFactory
            .createIdentity(david, IdentityTypes.INDIVIDUAL, "saltWithModules", new Structs.KeyParam[](0), modules);

        Identity identity = Identity(payable(identityAddr));
        assertTrue(
            identity.isModuleInstalled(1, additionalValidator, ""),
            "user-supplied validator should be installed alongside the factory defaults"
        );
        assertTrue(
            identity.isModuleInstalled(1, address(onchainidSetup.signatureValidator), ""),
            "factory's default validator should also be installed"
        );
    }

    // ============ _deploy CREATE2 failure ============

    /// @notice CREATE2 failure triggers assembly revert when proxy constructor reverts
    function test_createIdentity_revertWhenCreate2Fails() public {
        // Deploy a factory with a reverting implementation
        RevertingIdentity revertingImpl = new RevertingIdentity();
        ImplementationAuthority badAuthority = new ImplementationAuthority(address(revertingImpl), deployer);
        IdFactory badFactory = new IdFactory(address(badAuthority), deployer, address(0), address(0), address(0));

        // createIdentity will try CREATE2 with IdentityProxy whose constructor
        // delegatecalls initialize() on RevertingIdentity, which reverts,
        // causing CREATE2 to return address(0) and triggering assembly revert
        vm.expectRevert();
        badFactory.createIdentity(
            david, IdentityTypes.INDIVIDUAL, "salt1", new Structs.KeyParam[](0), new Structs.ModuleInstall[](0)
        );
    }

}
