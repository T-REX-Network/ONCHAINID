// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { InteroperableAddress } from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import { Identity } from "contracts/Identity.sol";
import { IdentityFactory } from "contracts/factory/IdentityFactory.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Structs } from "contracts/storage/Structs.sol";

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";

/// @notice Self-deploy binds the caller as the wallet, so the keys have to be that
///         wallet's and it has to come out as the only human manager. A single-binding
///         deploy is a contract and skips both checks.
contract SelfDeployManagementTest is OnchainIDSetup {

    function test_createIdentity_rejectsSignerDataForSomeoneElse() public {
        address wallet = makeAddr("wallet");
        address other = makeAddr("otherManager");
        bytes memory envelope = InteroperableAddress.formatEvmV1(block.chainid, wallet);

        vm.prank(wallet);
        vm.expectRevert(abi.encodeWithSelector(Errors.KeyNotForAccount.selector, keccak256(abi.encodePacked(other))));
        _factory().createIdentity(IdentityTypes.INDIVIDUAL, "foreign", _keys(other));

        assertEq(_factory().getIdentity(envelope), address(0));
    }

    function test_createIdentity_acceptsTheCallersOwnManagementKey() public {
        address wallet = makeAddr("wallet");
        address other = makeAddr("otherManager");
        bytes memory envelope = InteroperableAddress.formatEvmV1(block.chainid, wallet);

        vm.prank(wallet);
        Identity id = Identity(payable(_factory().createIdentity(IdentityTypes.INDIVIDUAL, "own", _keys(wallet))));

        assertEq(_factory().getIdentity(envelope), address(id));
        // The queue module holds MANAGEMENT too, and that key is not in the index.
        assertEq(id.getKeysByPurpose(KeyPurposes.MANAGEMENT).length, 1);
        assertTrue(id.keyHasPurpose(keccak256(abi.encodePacked(wallet)), KeyPurposes.MANAGEMENT));
        assertTrue(
            id.keyHasPurpose(
                keccak256(abi.encodePacked(address(onchainidSetup.keyApprovalModule))), KeyPurposes.MANAGEMENT
            )
        );
        assertFalse(id.keyHasPurpose(keccak256(abi.encodePacked(other)), KeyPurposes.MANAGEMENT));

        vm.prank(wallet);
        vm.expectRevert(abi.encodeWithSelector(Errors.WalletBoundToAnotherIdentity.selector, envelope, address(id)));
        _factory().createIdentity(IdentityTypes.INDIVIDUAL, "own-again", _keys(wallet));
    }

    /// @notice A key that is both foreign and typed MODULE still reports the module error.
    ///         The type check runs first, on the derived signer, not on the caller-supplied hash.
    function test_createIdentity_foreignModuleTypedKeyReportsTheModuleError() public {
        address wallet = makeAddr("wallet");
        address other = makeAddr("otherManager");
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1);
        keys[0] = Structs.KeyParam({
            keyHash: keccak256(abi.encodePacked(wallet)),
            purpose: KeyPurposes.MANAGEMENT,
            keyType: KeyTypes.MODULE,
            signerData: abi.encodePacked(other),
            clientData: ""
        });

        vm.prank(wallet);
        vm.expectRevert(
            abi.encodeWithSelector(Errors.CallerKeyCannotBeModule.selector, keccak256(abi.encodePacked(other)))
        );
        _factory().createIdentity(IdentityTypes.INDIVIDUAL, "module-foreign", keys);
        assertEq(_factory().getIdentity(InteroperableAddress.formatEvmV1(block.chainid, wallet)), address(0));
    }

    function test_createIdentityFor_stillRejectsAForeignSigner() public {
        address account = makeAddr("account");

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Errors.KeyNotForAccount.selector, keccak256(abi.encodePacked(alice))));
        _factory().createIdentityFor(account, IdentityTypes.INDIVIDUAL, "foreign-for", _keys(alice));

        vm.prank(alice);
        Identity id = Identity(
            payable(_factory().createIdentityFor(account, IdentityTypes.INDIVIDUAL, "own-for", _keys(account)))
        );
        assertEq(id.getKeysByPurpose(KeyPurposes.MANAGEMENT).length, 1);
        assertTrue(id.keyHasPurpose(keccak256(abi.encodePacked(account)), KeyPurposes.MANAGEMENT));
        assertFalse(id.keyHasPurpose(keccak256(abi.encodePacked(alice)), KeyPurposes.MANAGEMENT));
    }

    /// @notice The bound contract holds no key. The role holder supplies the management key,
    ///         and that is still allowed.
    function test_createIdentityFor_singleBindingSkipsTheWalletKeyCheck() public {
        address asset = makeAddr("assetContract");

        vm.prank(deployer);
        Identity id =
            Identity(payable(_factory().createIdentityFor(asset, IdentityTypes.ASSET, "asset", _keys(tokenOwner))));

        assertTrue(address(id) != address(0));
        assertTrue(id.keyHasPurpose(keccak256(abi.encodePacked(tokenOwner)), KeyPurposes.MANAGEMENT));
        assertEq(_factory().getIdentity(InteroperableAddress.formatEvmV1(block.chainid, asset)), address(id));
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
