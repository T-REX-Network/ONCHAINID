// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ERC7579Utils } from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {
    IERC7579Execution,
    IERC7579Module,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { BeaconProxy } from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import { Identity } from "contracts/Identity.sol";
import { IERC734 } from "contracts/interface/IERC734.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Structs } from "contracts/storage/Structs.sol";

import { OnchainIDSetup } from "./helpers/OnchainIDSetup.sol";

/// @notice Fallback uninstall runs `onUninstall` with the module's key already removed.
///         The key comes back only when another install of that same module still needs it.
contract SmartAccountFallbackAuthorityTest is OnchainIDSetup {

    bytes4 internal constant PING = 0x12345678;
    bytes4 internal constant PONG = 0x12345679;

    /// @notice The last selector is the whole install. The callback cannot grant a key
    ///         or remove the manager, and the module key is gone afterwards.
    function test_lastFallbackUninstallCannotReplaceManager() public {
        address attacker = makeAddr("fallbackAttacker");
        ManagerReplacingModule module = new ManagerReplacingModule(attacker, alice);
        _installFallback(module, PING);
        _grantModuleKey(address(module));

        vm.prank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PING));

        assertFalse(aliceIdentity.isModuleInstalled(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PING)));
        assertEq(_storedKey(aliceIdentity, attacker), bytes32(0));
        assertTrue(_hasManagement(aliceIdentity, alice));
        assertFalse(_hasManagement(aliceIdentity, address(module)));

        vm.prank(address(module));
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC7579Utils.ERC7579UninstalledModule.selector, MODULE_TYPE_EXECUTOR, address(module)
            )
        );
        IERC7579Execution(address(aliceIdentity))
            .executeFromExecutor(bytes32(0), abi.encodePacked(address(this), uint256(0), bytes("")));

        vm.prank(address(module));
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(attacker)),
            KeyPurposes.MANAGEMENT,
            KeyTypes.ECDSA,
            abi.encodePacked(attacker),
            ""
        );
    }

    /// @notice Dropping one selector of a module that is still an executor restores the key
    ///         after the callback. The callback itself does not get to use it.
    function test_selectorDropWhileExecutorRemainsRestoresKeyAfterCallback() public {
        address attacker = makeAddr("executorAttacker");
        ManagerReplacingModule module = new ManagerReplacingModule(attacker, alice);

        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(module), "");
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(module))),
            KeyPurposes.MANAGEMENT,
            KeyTypes.MODULE,
            abi.encodePacked(address(module)),
            ""
        );
        aliceIdentity.installModule(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PING));
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PING));
        vm.stopPrank();

        assertEq(_storedKey(aliceIdentity, attacker), bytes32(0));
        assertTrue(_hasManagement(aliceIdentity, alice));
        assertTrue(_hasManagement(aliceIdentity, address(module)));
        assertTrue(aliceIdentity.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(module), ""));
        assertFalse(aliceIdentity.isModuleInstalled(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PING)));

        CallCounter counter = new CallCounter();
        vm.prank(address(module));
        IERC7579Execution(address(aliceIdentity))
            .executeFromExecutor(
                bytes32(0), abi.encodePacked(address(counter), uint256(0), abi.encodeCall(CallCounter.increment, ()))
            );
        assertEq(counter.count(), 1);
    }

    /// @notice A second selector recorded by this account is enough to put the key back.
    ///         The callback still runs without it.
    function test_selectorDropWhileAnotherFallbackRemainsRestoresKey() public {
        address attacker = makeAddr("secondSelectorAttacker");
        ManagerReplacingModule module = new ManagerReplacingModule(attacker, alice);
        _installFallback(module, PING);
        _installFallback(module, PONG);
        _grantModuleKey(address(module));

        vm.prank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PING));

        assertFalse(aliceIdentity.isModuleInstalled(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PING)));
        assertTrue(aliceIdentity.isModuleInstalled(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PONG)));
        assertEq(_storedKey(aliceIdentity, attacker), bytes32(0));
        assertTrue(_hasManagement(aliceIdentity, alice));
        assertTrue(_hasManagement(aliceIdentity, address(module)));
    }

    /// @notice A validator install of the same module is the same kind of reason to restore.
    function test_selectorDropWhileValidatorRemainsRestoresKey() public {
        address attacker = makeAddr("validatorAttacker");
        ManagerReplacingModule module = new ManagerReplacingModule(attacker, alice);

        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_VALIDATOR, address(module), "");
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(module))),
            KeyPurposes.MANAGEMENT,
            KeyTypes.MODULE,
            abi.encodePacked(address(module)),
            ""
        );
        aliceIdentity.installModule(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PING));
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PING));
        vm.stopPrank();

        assertTrue(aliceIdentity.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(module), ""));
        assertEq(_storedKey(aliceIdentity, attacker), bytes32(0));
        assertTrue(_hasManagement(aliceIdentity, alice));
        assertTrue(_hasManagement(aliceIdentity, address(module)));
    }

    /// @notice The purpose carried on the install is enough. No later `addKey` is required
    ///         for the callback to be dangerous, and the callback still cannot use it.
    function test_fallbackInstalledWithPurposeCannotReplaceManager() public {
        address attacker = makeAddr("initAttacker");
        address manager = makeAddr("initManager");
        ManagerReplacingModule module = new ManagerReplacingModule(attacker, manager);

        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1);
        keys[0] = _managementKey(manager);
        Structs.ModuleInstall[] memory modules = new Structs.ModuleInstall[](2);
        modules[0] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_VALIDATOR,
            module: address(onchainidSetup.signatureValidator),
            initData: "",
            purpose: 0
        });
        modules[1] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: address(module),
            initData: abi.encodePacked(PING),
            purpose: KeyPurposes.MANAGEMENT
        });

        Identity id = Identity(
            payable(address(
                    new BeaconProxy(
                        address(getBeacon()),
                        abi.encodeCall(Identity.initialize, (IdentityTypes.INDIVIDUAL, keys, modules))
                    )
                ))
        );

        assertEq(id.getKeysByPurpose(KeyPurposes.MANAGEMENT).length, 1);
        assertTrue(_hasManagement(id, manager));
        assertTrue(_hasManagement(id, address(module)));

        vm.prank(manager);
        id.uninstallModule(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PING));

        assertEq(id.getKeysByPurpose(KeyPurposes.MANAGEMENT).length, 1);
        assertTrue(_hasManagement(id, manager));
        assertFalse(_hasManagement(id, attacker));
        assertFalse(_hasManagement(id, address(module)));
    }

    /// @notice An identity upgraded before the selector count existed stores zero. Dropping
    ///         one selector of a fallback-only module then removes the key, because the
    ///         account cannot see the selectors it did not count. The manager regrants it.
    function test_legacyFallbackCountDropsKeyWhileAnotherSelectorRemains() public {
        address attacker = makeAddr("legacyAttacker");
        ManagerReplacingModule module = new ManagerReplacingModule(attacker, alice);
        _installFallback(module, PING);
        _installFallback(module, PONG);
        _grantModuleKey(address(module));
        vm.store(address(aliceIdentity), _selectorCountSlot(address(module)), bytes32(0));

        vm.prank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PING));

        assertTrue(aliceIdentity.isModuleInstalled(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PONG)));
        assertEq(_storedKey(aliceIdentity, attacker), bytes32(0));
        assertTrue(_hasManagement(aliceIdentity, alice));
        assertFalse(_hasManagement(aliceIdentity, address(module)));

        vm.prank(address(module));
        vm.expectRevert(Errors.SenderDoesNotHaveManagementKey.selector);
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(attacker)),
            KeyPurposes.MANAGEMENT,
            KeyTypes.ECDSA,
            abi.encodePacked(attacker),
            ""
        );
    }

    /// @notice The same zero count still puts the key back when the executor install is there.
    ///         That install is visible without the counter.
    function test_legacyFallbackCountRestoresKeyWhenExecutorRemains() public {
        address attacker = makeAddr("legacyExecutorAttacker");
        ManagerReplacingModule module = new ManagerReplacingModule(attacker, alice);

        vm.startPrank(alice);
        aliceIdentity.installModule(MODULE_TYPE_EXECUTOR, address(module), "");
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(address(module))),
            KeyPurposes.MANAGEMENT,
            KeyTypes.MODULE,
            abi.encodePacked(address(module)),
            ""
        );
        aliceIdentity.installModule(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PING));
        vm.stopPrank();
        vm.store(address(aliceIdentity), _selectorCountSlot(address(module)), bytes32(0));

        vm.prank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PING));

        assertTrue(aliceIdentity.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(module), ""));
        assertEq(_storedKey(aliceIdentity, attacker), bytes32(0));
        assertTrue(_hasManagement(aliceIdentity, alice));
        assertTrue(_hasManagement(aliceIdentity, address(module)));
    }

    /// @notice A selector that was never installed reverts the whole uninstall. The key
    ///         and the real selector stay, and the count is still there for the next drop.
    function test_uninstallOfMissingSelectorLeavesKeyInPlace() public {
        address attacker = makeAddr("missingSelectorAttacker");
        ManagerReplacingModule module = new ManagerReplacingModule(attacker, alice);
        _installFallback(module, PING);
        _installFallback(module, PONG);
        _grantModuleKey(address(module));

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC7579Utils.ERC7579UninstalledModule.selector, MODULE_TYPE_FALLBACK, address(module)
            )
        );
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(bytes4(0xdeadbeef)));

        assertTrue(aliceIdentity.isModuleInstalled(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PING)));
        assertTrue(aliceIdentity.isModuleInstalled(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PONG)));
        assertTrue(_hasManagement(aliceIdentity, address(module)));
        assertTrue(_hasManagement(aliceIdentity, alice));
        assertEq(_storedKey(aliceIdentity, attacker), bytes32(0));

        // One of the two counted selectors can still come off without losing the key.
        vm.prank(alice);
        aliceIdentity.uninstallModule(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PING));
        assertTrue(_hasManagement(aliceIdentity, address(module)));
        assertTrue(aliceIdentity.isModuleInstalled(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(PONG)));
    }

    function _installFallback(ManagerReplacingModule module, bytes4 selector) internal {
        vm.prank(alice);
        aliceIdentity.installModule(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(selector));
    }

    function _grantModuleKey(address module) internal {
        vm.prank(alice);
        aliceIdentity.addKeyWithData(
            keccak256(abi.encodePacked(module)), KeyPurposes.MANAGEMENT, KeyTypes.MODULE, abi.encodePacked(module), ""
        );
    }

    /// @dev The account does not expose the selector count. This is its namespaced slot.
    ///      An upgrade from before the count existed reads zero here.
    function _selectorCountSlot(address module) internal pure returns (bytes32) {
        bytes32 namespace = keccak256(abi.encode(uint256(keccak256("onchainid.SmartAccount.FallbackInstall")) - 1))
            & ~bytes32(uint256(0xff));
        return keccak256(abi.encode(module, namespace));
    }

    function _managementKey(address who) internal pure returns (Structs.KeyParam memory) {
        bytes memory signer = abi.encodePacked(who);
        return Structs.KeyParam({
            keyHash: keccak256(signer),
            purpose: KeyPurposes.MANAGEMENT,
            keyType: KeyTypes.ECDSA,
            signerData: signer,
            clientData: ""
        });
    }

    function _hasManagement(Identity id, address who) internal view returns (bool) {
        return id.keyHasPurpose(keccak256(abi.encodePacked(who)), KeyPurposes.MANAGEMENT);
    }

    function _storedKey(Identity id, address who) internal view returns (bytes32 key) {
        (,, key) = id.getKey(keccak256(abi.encodePacked(who)));
    }

}

/// @notice On uninstall, grants `attacker` management and removes `manager`.
///         The account is `msg.sender`. Both writes need the module's own key, so they
///         revert together when that key is already off the account.
contract ManagerReplacingModule is IERC7579Module {

    address public immutable attacker;
    address public immutable manager;

    constructor(address attacker_, address manager_) {
        attacker = attacker_;
        manager = manager_;
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR || moduleTypeId == MODULE_TYPE_FALLBACK
            || moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function onInstall(bytes calldata) external pure { }

    function onUninstall(bytes calldata) external {
        IAddKeyWithData(msg.sender)
            .addKeyWithData(
                keccak256(abi.encodePacked(attacker)),
                KeyPurposes.MANAGEMENT,
                KeyTypes.ECDSA,
                abi.encodePacked(attacker),
                ""
            );
        IERC734(msg.sender).removeKey(keccak256(abi.encodePacked(manager)), KeyPurposes.MANAGEMENT);
    }

}

interface IAddKeyWithData {

    function addKeyWithData(
        bytes32 key,
        uint256 purpose,
        uint256 keyType,
        bytes memory signerData,
        bytes memory clientData
    ) external;

}

/// @notice External target used to show an executor can still dispatch after its key returns.
contract CallCounter {

    uint256 public count;

    function increment() external {
        count++;
    }

}
