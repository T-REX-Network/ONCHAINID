// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { PackedUserOperation } from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import { MODULE_TYPE_VALIDATOR } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Identity } from "contracts/Identity.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";

import { ClaimSignerHelper } from "./helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "./helpers/OnchainIDSetup.sol";

/// @notice Coverage for the SmartAccount execution surface and ERC-734 purpose invariants.
contract SmartAccountTest is OnchainIDSetup {

    /// @notice ACTION key calls execute() on an external target; the queue module auto-approves.
    function test_execute_externalCall_byActionKey_autoApproves() public {
        Counter counter = new Counter();

        vm.prank(david);
        IKeyExecutor(address(aliceIdentity)).execute(address(counter), 0, abi.encodeCall(Counter.increment, ()));

        assertEq(counter.count(), 1, "auto-approved external call should run");
    }

    /// @notice A CLAIM_SIGNER key must not be able to call self-targeted `addKey` through
    ///         execute(): the queue module's auto-approval is bounded to claim selectors only,
    ///         and explicit approval of a self-call requires MANAGEMENT.
    function test_execute_selfCall_byClaimSigner_does_not_escalate_to_addKey() public {
        bytes32 evilKey = keccak256("evil-management-key");
        bytes memory addKeyData = abi.encodeWithSignature(
            "addKey(bytes32,uint256,uint256)", evilKey, KeyPurposes.MANAGEMENT, KeyTypes.ECDSA
        );

        // carol is a CLAIM_SIGNER on aliceIdentity.
        vm.prank(carol);
        IKeyExecutor(address(aliceIdentity)).execute(address(aliceIdentity), 0, addKeyData);

        (,, bytes32 storedKey) = aliceIdentity.getKey(evilKey);
        assertEq(storedKey, bytes32(0), "CLAIM_SIGNER must not escalate to MANAGEMENT via execute/addKey");
    }

    /// @notice Removing the only MANAGEMENT key on an identity must revert — otherwise the
    ///         identity becomes unrecoverable (no caller would satisfy `onlyManager`).
    function test_removeKey_lastManagementKey_reverts() public {
        bytes32 aliceKey = keccak256(abi.encodePacked(alice));

        vm.prank(alice);
        vm.expectRevert(Errors.CannotRemoveLastManagementKey.selector);
        aliceIdentity.removeKey(aliceKey, KeyPurposes.MANAGEMENT);
    }

}

/// @notice Simple counter used as an external target in execute() tests.
contract Counter {

    uint256 public count;

    function increment() external {
        count++;
    }

}
