// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IERC734 } from "contracts/interface/IERC734.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { OnchainIDSetup } from "test/helpers/OnchainIDSetup.sol";

/// @notice Every IERC734 member must be callable through the interface type on a deployed
///         identity, with the declared return shapes decoding. This is what a third-party
///         caller trusting supportsInterface(IERC734) actually does.
contract IERC734SurfaceTest is OnchainIDSetup {

    function test_everyIERC734MemberAnswersThroughTheInterface() public {
        IERC734 id = IERC734(address(aliceIdentity));
        bytes32 aliceKey = keccak256(abi.encodePacked(alice));

        assertTrue(id.keyHasPurpose(aliceKey, KeyPurposes.MANAGEMENT));
        (uint256[] memory purposes,,) = id.getKey(aliceKey);
        assertGt(purposes.length, 0);
        assertGt(id.getKeyPurposes(aliceKey).length, 0);
        assertGt(id.getKeysByPurpose(KeyPurposes.MANAGEMENT).length, 0);

        bytes32 davidKey = keccak256(abi.encodePacked(david));
        vm.prank(alice);
        assertTrue(id.addKey(davidKey, KeyPurposes.CLAIM_SIGNER, KeyTypes.ECDSA));
        vm.prank(alice);
        assertTrue(id.removeKey(davidKey, KeyPurposes.CLAIM_SIGNER));
    }

}
