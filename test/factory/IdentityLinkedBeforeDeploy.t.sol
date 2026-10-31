// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { InteroperableAddress } from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import { IIdentityFactory } from "contracts/factory/IIdentityFactory.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Structs } from "contracts/storage/Structs.sol";

/// @notice An identity's address is known before it is deployed (CREATE3), so it can be linked
///         as a wallet of another identity first. Deploying it must take the address back.
contract IdentityLinkedBeforeDeployTest is OnchainIDSetup {

    string internal constant VICTIM_SALT = "victim";

    address internal victim;
    address internal squatter;
    address internal predictedIdentity;
    address internal squattingIdentity;

    function setUp() public override {
        super.setUp();
        victim = makeAddr("victim");
        squatter = makeAddr("squatter");

        // Learn the address the victim's deploy lands at, then roll the deploy back. The rollback
        // also resets this contract's storage, so the address is carried in a local.
        uint256 beforeDeploy = vm.snapshotState();
        vm.prank(victim);
        address predicted =
            onchainidSetup.idFactory.createIdentity(IdentityTypes.INDIVIDUAL, VICTIM_SALT, _managementKeys(victim));
        vm.revertToState(beforeDeploy);
        predictedIdentity = predicted;

        // INDIVIDUAL is open to anyone through createIdentityFor in the test setup.
        vm.prank(squatter);
        squattingIdentity = onchainidSetup.idFactory
            .createIdentityFor(predictedIdentity, IdentityTypes.INDIVIDUAL, "squat", _managementKeys(predictedIdentity));
    }

    function test_deploy_revokesALinkMadeBeforeDeploy() public {
        bytes memory predictedAccount = _account(predictedIdentity);
        assertEq(onchainidSetup.idFactory.getAccountsCount(squattingIdentity), 1);

        vm.expectEmit(address(onchainidSetup.idFactory));
        emit IIdentityFactory.AccountRevoked(predictedAccount, squattingIdentity, victim);
        vm.prank(victim);
        address deployed =
            onchainidSetup.idFactory.createIdentity(IdentityTypes.INDIVIDUAL, VICTIM_SALT, _managementKeys(victim));

        assertEq(deployed, predictedIdentity);
        assertEq(onchainidSetup.idFactory.getAccountsCount(squattingIdentity), 0);
        assertEq(onchainidSetup.idFactory.getIdentity(predictedAccount), predictedIdentity);
        (address resolved, IIdentityFactory.AccountStatus status) =
            onchainidSetup.idFactory.getIdentityIncludingRevoked(predictedAccount);
        assertEq(resolved, predictedIdentity);
        assertEq(uint256(status), uint256(IIdentityFactory.AccountStatus.Active));
    }

    function test_deploy_resolvesToItselfWhenTheEarlierLinkWasAlreadyRevoked() public {
        bytes memory predictedAccount = _account(predictedIdentity);
        vm.prank(squattingIdentity);
        onchainidSetup.idFactory.revokeAccount(predictedAccount);

        vm.prank(victim);
        onchainidSetup.idFactory.createIdentity(IdentityTypes.INDIVIDUAL, VICTIM_SALT, _managementKeys(victim));

        assertEq(onchainidSetup.idFactory.getAccountsCount(squattingIdentity), 0);
        assertEq(onchainidSetup.idFactory.getIdentity(predictedAccount), predictedIdentity);
    }

    function _account(address wallet) internal view returns (bytes memory) {
        return InteroperableAddress.formatEvmV1(block.chainid, wallet);
    }

    function _managementKeys(address wallet) internal pure returns (Structs.KeyParam[] memory keys) {
        keys = new Structs.KeyParam[](1);
        keys[0] = Structs.KeyParam({
            keyHash: keccak256(abi.encodePacked(wallet)),
            purpose: KeyPurposes.MANAGEMENT,
            keyType: KeyTypes.ECDSA,
            signerData: abi.encodePacked(wallet),
            clientData: ""
        });
    }

}
