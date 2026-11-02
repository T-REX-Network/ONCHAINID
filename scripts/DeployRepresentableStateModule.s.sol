// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { MODULE_TYPE_FALLBACK } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Identity } from "contracts/Identity.sol";
import { IIdentityUtilities } from "contracts/interface/IIdentityUtilities.sol";
import { RepresentableStateModule } from "contracts/modules/fallbacks/RepresentableStateModule.sol";
import { Script, console } from "forge-std/Script.sol";

/// @title DeployRepresentableStateModule
/// @notice Deploys the ERC-8100 {RepresentableStateModule} (or reuses one) and installs it on one
///         identity as four ERC-7579 fallbacks, one per selector the XML template binds.
///
/// The module is a stateless singleton: one deployment per chain serves every identity. Set
/// REPRESENTABLE_STATE_MODULE to reuse an existing one; leave it unset to deploy a fresh one.
///
/// Env:
///   DEPLOYER_PRIVATE_KEY         private key of a MANAGEMENT key holder on `IDENTITY`
///   IDENTITY                     identity to install on
///   IDENTITY_UTILITIES           the topic schema registry proxy (only read when deploying)
///   REPRESENTABLE_STATE_MODULE   optional, an already deployed module to install instead
///
/// Usage:
///   forge script scripts/DeployRepresentableStateModule.s.sol --rpc-url baseSepolia --broadcast
contract DeployRepresentableStateModule is Script {

    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address payable identity = payable(vm.envAddress("IDENTITY"));
        address existingModule = vm.envOr("REPRESENTABLE_STATE_MODULE", address(0));
        require(identity != address(0), "IDENTITY not set");

        vm.startBroadcast(deployerKey);

        address module = existingModule;
        if (module == address(0)) {
            IIdentityUtilities identityUtilities = IIdentityUtilities(vm.envAddress("IDENTITY_UTILITIES"));
            module = address(new RepresentableStateModule(identityUtilities));
        }

        Identity(identity)
            .installModule(
                MODULE_TYPE_FALLBACK, module, abi.encodePacked(RepresentableStateModule.stateXmlTemplate.selector)
            );
        Identity(identity)
            .installModule(
                MODULE_TYPE_FALLBACK, module, abi.encodePacked(RepresentableStateModule.representedTopics.selector)
            );
        Identity(identity)
            .installModule(
                MODULE_TYPE_FALLBACK, module, abi.encodePacked(RepresentableStateModule.representedKeys.selector)
            );
        Identity(identity)
            .installModule(
                MODULE_TYPE_FALLBACK, module, abi.encodePacked(RepresentableStateModule.representedClaims.selector)
            );

        vm.stopBroadcast();

        console.log("RepresentableStateModule:", module);
        console.log("Installed on identity:", identity);
    }

}
