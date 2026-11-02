// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { MODULE_TYPE_FALLBACK } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Identity } from "contracts/Identity.sol";
import { IIdentityUtilities } from "contracts/interface/IIdentityUtilities.sol";
import { Erc8100Module } from "contracts/modules/fallbacks/Erc8100Module.sol";
import { Script, console } from "forge-std/Script.sol";

/// @title DeployErc8100Module
/// @notice Deploys the ERC-8100 {Erc8100Module} (or reuses one) and installs it on one
///         identity as six ERC-7579 fallbacks, one per selector the XML template binds.
///
/// The module is a stateless singleton: one deployment per chain serves every identity. Set
/// ERC8100_MODULE to reuse an existing one; leave it unset to deploy a fresh one.
///
/// Env:
///   DEPLOYER_PRIVATE_KEY         private key of a MANAGEMENT key holder on `IDENTITY`
///   IDENTITY                     identity to install on
///   IDENTITY_UTILITIES           the topic schema registry proxy (only read when deploying)
///   ERC8100_MODULE   optional, an already deployed module to install instead
///
/// Usage:
///   forge script scripts/DeployErc8100Module.s.sol --rpc-url baseSepolia --broadcast
contract DeployErc8100Module is Script {

    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address payable identity = payable(vm.envAddress("IDENTITY"));
        address existingModule = vm.envOr("ERC8100_MODULE", address(0));
        require(identity != address(0), "IDENTITY not set");

        vm.startBroadcast(deployerKey);

        address module = existingModule;
        if (module == address(0)) {
            IIdentityUtilities identityUtilities = IIdentityUtilities(vm.envAddress("IDENTITY_UTILITIES"));
            module = address(new Erc8100Module(identityUtilities));
        }

        bytes4[6] memory selectors = [
            Erc8100Module.stateXmlTemplate.selector,
            Erc8100Module.claimTopics.selector,
            bytes4(keccak256("keys()")),
            bytes4(keccak256("keys(uint256,uint256)")),
            bytes4(keccak256("claims()")),
            bytes4(keccak256("claims(uint256,uint256)"))
        ];
        for (uint256 i = 0; i < selectors.length; i++) {
            Identity(identity).installModule(MODULE_TYPE_FALLBACK, module, abi.encodePacked(selectors[i]));
        }

        vm.stopBroadcast();

        console.log("Erc8100Module:", module);
        console.log("Installed on identity:", identity);
    }

}
