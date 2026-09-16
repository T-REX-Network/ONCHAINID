// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { MODULE_TYPE_EXECUTOR } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Identity } from "contracts/Identity.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { RecoveryModule } from "contracts/modules/executors/RecoveryModule.sol";
import { Script, console } from "forge-std/Script.sol";

/// @title DeployRecoveryModule
/// @notice Deploys the social {RecoveryModule} and installs it on one identity.
///
/// The module is deployed fresh (`new RecoveryModule()`), so every run mints a new
/// address — there is deliberately no shared RecoveryModule. It is installed as an
/// ERC-7579 executor (type 2) and then granted a MANAGEMENT MODULE key, matching the
/// two-transaction `prepareInstallRecovery` flow in identity-sdk.
///
/// Env:
///   DEPLOYER_PRIVATE_KEY  private key of a MANAGEMENT key holder on `RECOVERY_IDENTITY`
///   RECOVERY_IDENTITY     identity to protect
///   RECOVERY_GUARDIANS    comma-separated guardian addresses
///   RECOVERY_THRESHOLD    weighted threshold (1..sum of weights)
///   RECOVERY_DELAY        uint32 seconds before a scheduled recovery can run
///   RECOVERY_EXPIRATION   uint32 seconds after which a scheduled recovery expires
///
/// Usage:
///   forge script scripts/DeployRecoveryModule.s.sol --rpc-url baseSepolia --broadcast
contract DeployRecoveryModule is Script {

    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address payable identity = payable(vm.envAddress("RECOVERY_IDENTITY"));
        address[] memory guardianAddrs = vm.envAddress("RECOVERY_GUARDIANS", ",");
        uint64 threshold = uint64(vm.envUint("RECOVERY_THRESHOLD"));
        uint32 delay = uint32(vm.envUint("RECOVERY_DELAY"));
        uint32 expiration = uint32(vm.envUint("RECOVERY_EXPIRATION"));

        require(identity != address(0), "RECOVERY_IDENTITY not set");
        require(guardianAddrs.length > 0, "RECOVERY_GUARDIANS empty");
        require(threshold > 0 && threshold <= guardianAddrs.length, "threshold unreachable with 1 weight each");

        vm.startBroadcast(deployerKey);

        RecoveryModule module = new RecoveryModule();

        // OpenZeppelin ERC7579SocialRecoveryExecutor.onInstall payload:
        //   [uint16(execArgs.length) || execArgs || uint16(msigArgs.length) || msigArgs]
        //   execArgs = abi.encodePacked(uint32 delay, uint32 expiration)
        //   msigArgs = abi.encode(bytes[] guardians, uint64 threshold, uint64[] weights)
        // Guardians are ERC-7913 signer blobs: for an EOA that is abi.encodePacked(address).
        bytes[] memory guardians = new bytes[](guardianAddrs.length);
        for (uint256 i = 0; i < guardianAddrs.length; i++) {
            guardians[i] = abi.encodePacked(guardianAddrs[i]);
        }
        bytes memory execArgs = abi.encodePacked(delay, expiration);
        uint64[] memory weights = new uint64[](guardians.length);
        for (uint256 i = 0; i < guardians.length; i++) {
            weights[i] = 1;
        }
        bytes memory msigArgs = abi.encode(guardians, threshold, weights);
        bytes memory initData = abi.encodePacked(uint16(execArgs.length), execArgs, uint16(msigArgs.length), msigArgs);

        // 1. Seat the module as an ERC-7579 executor.
        Identity(identity).installModule(MODULE_TYPE_EXECUTOR, address(module), initData);

        // 2. Grant it the MANAGEMENT MODULE key, otherwise the self-targeted
        //    addKeyWithData a recovery dispatches is refused by SmartAccount.
        Identity(identity)
            .addKeyWithData(
                keccak256(abi.encodePacked(address(module))),
                KeyPurposes.MANAGEMENT,
                KeyTypes.MODULE,
                abi.encodePacked(address(module)),
                ""
            );

        vm.stopBroadcast();

        console.log("RecoveryModule:", address(module));
        console.log("Installed on identity:", identity);
        console.log("Guardians:", guardians.length, "threshold:", threshold);
        console.log("delay:", delay, "expiration:", expiration);
    }

}
