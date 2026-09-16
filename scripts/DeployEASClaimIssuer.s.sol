// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IIdentityFactory } from "contracts/factory/IIdentityFactory.sol";
import { EASClaimIssuer } from "contracts/modules/claims/EASClaimIssuer.sol";
import { IEAS } from "contracts/vendor/eas/IEAS.sol";
import { Script, console } from "forge-std/Script.sol";

/// @title DeployEASClaimIssuer
/// @notice Deploys the stateless EAS claim-issuer adapter (a singleton, not installed
///         per identity). Reads attestations live from EAS and translates them into
///         OnchainID claims.
///
/// Env:
///   DEPLOYER_PRIVATE_KEY  broadcast signer
///   EAS_AUTHORITY         AccessManager backing `restricted` setters
///   EAS_FACTORY           the IdentityFactory
///
/// Usage:
///   forge script scripts/DeployEASClaimIssuer.s.sol --rpc-url baseSepolia --broadcast
contract DeployEASClaimIssuer is Script {

    // Canonical EAS on Base Sepolia / Base mainnet.
    address internal constant EAS = 0x4200000000000000000000000000000000000021;

    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address authority = vm.envAddress("EAS_AUTHORITY");
        address factory = vm.envAddress("EAS_FACTORY");

        vm.startBroadcast(deployerKey);

        EASClaimIssuer adapter = new EASClaimIssuer(authority, IEAS(EAS), IIdentityFactory(factory));

        vm.stopBroadcast();

        console.log("EASClaimIssuer:", address(adapter));
        console.log("EAS:", EAS);
        console.log("Factory:", factory);
        console.log("Authority:", authority);
    }

}
