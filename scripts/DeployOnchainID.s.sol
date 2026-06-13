// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Script, console } from "forge-std/Script.sol";

import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import { UpgradeableBeacon } from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {
    ERC7913WebAuthnVerifier
} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913WebAuthnVerifier.sol";
import { Identity } from "contracts/Identity.sol";
import { IdentityUtilities } from "contracts/IdentityUtilities.sol";
import { IIdentityFactory } from "contracts/factory/IIdentityFactory.sol";
import { IdentityFactory } from "contracts/factory/IdentityFactory.sol";
import { ClaimsModule } from "contracts/modules/claims/ClaimsModule.sol";
import { KeyApprovalModule } from "contracts/modules/executors/KeyApprovalModule.sol";
import { ERC7579Signature } from "contracts/modules/validators/ERC7579Signature.sol";
import { IdentityUtilitiesProxy } from "contracts/proxy/IdentityUtilitiesProxy.sol";

/**
 * @title DeployOnchainID
 * @notice Deploys the full OnchainID protocol stack.
 *
 * Deployment order:
 *   1. Identity implementation (library mode)
 *   2. IdentityUtilities implementation + proxy
 *   3. UpgradeableBeacon (points to Identity impl; owned by AccessManager)
 *   4. Module singletons (KeyApprovalModule, ClaimsModule)
 *   5. AccessManager (single source of truth for IdentityFactory permissions)
 *   6. IdentityFactory (BeaconProxy + UpgradeableBeacon for identity proxies)
 *   7. AccessManager role wiring (per-identity-type role mapping)
 *
 * Usage:
 *   forge script scripts/DeployOnchainID.s.sol --rpc-url <RPC> --private-key <PK> --broadcast --verify
 */
contract DeployOnchainID is Script {

    /// @dev Conventional, deployer-chosen role ids. Names are labeled on-chain via
    ///      {AccessManager.labelRole} for explorer/dashboard discoverability.
    uint64 internal constant ROLE_TOKEN_FACTORY = 1;
    uint64 internal constant ROLE_CLAIM_ISSUER_ADMIN = 2;

    function run() external {
        vm.startBroadcast();

        address deployer = msg.sender;
        console.log("Deployer:", deployer);
        console.log("");

        // ===== Phase 1: Implementation contracts =====

        // 1. Validator module singleton — one module, ERC-7913 signer shape, EOA/1271/7913
        //    crypto dispatch via OZ `SignatureChecker`, ACTION purpose enforced against the
        //    calling account's ERC-734 registry.
        ERC7579Signature signatureValidator = new ERC7579Signature();
        console.log("ERC7579Signature Validator:", address(signatureValidator));

        // 2. Identity implementation (library mode — prevents direct initialization)
        Identity identityImpl = new Identity(deployer, true);
        console.log("Identity implementation:", address(identityImpl));

        // 3. IdentityUtilities implementation + proxy
        IdentityUtilities utilitiesImpl = new IdentityUtilities();
        IdentityUtilitiesProxy utilitiesProxy = new IdentityUtilitiesProxy(
            address(utilitiesImpl), abi.encodeCall(IdentityUtilities.initialize, (deployer))
        );
        console.log("IdentityUtilities implementation:", address(utilitiesImpl));
        console.log("IdentityUtilities proxy:", address(utilitiesProxy));

        // ===== Phase 2: Infrastructure =====

        // 4. UpgradeableBeacon (beacon for identity proxies). Owned by the deployer
        //    initially; transferred to the AccessManager below so upgrades go through
        //    role gating.
        UpgradeableBeacon beacon = new UpgradeableBeacon(address(identityImpl), deployer);
        console.log("Beacon:", address(beacon));

        // 4b. Module singletons. Callers include these in their `_modules` array on
        //     `createIdentity` to opt into the legacy ERC-734 execute/approve queue
        //     (KeyApprovalModule) and the full ERC-735 claim surface (ClaimsModule).
        KeyApprovalModule keyApprovalModule = new KeyApprovalModule();
        console.log("KeyApprovalModule:", address(keyApprovalModule));
        ClaimsModule claimsModule = new ClaimsModule();
        console.log("ClaimsModule:", address(claimsModule));

        // 5. AccessManager — single source of truth for IdentityFactory permissions.
        //    The deployer starts as the AccessManager admin (`ADMIN_ROLE = 0`). Production
        //    deployments should rotate this to a multisig immediately via
        //    `am.grantRole(0, multisig, 0); am.revokeRole(0, deployer);`.
        AccessManager am = new AccessManager(deployer);
        console.log("AccessManager:", address(am));

        // Label roles so explorers and ops dashboards can show human names.
        am.labelRole(ROLE_TOKEN_FACTORY, "TOKEN_FACTORY");
        am.labelRole(ROLE_CLAIM_ISSUER_ADMIN, "CLAIM_ISSUER_ADMIN");

        // 6. IdentityFactory
        IdentityFactory idFactory = new IdentityFactory(address(beacon), address(am));
        console.log("IdentityFactory:", address(idFactory));

        // Hand the beacon to the AccessManager so future implementation upgrades
        // (`beacon.upgradeTo(newImpl)`) go through the same role gating as everything else.
        beacon.transferOwnership(address(am));

        // ===== Phase 3: AccessManager target-function wiring =====
        // The factory's two deploy paths are both `restricted`. Gating happens at the
        // AM via `setTargetFunctionRole(target, [selector], roleId)`:
        //   - createIdentity (self-deploy) -> PUBLIC_ROLE (anyone can self-deploy).
        //   - createIdentityFor            -> ROLE_TOKEN_FACTORY (only registered factories).
        // Operators can re-point either selector at a different role later.
        bytes4[] memory createSelector = new bytes4[](1);
        createSelector[0] = IIdentityFactory.createIdentity.selector;
        am.setTargetFunctionRole(address(idFactory), createSelector, am.PUBLIC_ROLE());

        bytes4[] memory createForSelector = new bytes4[](1);
        createForSelector[0] = IIdentityFactory.createIdentityFor.selector;
        am.setTargetFunctionRole(address(idFactory), createForSelector, ROLE_TOKEN_FACTORY);

        // 7. ERC-7913 WebAuthn Verifier (stateless — verifies P-256 WebAuthn assertions on-chain)
        ERC7913WebAuthnVerifier webAuthnVerifier = new ERC7913WebAuthnVerifier();
        console.log("ERC7913WebAuthnVerifier:", address(webAuthnVerifier));

        vm.stopBroadcast();

        // ===== Summary =====
        console.log("");
        console.log("========== Deployment Summary ==========");
        console.log("Identity impl:          ", address(identityImpl));
        console.log("IdentityUtilities impl: ", address(utilitiesImpl));
        console.log("IdentityUtilities proxy:", address(utilitiesProxy));
        console.log("Beacon:                 ", address(beacon));
        console.log("AccessManager:          ", address(am));
        console.log("IdentityFactory:        ", address(idFactory));
        console.log("ERC7579Signature:       ", address(signatureValidator));
        console.log("KeyApprovalModule:      ", address(keyApprovalModule));
        console.log("ClaimsModule:           ", address(claimsModule));
        console.log("ERC7913WebAuthnVerifier:", address(webAuthnVerifier));
        console.log("=========================================");
    }

}
