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
import { IdentityFactory } from "contracts/factory/IdentityFactory.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyApprovalModule } from "contracts/modules/executors/KeyApprovalModule.sol";
import { ERC734Validator } from "contracts/modules/validators/ERC734Validator.sol";
import { IdentityUtilitiesProxy } from "contracts/proxy/IdentityUtilitiesProxy.sol";
import { ReputationRegistry } from "contracts/reputation/ReputationRegistry.sol";

/**
 * @title DeployOnchainID
 * @notice Deploys the full OnchainID protocol stack.
 *
 * Deployment order:
 *   1. Identity implementation (library mode)
 *   2. IdentityUtilities implementation + proxy
 *   3. UpgradeableBeacon (points to Identity impl; owned by AccessManager)
 *   4. Module singletons (KeyApprovalModule; claims live in the ERC734Validator)
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
        //
        // Note: the ERC734Validator singleton is deployed later (Phase 2), after the
        // IdentityFactory and ReputationRegistry exist, because its constructor takes both —
        // it holds the ERC-734 key registry AND the ERC-735 claim surface, including the
        // trusted-issuer addClaim path that consults the factory and the registry.

        // 1. The Identity implementation now takes the registry module (the ERC734Validator) in its
        //    constructor, and the validator needs the factory, which needs the beacon. It is
        //    therefore deployed in Phase 2, after the validator exists, and the beacon is pointed at
        //    it via `upgradeTo`.

        // 3. IdentityUtilities implementation + proxy
        IdentityUtilities utilitiesImpl = new IdentityUtilities();
        IdentityUtilitiesProxy utilitiesProxy = new IdentityUtilitiesProxy(
            address(utilitiesImpl), abi.encodeCall(IdentityUtilities.initialize, (deployer))
        );
        console.log("IdentityUtilities implementation:", address(utilitiesImpl));
        console.log("IdentityUtilities proxy:", address(utilitiesProxy));

        // ===== Phase 2: Infrastructure =====

        // 4b. KeyApprovalModule (the legacy ERC-734 execute/approve queue, no deps). Callers
        //     include it in their `_modules` array on `createIdentity` to opt into the legacy
        //     ERC-734 execute/approve queue. The ERC-735 claim surface lives in the
        //     ERC734Validator deployed below, installed as claim fallbacks.
        KeyApprovalModule keyApprovalModule = new KeyApprovalModule();
        console.log("KeyApprovalModule:", address(keyApprovalModule));

        // 4. UpgradeableBeacon (beacon for identity proxies). Owned by the deployer initially;
        //    transferred to the AccessManager below. It starts pointing at a throwaway
        //    implementation (any contract) and is upgraded to the real Identity implementation once
        //    the validator exists, breaking the impl <- validator <- factory <- beacon <- impl cycle.
        UpgradeableBeacon beacon = new UpgradeableBeacon(address(keyApprovalModule), deployer);
        console.log("Beacon:", address(beacon));

        // 5. AccessManager. Single source of truth for IdentityFactory and
        //    ReputationRegistry permissions. The deployer starts as the AccessManager admin
        //    (`ADMIN_ROLE = 0`). Production deployments should rotate this to a multisig
        //    immediately via `am.grantRole(0, multisig, 0); am.revokeRole(0, deployer);`.
        AccessManager am = new AccessManager(deployer);
        console.log("AccessManager:", address(am));

        // Label roles so explorers and ops dashboards can show human names.
        am.labelRole(ROLE_TOKEN_FACTORY, "TOKEN_FACTORY");
        am.labelRole(ROLE_CLAIM_ISSUER_ADMIN, "CLAIM_ISSUER_ADMIN");

        // 6. IdentityFactory
        IdentityFactory idFactory = new IdentityFactory(address(beacon), address(am));
        console.log("IdentityFactory:", address(idFactory));

        // 6b. ReputationRegistry. Needs the factory address so its lazy default-tier
        //     fallback can gate on factory membership. Writes are restricted via the AM.
        ReputationRegistry reputationRegistry = new ReputationRegistry(address(am), address(idFactory));
        console.log("ReputationRegistry:", address(reputationRegistry));

        // 6c. Validator module singleton — one module, ERC-7913 signer shape, EOA/1271/7913
        //     crypto dispatch via OZ `SignatureChecker`, ACTION purpose enforced against the
        //     calling account's ERC-734 registry. It also holds the ERC-735 claim surface,
        //     so it needs the factory and the registry for the trusted-issuer addClaim path.
        ERC734Validator signatureValidator = new ERC734Validator(address(idFactory), address(reputationRegistry));
        console.log("ERC734Validator:", address(signatureValidator));

        // Now the real Identity implementation, wired to the registry module, and point the beacon
        // at it. The constructor calls `_disableInitializers()`, so the implementation itself can
        // never be initialized directly.
        Identity identityImpl = new Identity(address(signatureValidator));
        console.log("Identity implementation:", address(identityImpl));
        beacon.upgradeTo(address(identityImpl));

        // Hand the beacon to the AccessManager so future implementation upgrades
        // (`beacon.upgradeTo(newImpl)`) go through the same role gating as everything else.
        beacon.transferOwnership(address(am));

        // ===== Phase 3: per-identity-type deploy policy =====
        // Each type carries a policy: an AM role id (gates createIdentityFor) and a
        // selfDeployable flag (gates createIdentity). Unregistered types revert from
        // both entry points.
        //
        // Contract-shaped types (ASSET, SMART_CONTRACT, PUBLIC_AUTHORITY) opt out of
        // self-deploy because their identity represents a contract, not msg.sender.
        // CLAIM_ISSUER also opts out so the admin role on createIdentityFor is not
        // bypassable via self-deploy.
        uint64 publicRole = am.PUBLIC_ROLE();

        // Gated for createIdentityFor; self-deploy disabled.
        idFactory.setIdentityTypePolicy(IdentityTypes.ASSET, ROLE_TOKEN_FACTORY, false);
        idFactory.setIdentityTypePolicy(IdentityTypes.CLAIM_ISSUER, ROLE_CLAIM_ISSUER_ADMIN, false);

        // Open for createIdentityFor; self-deploy enabled (EOA-shaped types).
        idFactory.setIdentityTypePolicy(IdentityTypes.INDIVIDUAL, publicRole, true);
        idFactory.setIdentityTypePolicy(IdentityTypes.CORPORATE, publicRole, true);
        idFactory.setIdentityTypePolicy(IdentityTypes.IOT, publicRole, true);
        idFactory.setIdentityTypePolicy(IdentityTypes.AI_AGENT, publicRole, true);

        // Open for createIdentityFor; self-deploy disabled (contract-shaped /
        // institutional types).
        idFactory.setIdentityTypePolicy(IdentityTypes.SMART_CONTRACT, publicRole, false);
        idFactory.setIdentityTypePolicy(IdentityTypes.PUBLIC_AUTHORITY, publicRole, false);

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
        console.log("ERC734Validator:        ", address(signatureValidator));
        console.log("KeyApprovalModule:      ", address(keyApprovalModule));
        console.log("ERC7913WebAuthnVerifier:", address(webAuthnVerifier));
        console.log("=========================================");
    }

}
