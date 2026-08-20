// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Script, console } from "forge-std/Script.sol";

import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
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
 * Deployment order (linear — each contract only needs addresses that already exist):
 *   1. IdentityUtilities implementation + proxy
 *   2. KeyApprovalModule (no deps)
 *   3. AccessManager (single source of truth for IdentityFactory permissions)
 *   4. IdentityFactory (commits its beacon CREATE3 slot as an immutable)
 *   5. ReputationRegistry (needs AM + factory)
 *   6. ERC734Validator (needs factory + registry)
 *   7. Identity implementation (needs the validator — its enshrined registry immutable)
 *   8. factory.initializeBeacon (deploys the UpgradeableBeacon at the committed slot)
 *   9. AccessManager role wiring (per-identity-type role mapping)
 *
 * Usage:
 *   forge script scripts/DeployOnchainID.s.sol --rpc-url <RPC> --private-key <PK> --broadcast --verify
 */
contract DeployOnchainID is Script {

    /// @dev Conventional, deployer-chosen role ids. Names are labeled on-chain via
    ///      {AccessManager.labelRole} for explorer/dashboard discoverability.
    uint64 internal constant ROLE_TOKEN_FACTORY = 1;
    uint64 internal constant ROLE_CLAIM_ISSUER_ADMIN = 2;
    uint64 internal constant ROLE_BEACON_UPGRADER = 3;

    /// @dev Execution delay on the beacon upgrade role. A beacon upgrade re-points every
    ///      identity at once, so it is scheduled first and only executable after the delay,
    ///      which gives holders a window to see it coming and the admin a window to cancel.
    uint32 internal constant BEACON_UPGRADE_DELAY = 2 days;

    function run() external {
        vm.startBroadcast();

        address deployer = msg.sender;
        console.log("Deployer:", deployer);
        console.log("");

        // 1. IdentityUtilities implementation + proxy
        IdentityUtilities utilitiesImpl = new IdentityUtilities();
        IdentityUtilitiesProxy utilitiesProxy = new IdentityUtilitiesProxy(
            address(utilitiesImpl), abi.encodeCall(IdentityUtilities.initialize, (deployer))
        );
        console.log("IdentityUtilities implementation:", address(utilitiesImpl));
        console.log("IdentityUtilities proxy:", address(utilitiesProxy));

        // 2. KeyApprovalModule (the legacy ERC-734 execute/approve queue, no deps). Callers
        //    include it in their `_modules` array on `createIdentity` to opt into the legacy
        //    ERC-734 execute/approve queue. The ERC-735 claim surface lives in the
        //    ERC734Validator deployed below, installed as claim fallbacks.
        KeyApprovalModule keyApprovalModule = new KeyApprovalModule();
        console.log("KeyApprovalModule:", address(keyApprovalModule));

        // 3. AccessManager. Single source of truth for IdentityFactory and
        //    ReputationRegistry permissions. The deployer starts as the AccessManager admin
        //    (`ADMIN_ROLE = 0`). Production deployments should rotate this to a multisig
        //    immediately via `am.grantRole(0, multisig, 0); am.revokeRole(0, deployer);`.
        AccessManager am = new AccessManager(deployer);
        console.log("AccessManager:", address(am));

        // Label roles so explorers and ops dashboards can show human names.
        am.labelRole(ROLE_TOKEN_FACTORY, "TOKEN_FACTORY");
        am.labelRole(ROLE_CLAIM_ISSUER_ADMIN, "CLAIM_ISSUER_ADMIN");
        am.labelRole(ROLE_BEACON_UPGRADER, "BEACON_UPGRADER");

        // 4. IdentityFactory. The beacon cannot exist yet (it needs the Identity
        //    implementation, which needs the validator, which needs this factory), so the
        //    factory commits its predetermined CREATE3 beacon slot as an immutable and the
        //    beacon is deployed there via `initializeBeacon` once the chain below exists.
        IdentityFactory idFactory = new IdentityFactory(address(am));
        console.log("IdentityFactory:", address(idFactory));

        // 5. ReputationRegistry. Needs the factory address so its lazy default-tier
        //    fallback can gate on factory membership. Writes are restricted via the AM.
        ReputationRegistry reputationRegistry = new ReputationRegistry(address(am), address(idFactory));
        console.log("ReputationRegistry:", address(reputationRegistry));

        // 6. Validator module singleton — one module, ERC-7913 signer shape, EOA/1271/7913
        //    crypto dispatch via OZ `SignatureChecker`, ACTION purpose enforced against the
        //    calling account's ERC-734 registry. It also holds the ERC-735 claim surface,
        //    so it needs the factory and the registry for the trusted-issuer addClaim path.
        ERC734Validator signatureValidator = new ERC734Validator(address(idFactory), address(reputationRegistry));
        console.log("ERC734Validator:", address(signatureValidator));

        // 7. Identity implementation. The validator (its enshrined registry) and the factory are
        //    both fixed as immutables; the implementation's own initializers are disabled.
        Identity identityImpl = new Identity(address(signatureValidator), address(idFactory));
        console.log("Identity implementation:", address(identityImpl));

        // 8. UpgradeableBeacon for identity proxies, deployed by the factory at its
        //    predetermined CREATE3 slot (already committed as the factory's `beacon`
        //    immutable) and owned by the factory itself. Upgrades run through
        //    `idFactory.upgradeBeacon`, gated by the factory's current authority.
        idFactory.initializeBeacon(address(identityImpl));
        console.log("Beacon:", idFactory.beacon());

        // Give `upgradeBeacon` its own role with an execution delay instead of letting it
        // fall through to ADMIN_ROLE, which the deployer holds with no delay. The upgrade
        // re-points every deployed identity, so it has to be schedulable and observable
        // rather than immediate. The deployer holds the role to bootstrap; production should
        // rotate it to a multisig alongside the ADMIN_ROLE rotation noted above.
        bytes4[] memory upgradeSelectors = new bytes4[](1);
        upgradeSelectors[0] = IdentityFactory.upgradeBeacon.selector;
        am.setTargetFunctionRole(address(idFactory), upgradeSelectors, ROLE_BEACON_UPGRADER);
        am.grantRole(ROLE_BEACON_UPGRADER, deployer, BEACON_UPGRADE_DELAY);

        // ===== 9. Per-identity-type deploy policy =====
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

        // 10. ERC-7913 WebAuthn Verifier (stateless — verifies P-256 WebAuthn assertions on-chain)
        ERC7913WebAuthnVerifier webAuthnVerifier = new ERC7913WebAuthnVerifier();
        console.log("ERC7913WebAuthnVerifier:", address(webAuthnVerifier));

        vm.stopBroadcast();

        // ===== Summary =====
        console.log("");
        console.log("========== Deployment Summary ==========");
        console.log("Identity impl:          ", address(identityImpl));
        console.log("IdentityUtilities impl: ", address(utilitiesImpl));
        console.log("IdentityUtilities proxy:", address(utilitiesProxy));
        console.log("Beacon:                 ", idFactory.beacon());
        console.log("AccessManager:          ", address(am));
        console.log("IdentityFactory:        ", address(idFactory));
        console.log("ERC734Validator:        ", address(signatureValidator));
        console.log("KeyApprovalModule:      ", address(keyApprovalModule));
        console.log("ERC7913WebAuthnVerifier:", address(webAuthnVerifier));
        console.log("=========================================");
    }

}
