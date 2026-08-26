// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Script, console } from "forge-std/Script.sol";

import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {
    ERC7913WebAuthnVerifier
} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913WebAuthnVerifier.sol";
import { Identity } from "contracts/Identity.sol";
import { IdentityUtilities } from "contracts/IdentityUtilities.sol";
import { IdentityFactory } from "contracts/factory/IdentityFactory.sol";
import { IClaimIssuer } from "contracts/interface/IClaimIssuer.sol";
import { IERC734 } from "contracts/interface/IERC734.sol";
import { IERC735 } from "contracts/interface/IERC735.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyApprovalModule } from "contracts/modules/executors/KeyApprovalModule.sol";
import { ERC734Validator } from "contracts/modules/validators/ERC734Validator.sol";
import { IdentityUtilitiesProxy } from "contracts/proxy/IdentityUtilitiesProxy.sol";
import { ReputationRegistry } from "contracts/reputation/ReputationRegistry.sol";
import { Structs } from "contracts/storage/Structs.sol";

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
 *  10. Module bundle registered per identity type on the factory
 *
 * Usage:
 *   forge script scripts/DeployOnchainID.s.sol --rpc-url <RPC> --private-key <PK> --broadcast --verify
 */
contract DeployOnchainID is Script {

    // Role ids used below. Labeled on-chain via AccessManager.labelRole. Each one gates
    // createIdentityFor for one identity type.

    /// @dev Can create ASSET and SMART_CONTRACT identities. These can't sign, so the role
    ///      is their only gate. Keep it off PUBLIC_ROLE.
    uint64 internal constant ROLE_TOKEN_FACTORY = 1;

    /// @dev Can create CLAIM_ISSUER identities. The issuer ends up managing its own
    ///      identity, so this only controls who may onboard one.
    uint64 internal constant ROLE_CLAIM_ISSUER_ADMIN = 2;
    uint64 internal constant ROLE_BEACON_UPGRADER = 3;

    /// @dev Execution delay on the beacon upgrade role. A beacon upgrade re-points every
    ///      identity at once, so it is scheduled first and only executable after the delay,
    ///      which gives holders a window to see it coming and the admin a window to cancel.
    uint32 internal constant BEACON_UPGRADE_DELAY = 2 days;

    /// @dev Can create PUBLIC_AUTHORITY identities. Kept off PUBLIC_ROLE because an
    ///      authority may not have a key to sign with.
    uint64 internal constant ROLE_PUBLIC_AUTHORITY = 3;

    /// @dev Can create INDIVIDUAL, CORPORATE, IOT and AI_AGENT identities for a third
    ///      party. Third-party onboarding stays with named issuers because bindings are
    ///      sticky; self-deploy remains open for these types.
    uint64 internal constant ROLE_ISSUER = 4;

    function run() external {
        vm.startBroadcast();

        address deployer = msg.sender;
        console.log("Deployer:", deployer);
        console.log("");

        // 1. IdentityUtilities implementation + proxy
        IdentityUtilities utilitiesImpl = new IdentityUtilities();
        IdentityUtilitiesProxy utilitiesProxy = new IdentityUtilitiesProxy(address(utilitiesImpl), deployer);
        console.log("IdentityUtilities implementation:", address(utilitiesImpl));
        console.log("IdentityUtilities proxy:", address(utilitiesProxy));

        // 2. KeyApprovalModule (the legacy ERC-734 execute/approve queue, no deps). It is
        //    part of the module bundle registered per identity type in step 10. The ERC-735
        //    claim surface lives in the ERC734Validator deployed below, installed as claim
        //    fallbacks.
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
        am.labelRole(ROLE_PUBLIC_AUTHORITY, "PUBLIC_AUTHORITY");
        am.labelRole(ROLE_ISSUER, "ISSUER");

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
        // Each type carries a policy: an AM role id (gates createIdentityFor), a
        // selfDeployable flag (gates createIdentity) and a singleBinding flag (the
        // identity keeps the one account set at deploy; link/revoke are blocked).
        // Unregistered types revert from both entry points.
        //
        // Contract-shaped types (ASSET, SMART_CONTRACT, PUBLIC_AUTHORITY) opt out of
        // self-deploy because their identity represents a contract, not msg.sender.
        // CLAIM_ISSUER also opts out so the admin role on createIdentityFor is not
        // bypassable via self-deploy.
        // Gated for createIdentityFor; self-deploy disabled. ASSET and SMART_CONTRACT are
        // single-binding: the bound contract can't sign, so the role must not be
        // PUBLIC_ROLE or anyone could bind a contract to keys they alone hold. Both use the
        // token-factory role.
        idFactory.setIdentityTypePolicy(IdentityTypes.ASSET, ROLE_TOKEN_FACTORY, false, true);
        idFactory.setIdentityTypePolicy(IdentityTypes.SMART_CONTRACT, ROLE_TOKEN_FACTORY, false, true);
        idFactory.setIdentityTypePolicy(IdentityTypes.CLAIM_ISSUER, ROLE_CLAIM_ISSUER_ADMIN, false, false);

        // Self-deploy is open for every type below: the caller is the account, so there is
        // nothing to abuse. createIdentityFor is what the role gates.
        //
        // INDIVIDUAL third-party onboarding goes through ROLE_ISSUER. Bindings are sticky,
        // so an open createIdentityFor would let a stranger bind a wallet to an identity
        // its owner never asked for, blocking that wallet from any other identity. Users
        // who want an identity without an issuer can still self-deploy.
        idFactory.setIdentityTypePolicy(IdentityTypes.INDIVIDUAL, ROLE_ISSUER, true, false);

        // Restricted for createIdentityFor. These are signing entities, a company multisig,
        // a provisioned device, an agent key, so they keep the sole management guarantee.
        // But nobody onboards them from a wallet themselves, a registrar does it, so only
        // named issuers may deploy for them.
        idFactory.setIdentityTypePolicy(IdentityTypes.CORPORATE, ROLE_ISSUER, true, false);
        idFactory.setIdentityTypePolicy(IdentityTypes.IOT, ROLE_ISSUER, true, false);
        idFactory.setIdentityTypePolicy(IdentityTypes.AI_AGENT, ROLE_ISSUER, true, false);

        // Restricted for createIdentityFor; self-deploy disabled. A public authority is an
        // institution, a regulator or a court, onboarded by an operator rather than by
        // itself. Not single binding: an authority that controls a multisig holds a key and
        // may link more than one wallet.
        idFactory.setIdentityTypePolicy(IdentityTypes.PUBLIC_AUTHORITY, ROLE_PUBLIC_AUTHORITY, false, false);

        // ===== 10. Modules registered per identity type =====
        // Callers pass no modules. Every identity installs exactly what is registered for
        // its type here, which is what lets createIdentityFor promise that the account
        // manages its own identity: a caller cannot slip in a module of its own and act
        // through it. Changing the setup later is a parameter update through the AM, not an
        // upgrade. All types start on the same standard bundle.
        Structs.ModuleInstall[] memory standardModules =
            _standardModules(address(keyApprovalModule), address(signatureValidator));
        uint256[8] memory allTypes = [
            IdentityTypes.ASSET,
            IdentityTypes.INDIVIDUAL,
            IdentityTypes.CORPORATE,
            IdentityTypes.IOT,
            IdentityTypes.CLAIM_ISSUER,
            IdentityTypes.SMART_CONTRACT,
            IdentityTypes.PUBLIC_AUTHORITY,
            IdentityTypes.AI_AGENT
        ];
        for (uint256 i = 0; i < allTypes.length; i++) {
            idFactory.setIdentityTypeModules(allTypes[i], standardModules);
        }

        // 11. ERC-7913 WebAuthn Verifier (stateless — verifies P-256 WebAuthn assertions on-chain)
        ERC7913WebAuthnVerifier webAuthnVerifier = new ERC7913WebAuthnVerifier();
        console.log("ERC7913WebAuthnVerifier:", address(webAuthnVerifier));

        // Approve it for linkAccount: ERC-7913 signers only link through a
        // verifier on this list.
        idFactory.setTrustedVerifier(address(webAuthnVerifier), true);

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

    /// @dev The standard module bundle every type starts with: the merged ERC734Validator
    ///      as validator (empty initData, so the MANAGEMENT key comes from the deploy's
    ///      keys), the KeyApprovalModule execute/approve queue, and the fallback surface for
    ///      the ERC-734 getters and ERC-735 claim methods, all served by the merged
    ///      validator. Only the queue executor carries a purpose. It needs MANAGEMENT to
    ///      dispatch self targeted calls once an execution is approved.
    function _standardModules(address keyApprovalModule, address validator)
        private
        pure
        returns (Structs.ModuleInstall[] memory installs)
    {
        installs = new Structs.ModuleInstall[](20);
        installs[0] =
            Structs.ModuleInstall({ moduleType: MODULE_TYPE_VALIDATOR, module: validator, initData: "", purpose: 0 });
        installs[1] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_EXECUTOR, module: keyApprovalModule, initData: "", purpose: KeyPurposes.MANAGEMENT
        });
        installs[2] = _fallback(keyApprovalModule, IKeyExecutor.execute.selector);
        installs[3] = _fallback(keyApprovalModule, IKeyExecutor.approve.selector);
        installs[4] = _fallback(keyApprovalModule, IKeyExecutor.getCurrentNonce.selector);
        installs[5] =
            Structs.ModuleInstall({ moduleType: MODULE_TYPE_EXECUTOR, module: validator, initData: "", purpose: 0 });
        installs[6] = _fallback(validator, IERC735.addClaim.selector);
        installs[7] = _fallback(validator, IERC735.removeClaim.selector);
        installs[8] = _fallback(validator, IERC735.getClaim.selector);
        installs[9] = _fallback(validator, IERC735.getClaimIdsByTopic.selector);
        installs[10] = _fallback(validator, IIdentity.isClaimValid.selector);
        installs[11] = _fallback(validator, IIdentity.getClaimHash.selector);
        installs[12] = _fallback(validator, IClaimIssuer.revokeClaimByDigest.selector);
        installs[13] = _fallback(validator, IClaimIssuer.isDigestRevoked.selector);
        installs[14] = _fallback(validator, IClaimIssuer.addClaimTo.selector);
        installs[15] = _fallback(validator, ERC734Validator.addClaimByTrustedIssuer.selector);
        installs[16] = _fallback(validator, IERC734.keyHasPurpose.selector);
        installs[17] = _fallback(validator, IERC734.getKey.selector);
        installs[18] = _fallback(validator, IERC734.getKeyPurposes.selector);
        installs[19] = _fallback(validator, IERC734.getKeysByPurpose.selector);
    }

    function _fallback(address module, bytes4 selector) private pure returns (Structs.ModuleInstall memory) {
        return Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK, module: module, initData: abi.encodePacked(selector), purpose: 0
        });
    }

}
