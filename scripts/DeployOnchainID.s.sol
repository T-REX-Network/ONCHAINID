// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Script, console } from "forge-std/Script.sol";

import {
    ERC7913WebAuthnVerifier
} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913WebAuthnVerifier.sol";
import { Identity } from "contracts/Identity.sol";
import { IdentityUtilities } from "contracts/IdentityUtilities.sol";
import { IdFactory } from "contracts/factory/IdFactory.sol";
import { Gateway } from "contracts/gateway/Gateway.sol";
import { ClaimsModule } from "contracts/modules/claims/ClaimsModule.sol";
import { KeyApprovalModule } from "contracts/modules/executors/KeyApprovalModule.sol";
import { ERC7579Signature } from "contracts/modules/validators/ERC7579Signature.sol";
import { IdentityUtilitiesProxy } from "contracts/proxy/IdentityUtilitiesProxy.sol";
import { ImplementationAuthority } from "contracts/proxy/ImplementationAuthority.sol";

/**
 * @title DeployOnchainID
 * @notice Deploys the full OnchainID protocol stack.
 *
 * Deployment order:
 *   1. Identity implementation (library mode)
 *   2. IdentityUtilities implementation + proxy
 *   3. ImplementationAuthority (beacon pointing to Identity impl)
 *   4. Module singletons (KeyApprovalModule, ClaimsModule)
 *   5. IdFactory (uses ImplementationAuthority for identity proxies)
 *   6. Gateway (entry point for signed identity deployments)
 *
 * Usage:
 *   forge script scripts/DeployOnchainID.s.sol --rpc-url <RPC> --private-key <PK> --broadcast --verify
 */
contract DeployOnchainID is Script {

    function run() external {
        // Gateway signers — hardcode as needed
        address[] memory gatewaySigners = new address[](2);
        gatewaySigners[0] = 0x927eCbf77127C423642e6e3459CFc0B2c08BeC0c;
        gatewaySigners[1] = 0xc756c27486d07112bc11AA6d3f53DA3Ca9aAf2ca;

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
        Identity identityImpl = new Identity(true);
        console.log("Identity implementation:", address(identityImpl));

        // 3. IdentityUtilities implementation + proxy
        IdentityUtilities utilitiesImpl = new IdentityUtilities();
        IdentityUtilitiesProxy utilitiesProxy = new IdentityUtilitiesProxy(
            address(utilitiesImpl), abi.encodeCall(IdentityUtilities.initialize, (deployer))
        );
        console.log("IdentityUtilities implementation:", address(utilitiesImpl));
        console.log("IdentityUtilities proxy:", address(utilitiesProxy));

        // ===== Phase 2: Infrastructure =====

        // 4. ImplementationAuthority (beacon for identity proxies)
        ImplementationAuthority authority = new ImplementationAuthority(address(identityImpl), deployer);
        console.log("ImplementationAuthority:", address(authority));

        // 4b. Module singletons. Callers include these in their `_modules` array on
        //     `createIdentity` to opt into the legacy ERC-734 execute/approve queue
        //     (KeyApprovalModule) and the full ERC-735 claim surface (ClaimsModule).
        KeyApprovalModule keyApprovalModule = new KeyApprovalModule();
        console.log("KeyApprovalModule:", address(keyApprovalModule));
        ClaimsModule claimsModule = new ClaimsModule();
        console.log("ClaimsModule:", address(claimsModule));

        // 5. IdFactory
        IdFactory idFactory = new IdFactory(
            address(authority), deployer, address(signatureValidator), address(keyApprovalModule), address(claimsModule)
        );
        console.log("IdFactory:", address(idFactory));

        // 7. Gateway
        Gateway gateway = new Gateway(address(idFactory), gatewaySigners, deployer);
        console.log("Gateway:", address(gateway));

        // 8. ERC-7913 WebAuthn Verifier (stateless — verifies P-256 WebAuthn assertions on-chain)
        ERC7913WebAuthnVerifier webAuthnVerifier = new ERC7913WebAuthnVerifier();
        console.log("ERC7913WebAuthnVerifier:", address(webAuthnVerifier));

        // Transfer IdFactory ownership to Gateway so it can deploy identities
        idFactory.transferOwnership(address(gateway));
        console.log("IdFactory ownership transferred to Gateway");

        vm.stopBroadcast();

        // ===== Summary =====
        console.log("");
        console.log("========== Deployment Summary ==========");
        console.log("Identity impl:          ", address(identityImpl));
        console.log("IdentityUtilities impl: ", address(utilitiesImpl));
        console.log("IdentityUtilities proxy:", address(utilitiesProxy));
        console.log("ImplementationAuthority:", address(authority));
        console.log("IdFactory:              ", address(idFactory));
        console.log("ERC7579Signature:       ", address(signatureValidator));
        console.log("KeyApprovalModule:      ", address(keyApprovalModule));
        console.log("ClaimsModule:           ", address(claimsModule));
        console.log("Gateway:                ", address(gateway));
        console.log("ERC7913WebAuthnVerifier:", address(webAuthnVerifier));
        console.log("=========================================");
    }

}
