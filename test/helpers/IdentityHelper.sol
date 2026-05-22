// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import {
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Identity } from "contracts/Identity.sol";
import { IdFactory } from "contracts/factory/IdFactory.sol";
import { IClaimIssuer } from "contracts/interface/IClaimIssuer.sol";
import { IERC735 } from "contracts/interface/IERC735.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { ClaimsModule } from "contracts/modules/claims/ClaimsModule.sol";
import { KeyApprovalModule } from "contracts/modules/executors/KeyApprovalModule.sol";
import { ECDSAValidator } from "contracts/modules/validators/ECDSAValidator.sol";
import { WebAuthnValidator } from "contracts/modules/validators/WebAuthnValidator.sol";
import { IdentityProxy } from "contracts/proxy/IdentityProxy.sol";
import { ImplementationAuthority } from "contracts/proxy/ImplementationAuthority.sol";
import { Structs } from "contracts/storage/Structs.sol";
import { Vm } from "forge-std/Vm.sol";

/// @notice Helper library for deploying OnchainID Identity Factory infrastructure
library IdentityHelper {

    struct OnchainIDSetup {
        Identity identityImplementation;
        ImplementationAuthority implementationAuthority;
        IdFactory idFactory;
        KeyApprovalModule keyApprovalModule;
        ECDSAValidator ecdsaValidator;
        WebAuthnValidator webauthnValidator;
        ClaimsModule claimsModule;
    }

    /// @notice Deploys complete Identity Factory infrastructure
    /// @param managementKey The initial management key address
    /// @return setup Struct containing all deployed contracts
    function deployFactory(address managementKey) internal returns (OnchainIDSetup memory setup) {
        // Deploy module singletons
        setup.ecdsaValidator = new ECDSAValidator();
        setup.webauthnValidator = new WebAuthnValidator();
        setup.keyApprovalModule = new KeyApprovalModule();
        setup.claimsModule = new ClaimsModule();

        setup.identityImplementation = new Identity(managementKey, false);
        setup.implementationAuthority =
            new ImplementationAuthority(address(setup.identityImplementation), managementKey);
        setup.idFactory = new IdFactory(address(setup.implementationAuthority), managementKey);
    }

    /// @notice Builds the full default-module install list: legacy queue (execute/approve) +
    ///         ClaimsModule (ERC-735 surface + issuer extras). Caller passes the singletons.
    function legacyQueueModules(address keyApprovalModule, address claimsModule)
        internal
        pure
        returns (Structs.ModuleInstall[] memory installs)
    {
        installs = new Structs.ModuleInstall[](15);
        // ----- KeyApprovalModule: 1 executor + 3 fallbacks -----
        installs[0] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_EXECUTOR, module: keyApprovalModule, initData: "", purpose: KeyPurposes.MANAGEMENT
        });
        installs[1] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: keyApprovalModule,
            initData: abi.encodePacked(IKeyExecutor.execute.selector),
            purpose: 0
        });
        installs[2] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: keyApprovalModule,
            initData: abi.encodePacked(IKeyExecutor.approve.selector),
            purpose: 0
        });
        installs[3] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: keyApprovalModule,
            initData: abi.encodePacked(IKeyExecutor.getCurrentNonce.selector),
            purpose: 0
        });
        // ----- ClaimsModule: 1 executor + 10 fallbacks -----
        installs[4] =
            Structs.ModuleInstall({ moduleType: MODULE_TYPE_EXECUTOR, module: claimsModule, initData: "", purpose: 0 });
        installs[5] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IERC735.addClaim.selector),
            purpose: 0
        });
        installs[6] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IERC735.removeClaim.selector),
            purpose: 0
        });
        installs[7] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IERC735.getClaim.selector),
            purpose: 0
        });
        installs[8] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IERC735.getClaimIdsByTopic.selector),
            purpose: 0
        });
        installs[9] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IIdentity.isClaimValid.selector),
            purpose: 0
        });
        installs[10] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IIdentity.getClaimHash.selector),
            purpose: 0
        });
        installs[11] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IClaimIssuer.revokeClaim.selector),
            purpose: 0
        });
        installs[12] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IClaimIssuer.revokeClaimBySignature.selector),
            purpose: 0
        });
        installs[13] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IClaimIssuer.isClaimRevoked.selector),
            purpose: 0
        });
        installs[14] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IClaimIssuer.addClaimTo.selector),
            purpose: 0
        });
    }

    /// @notice Deploys an Identity through the custom IdentityProxy pattern and installs an
    ///         ECDSAValidator on it so it can verify signatures via its installed module.
    /// @param initialManagementKey The management key for the identity
    /// @return identity The Identity contract at the proxy address
    /// @return ecdsaValidator The ECDSA validator module installed on the identity
    function deployIdentityWithProxy(address initialManagementKey)
        internal
        returns (Identity identity, ECDSAValidator ecdsaValidator)
    {
        return deployIdentityWithProxy(initialManagementKey, IdentityTypes.INDIVIDUAL);
    }

    function deployIdentityWithProxy(address initialManagementKey, uint256 identityType)
        internal
        returns (Identity identity, ECDSAValidator ecdsaValidator)
    {
        Identity impl = new Identity(initialManagementKey, false);
        ImplementationAuthority ia = new ImplementationAuthority(address(impl), initialManagementKey);
        IdentityProxy proxy = new IdentityProxy(address(ia), initialManagementKey, identityType);
        identity = Identity(payable(address(proxy)));

        ecdsaValidator = new ECDSAValidator();
        Vm vmHandle = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
        vmHandle.prank(initialManagementKey);
        identity.installModule(MODULE_TYPE_VALIDATOR, address(ecdsaValidator), "");

        // Install ClaimsModule so the identity exposes the ERC-735 ABI via fallback.
        ClaimsModule claimsModule = new ClaimsModule();
        _installClaimsModule(identity, address(claimsModule), initialManagementKey, vmHandle);
    }

    /// @dev Installs ClaimsModule as executor + fallback for the ERC-735 / claim-issuer
    ///      selector set on `identity`. Used by {deployIdentityWithProxy} test paths.
    function _installClaimsModule(Identity identity, address claimsModule, address managementKey, Vm vmHandle) private {
        vmHandle.startPrank(managementKey);
        identity.installModule(MODULE_TYPE_EXECUTOR, claimsModule, "");
        identity.installModule(MODULE_TYPE_FALLBACK, claimsModule, abi.encodePacked(IERC735.addClaim.selector));
        identity.installModule(MODULE_TYPE_FALLBACK, claimsModule, abi.encodePacked(IERC735.removeClaim.selector));
        identity.installModule(MODULE_TYPE_FALLBACK, claimsModule, abi.encodePacked(IERC735.getClaim.selector));
        identity.installModule(
            MODULE_TYPE_FALLBACK, claimsModule, abi.encodePacked(IERC735.getClaimIdsByTopic.selector)
        );
        identity.installModule(MODULE_TYPE_FALLBACK, claimsModule, abi.encodePacked(IIdentity.isClaimValid.selector));
        identity.installModule(MODULE_TYPE_FALLBACK, claimsModule, abi.encodePacked(IIdentity.getClaimHash.selector));
        identity.installModule(MODULE_TYPE_FALLBACK, claimsModule, abi.encodePacked(IClaimIssuer.revokeClaim.selector));
        identity.installModule(
            MODULE_TYPE_FALLBACK, claimsModule, abi.encodePacked(IClaimIssuer.revokeClaimBySignature.selector)
        );
        identity.installModule(
            MODULE_TYPE_FALLBACK, claimsModule, abi.encodePacked(IClaimIssuer.isClaimRevoked.selector)
        );
        identity.installModule(MODULE_TYPE_FALLBACK, claimsModule, abi.encodePacked(IClaimIssuer.addClaimTo.selector));
        vmHandle.stopPrank();
    }

}
