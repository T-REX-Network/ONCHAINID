// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import {
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Identity } from "contracts/Identity.sol";
import { IdFactory } from "contracts/factory/IdFactory.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
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
    }

    /// @notice Deploys complete Identity Factory infrastructure
    /// @param managementKey The initial management key address
    /// @return setup Struct containing all deployed contracts
    function deployFactory(address managementKey) internal returns (OnchainIDSetup memory setup) {
        // Deploy validator module singletons
        setup.ecdsaValidator = new ECDSAValidator();
        setup.webauthnValidator = new WebAuthnValidator();
        setup.keyApprovalModule = new KeyApprovalModule();

        setup.identityImplementation = new Identity(managementKey, false);
        setup.implementationAuthority = new ImplementationAuthority(address(setup.identityImplementation));
        setup.idFactory = new IdFactory(address(setup.implementationAuthority));
    }

    /// @notice Builds the four `ModuleInstall` entries that enable the legacy ERC-734
    ///         `execute`/`approve` ABI on an identity via the queue module. Caller prepends
    ///         (or otherwise includes) these in their `_modules` array for `createIdentity`.
    function legacyQueueModules(address keyApprovalModule)
        internal
        pure
        returns (Structs.ModuleInstall[] memory installs)
    {
        installs = new Structs.ModuleInstall[](4);
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
        ImplementationAuthority ia = new ImplementationAuthority(address(impl));
        IdentityProxy proxy = new IdentityProxy(address(ia), initialManagementKey, identityType);
        identity = Identity(payable(address(proxy)));

        ecdsaValidator = new ECDSAValidator();
        Vm vmHandle = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
        vmHandle.prank(initialManagementKey);
        identity.installModule(MODULE_TYPE_VALIDATOR, address(ecdsaValidator), "");
    }

}
