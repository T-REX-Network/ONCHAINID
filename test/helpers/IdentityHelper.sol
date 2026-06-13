// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { AccessManager } from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { BeaconProxy } from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import { UpgradeableBeacon } from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import { Identity } from "contracts/Identity.sol";
import { IIdentityFactory } from "contracts/factory/IIdentityFactory.sol";
import { IdentityFactory } from "contracts/factory/IdentityFactory.sol";
import { IClaimIssuer } from "contracts/interface/IClaimIssuer.sol";
import { IERC735 } from "contracts/interface/IERC735.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { IKeyExecutor } from "contracts/interface/IKeyExecutor.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { ClaimsModule } from "contracts/modules/claims/ClaimsModule.sol";
import { KeyApprovalModule } from "contracts/modules/executors/KeyApprovalModule.sol";
import { ERC7579Signature } from "contracts/modules/validators/ERC7579Signature.sol";
import { Structs } from "contracts/storage/Structs.sol";
import { Vm } from "forge-std/Vm.sol";

/// @notice Helper library for deploying OnchainID Identity Factory infrastructure
library IdentityHelper {

    /// @dev AccessManager built-in role id; equivalent to `AccessManager.PUBLIC_ROLE()` but
    ///      exposed as a constant here so the test setup does not need to invoke `vm.prank`
    ///      semantics just to read it.
    uint64 internal constant PUBLIC_ROLE = type(uint64).max;

    struct OnchainIDSetup {
        Identity identityImplementation;
        UpgradeableBeacon beacon;
        AccessManager accessManager;
        IdentityFactory idFactory;
        KeyApprovalModule keyApprovalModule;
        ERC7579Signature signatureValidator;
        ClaimsModule claimsModule;
    }

    /// @notice Deploys complete Identity Factory infrastructure. Wires an AccessManager
    ///         whose initial admin is `managementKey` and opens every identity type to
    ///         `PUBLIC_ROLE` so that existing tests (which expect the deployer to be able
    ///         to mint identities of any type) keep working without per-test plumbing.
    ///         Tests that exercise the gating itself should redeploy with a custom config.
    /// @param managementKey The initial management key address (also initial admin of the
    ///        AccessManager).
    /// @return setup Struct containing all deployed contracts
    function deployFactory(address managementKey) internal returns (OnchainIDSetup memory setup) {
        // Deploy module singletons
        setup.signatureValidator = new ERC7579Signature();
        setup.keyApprovalModule = new KeyApprovalModule();
        setup.claimsModule = new ClaimsModule();

        setup.identityImplementation = new Identity(managementKey, false);
        setup.beacon = new UpgradeableBeacon(address(setup.identityImplementation), managementKey);
        setup.accessManager = new AccessManager(managementKey);
        setup.idFactory = new IdentityFactory(address(setup.beacon), address(setup.accessManager));

        // Default test policy: both deploy paths open to PUBLIC_ROLE so test setUps can mint
        // identities for arbitrary addresses without per-test plumbing. Production deployments
        // use a stricter policy — see `scripts/DeployOnchainID.s.sol`.
        bytes4[] memory deploySelectors = new bytes4[](2);
        deploySelectors[0] = IIdentityFactory.createIdentity.selector;
        deploySelectors[1] = IIdentityFactory.createIdentityFor.selector;
        setup.accessManager.setTargetFunctionRole(address(setup.idFactory), deploySelectors, PUBLIC_ROLE);
    }

    /// @notice Builds the full default-module install list: legacy queue (execute/approve) +
    ///         ClaimsModule (ERC-735 surface + issuer extras). Caller passes the singletons.
    function legacyQueueModules(address keyApprovalModule, address claimsModule)
        internal
        pure
        returns (Structs.ModuleInstall[] memory installs)
    {
        installs = new Structs.ModuleInstall[](14);
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
        // ----- ClaimsModule: 1 executor + 9 fallbacks -----
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
            initData: abi.encodePacked(IClaimIssuer.revokeClaimByDigest.selector),
            purpose: 0
        });
        installs[12] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IClaimIssuer.isDigestRevoked.selector),
            purpose: 0
        });
        installs[13] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IClaimIssuer.addClaimTo.selector),
            purpose: 0
        });
    }

    /// @notice Deploys an Identity through a standalone BeaconProxy and installs an
    ///         {ERC7579Signature} validator on it so it can verify ERC-1271 / 4337 signatures.
    /// @param initialManagementKey The management key for the identity.
    /// @return identity The Identity contract at the proxy address.
    /// @return signatureValidator The ERC-7579 signature validator installed on the identity.
    function deployIdentityWithProxy(address initialManagementKey)
        internal
        returns (Identity identity, ERC7579Signature signatureValidator)
    {
        return deployIdentityWithProxy(initialManagementKey, IdentityTypes.INDIVIDUAL);
    }

    function deployIdentityWithProxy(address initialManagementKey, uint256 identityType)
        internal
        returns (Identity identity, ERC7579Signature signatureValidator)
    {
        Identity impl = new Identity(initialManagementKey, false);
        UpgradeableBeacon b = new UpgradeableBeacon(address(impl), initialManagementKey);
        BeaconProxy proxy =
            new BeaconProxy(address(b), abi.encodeCall(Identity.initialize, (initialManagementKey, identityType)));
        identity = Identity(payable(address(proxy)));

        signatureValidator = new ERC7579Signature();
        Vm vmHandle = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
        vmHandle.prank(initialManagementKey);
        identity.installModule(MODULE_TYPE_VALIDATOR, address(signatureValidator), "");

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
        identity.installModule(
            MODULE_TYPE_FALLBACK, claimsModule, abi.encodePacked(IClaimIssuer.revokeClaimByDigest.selector)
        );
        identity.installModule(
            MODULE_TYPE_FALLBACK, claimsModule, abi.encodePacked(IClaimIssuer.isDigestRevoked.selector)
        );
        identity.installModule(MODULE_TYPE_FALLBACK, claimsModule, abi.encodePacked(IClaimIssuer.addClaimTo.selector));
        vmHandle.stopPrank();
    }

}
