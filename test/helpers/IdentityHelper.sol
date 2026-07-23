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
import { ReputationRegistry } from "contracts/reputation/ReputationRegistry.sol";
import { Structs } from "contracts/storage/Structs.sol";

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
        ReputationRegistry reputationRegistry;
        KeyApprovalModule keyApprovalModule;
        ERC734Validator signatureValidator;
    }

    /// @notice Deploys complete Identity Factory infrastructure with an AccessManager
    ///         whose initial admin is `managementKey`. Every standard identity type is
    ///         registered with `PUBLIC_ROLE` and `selfDeployable = true` so tests can
    ///         mint any type for any address without extra plumbing. Tests that
    ///         exercise stricter gating should re-point the relevant type via
    ///         `setIdentityTypePolicy`.
    /// @param managementKey The initial management key address (also initial admin of the
    ///        AccessManager).
    /// @return setup Struct containing all deployed contracts
    function deployFactory(address managementKey) internal returns (OnchainIDSetup memory setup) {
        // Linear order — each contract only needs addresses that already exist:
        // KAM (no deps) -> AM -> factory (no beacon yet) -> reputation registry (needs the
        // factory) -> validator (needs factory + registry) -> Identity impl (the validator is
        // its enshrined registry immutable) -> factory.initializeBeacon.
        setup.keyApprovalModule = new KeyApprovalModule();
        setup.accessManager = new AccessManager(managementKey);
        setup.idFactory = new IdentityFactory(address(setup.accessManager));
        setup.reputationRegistry = new ReputationRegistry(address(setup.accessManager), address(setup.idFactory));
        setup.signatureValidator = new ERC734Validator(address(setup.idFactory), address(setup.reputationRegistry));
        setup.identityImplementation = new Identity(address(setup.signatureValidator), address(setup.idFactory));
        // The factory deploys the beacon at its predetermined CREATE3 slot; its owner is
        // the AccessManager, so upgrades in tests route through `accessManager.execute`.
        setup.idFactory.initializeBeacon(address(setup.identityImplementation));
        setup.beacon = UpgradeableBeacon(setup.idFactory.beacon());

        // Register every standard type with PUBLIC_ROLE and selfDeployable = true for
        // a permissive test default.
        uint256[8] memory types = [
            IdentityTypes.ASSET,
            IdentityTypes.INDIVIDUAL,
            IdentityTypes.CORPORATE,
            IdentityTypes.IOT,
            IdentityTypes.CLAIM_ISSUER,
            IdentityTypes.SMART_CONTRACT,
            IdentityTypes.PUBLIC_AUTHORITY,
            IdentityTypes.AI_AGENT
        ];
        for (uint256 i = 0; i < types.length; i++) {
            setup.idFactory.setIdentityTypePolicy(types[i], PUBLIC_ROLE, true);
        }
    }

    /// @notice Builds the full default-module install list: the merged ERC734Validator installed as
    ///         a validator (it holds the key registry, enshrined during `initialize`) + the legacy
    ///         queue (execute/approve) + the ERC-734 getter and ERC-735 claim fallback surface.
    ///         `claimsModule` is the merged ERC734Validator. The validator install carries empty
    ///         initData: the MANAGEMENT key is seeded from the factory's `_keys` array (which the
    ///         factory requires to be non-empty and to hold at least one MANAGEMENT key).
    function legacyQueueModules(address keyApprovalModule, address claimsModule)
        internal
        pure
        returns (Structs.ModuleInstall[] memory installs)
    {
        installs = new Structs.ModuleInstall[](20);
        // ----- merged ERC734Validator: validator (holds the key registry) -----
        // Empty initData -> onInstall does not seed a key; MANAGEMENT comes from `_keys`.
        installs[0] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_VALIDATOR, module: claimsModule, initData: "", purpose: 0
        });
        // ----- KeyApprovalModule: 1 executor + 3 fallbacks -----
        installs[1] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_EXECUTOR, module: keyApprovalModule, initData: "", purpose: KeyPurposes.MANAGEMENT
        });
        installs[2] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: keyApprovalModule,
            initData: abi.encodePacked(IKeyExecutor.execute.selector),
            purpose: 0
        });
        installs[3] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: keyApprovalModule,
            initData: abi.encodePacked(IKeyExecutor.approve.selector),
            purpose: 0
        });
        installs[4] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: keyApprovalModule,
            initData: abi.encodePacked(IKeyExecutor.getCurrentNonce.selector),
            purpose: 0
        });
        // ----- claim module (merged validator): 1 executor + 9 claim fallbacks -----
        installs[5] =
            Structs.ModuleInstall({ moduleType: MODULE_TYPE_EXECUTOR, module: claimsModule, initData: "", purpose: 0 });
        installs[6] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IERC735.addClaim.selector),
            purpose: 0
        });
        installs[7] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IERC735.removeClaim.selector),
            purpose: 0
        });
        installs[8] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IERC735.getClaim.selector),
            purpose: 0
        });
        installs[9] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IERC735.getClaimIdsByTopic.selector),
            purpose: 0
        });
        installs[10] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IIdentity.isClaimValid.selector),
            purpose: 0
        });
        installs[11] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IIdentity.getClaimHash.selector),
            purpose: 0
        });
        installs[12] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IClaimIssuer.revokeClaimByDigest.selector),
            purpose: 0
        });
        installs[13] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IClaimIssuer.isDigestRevoked.selector),
            purpose: 0
        });
        installs[14] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IClaimIssuer.addClaimTo.selector),
            purpose: 0
        });
        // ----- trusted-issuer add path served by the merged module via fallback -----
        installs[15] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(ERC734Validator.addClaimByTrustedIssuer.selector),
            purpose: 0
        });
        // ----- ERC-734 getters served by the merged module via fallback -----
        installs[16] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IERC734.keyHasPurpose.selector),
            purpose: 0
        });
        installs[17] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IERC734.getKey.selector),
            purpose: 0
        });
        installs[18] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IERC734.getKeyPurposes.selector),
            purpose: 0
        });
        installs[19] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: claimsModule,
            initData: abi.encodePacked(IERC734.getKeysByPurpose.selector),
            purpose: 0
        });
    }

    /// @notice Deploys an Identity through a standalone BeaconProxy and installs an
    ///         {ERC734Validator} validator on it so it can verify ERC-1271 / 4337 signatures.
    /// @param initialManagementKey The management key for the identity.
    /// @return identity The Identity contract at the proxy address.
    /// @return signatureValidator The ERC-7579 signature validator installed on the identity.
    function deployIdentityWithProxy(address initialManagementKey)
        internal
        returns (Identity identity, ERC734Validator signatureValidator)
    {
        return deployIdentityWithProxy(initialManagementKey, IdentityTypes.INDIVIDUAL);
    }

    function deployIdentityWithProxy(address initialManagementKey, uint256 identityType)
        internal
        returns (Identity identity, ERC734Validator signatureValidator)
    {
        // Minimal AccessManager + IdentityFactory + ReputationRegistry so the merged
        // ERC734Validator constructor has real addresses to bind to. These identities
        // do not exercise the trusted-issuer path, so the addresses can be local
        // throwaways. They are real contracts so the constructor's zero-address checks pass.
        // The local factory never deploys proxies here (the proxy is deployed directly
        // below), so its beacon is left unset.
        AccessManager am = new AccessManager(initialManagementKey);
        IdentityFactory localFactory = new IdentityFactory(address(am));
        ReputationRegistry localRegistry = new ReputationRegistry(address(am), address(localFactory));

        signatureValidator = new ERC734Validator(address(localFactory), address(localRegistry));
        Identity impl = new Identity(address(signatureValidator), address(localFactory));
        UpgradeableBeacon b = new UpgradeableBeacon(address(impl), initialManagementKey);
        // The validator also holds the claim registry, so the claim fallbacks point at it too.
        address claimsModule = address(signatureValidator);

        // Bundle the management key + validator + claim fallback surface into a single
        // `initialize` call. Identity now bootstraps atomically inside the proxy constructor —
        // no post-deploy external installModule calls.
        Structs.KeyParam[] memory keys = new Structs.KeyParam[](1);
        bytes memory mgmtSigner = abi.encodePacked(initialManagementKey);
        keys[0] = Structs.KeyParam({
            keyHash: keccak256(mgmtSigner),
            purpose: KeyPurposes.MANAGEMENT,
            keyType: 1, // ECDSA
            signerData: mgmtSigner,
            clientData: ""
        });

        Structs.ModuleInstall[] memory modules = new Structs.ModuleInstall[](16);
        // The validator install carries empty initData: the MANAGEMENT key is seeded from `keys`
        // above (the account seeds every `_keys` entry into the enshrined module during
        // `initialize`). The validator owns scoping now, so no account-level purpose is granted to
        // the validator address (purpose: 0). Additional keys (e.g. ACTION signers) are added
        // afterwards via a self-call to `validator.addKey`.
        modules[0] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(signatureValidator), initData: "", purpose: 0
        });
        modules[1] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_EXECUTOR, module: address(claimsModule), initData: "", purpose: 0
        });
        modules[2] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: address(claimsModule),
            initData: abi.encodePacked(IERC735.addClaim.selector),
            purpose: 0
        });
        modules[3] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: address(claimsModule),
            initData: abi.encodePacked(IERC735.removeClaim.selector),
            purpose: 0
        });
        modules[4] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: address(claimsModule),
            initData: abi.encodePacked(IERC735.getClaim.selector),
            purpose: 0
        });
        modules[5] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: address(claimsModule),
            initData: abi.encodePacked(IERC735.getClaimIdsByTopic.selector),
            purpose: 0
        });
        modules[6] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: address(claimsModule),
            initData: abi.encodePacked(IIdentity.isClaimValid.selector),
            purpose: 0
        });
        modules[7] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: address(claimsModule),
            initData: abi.encodePacked(IIdentity.getClaimHash.selector),
            purpose: 0
        });
        modules[8] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: address(claimsModule),
            initData: abi.encodePacked(IClaimIssuer.revokeClaimByDigest.selector),
            purpose: 0
        });
        modules[9] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: address(claimsModule),
            initData: abi.encodePacked(IClaimIssuer.isDigestRevoked.selector),
            purpose: 0
        });
        modules[10] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: address(claimsModule),
            initData: abi.encodePacked(IClaimIssuer.addClaimTo.selector),
            purpose: 0
        });
        // ----- ERC-734 getters served by the merged module via fallback -----
        modules[11] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: address(claimsModule),
            initData: abi.encodePacked(IERC734.keyHasPurpose.selector),
            purpose: 0
        });
        modules[12] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: address(claimsModule),
            initData: abi.encodePacked(IERC734.getKey.selector),
            purpose: 0
        });
        modules[13] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: address(claimsModule),
            initData: abi.encodePacked(IERC734.getKeyPurposes.selector),
            purpose: 0
        });
        modules[14] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: address(claimsModule),
            initData: abi.encodePacked(IERC734.getKeysByPurpose.selector),
            purpose: 0
        });
        modules[15] = Structs.ModuleInstall({
            moduleType: MODULE_TYPE_FALLBACK,
            module: address(claimsModule),
            initData: abi.encodePacked(ERC734Validator.addClaimByTrustedIssuer.selector),
            purpose: 0
        });

        BeaconProxy proxy =
            new BeaconProxy(address(b), abi.encodeCall(Identity.initialize, (identityType, keys, modules)));
        identity = Identity(payable(address(proxy)));
    }

}
