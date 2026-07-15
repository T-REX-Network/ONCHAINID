// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IKeyRegistryModule } from "./KeyManager.sol";
import { SmartAccount } from "./SmartAccount.sol";
import { IERC734 } from "./interface/IERC734.sol";
import { IERC735 } from "./interface/IERC735.sol";
import { IIdentity } from "./interface/IIdentity.sol";
import { Errors } from "./libraries/Errors.sol";
import { KeyTypes } from "./libraries/KeyTypes.sol";
import { Structs } from "./storage/Structs.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { MODULE_TYPE_EXECUTOR, MODULE_TYPE_VALIDATOR } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { ERC165 } from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

/**
 * @title Identity
 * @dev Smart-account identity. ERC-734 key registry lives here (inherited from {KeyManager} via
 *      {SmartAccount}); ERC-735 claim functionality is provided by the installed {ERC734Validator}
 *      module (which holds both the key and claim registries) reached through this account's
 *      ERC-7579 fallback handler.
 *
 *      Storage layout uses ERC-7201 namespaced slots:
 *        - `onchainid.keymanager.storage`     — keys (from KeyManager)
 *        - `onchainid.identity.metadata`      — `identityType`, queried by anyone via {getIdentityType}
 *        - `onchainid.accountERC7579.storage` — installed modules (from OZ)
 *
 *      Key purposes supported by the registry:
 *        - MANAGEMENT       — manage the identity
 *        - ACTION           — perform actions on behalf of the identity
 *        - CLAIM_SIGNER     — sign and remove claims
 *        - CLAIM_ADDER      — add claims (cannot remove)
 *        - ENCRYPTION       — out-of-band encryption usage
 *        - PROPOSER         — queue executions via {KeyApprovalModule.execute} (cannot auto-run or approve)
 *
 *      The {IIdentity} interface continues to declare the ERC-735 selectors; calls to those
 *      selectors land on the installed {ERC734Validator} via fallback dispatch.
 *
 *      Initialization is single-shot. {initialize} takes the identity type plus the
 *      caller-supplied keys and modules and applies them inside the proxy constructor frame,
 *      with no cross-contract calls. No transient bootstrap MANAGEMENT key is ever written
 *      to any external contract.
 *
 *      Two shape invariants are enforced at init time. The factory's post-deploy check
 *      asserts at least one MANAGEMENT key. This contract's pre-init check asserts the
 *      module list contains at least one validator or executor, so the account can either
 *      verify signatures or dispatch outbound calls.
 */
contract Identity is Initializable, SmartAccount, ERC165 {

    /// @notice Emitted once, when an identity finishes initialization. Lets indexers
    ///         classify identities at deploy time without an extra `eth_call`.
    event IdentityInitialized(uint256 indexed identityType);

    /// @dev Account-level identity metadata.
    /// @custom:storage-location erc7201:onchainid.identity.metadata
    struct IdentityMetadata {
        uint256 identityType;
    }

    /// @dev ERC-7201 storage slot for identity-level metadata.
    bytes32 internal constant _IDENTITY_METADATA_SLOT =
        keccak256(abi.encode(uint256(keccak256(bytes("onchainid.identity.metadata"))) - 1)) & ~bytes32(uint256(0xff));

    /**
     * @notice Constructor of the Identity contract.
     * @param _isLibrary True when deploying the implementation contract behind a proxy. In that
     *        case we lock the OZ `Initializable` slot via `_disableInitializers()` so the
     *        implementation can never be initialized directly; only proxies (which run the
     *        constructor in their own context with `_isLibrary == false`) can initialize.
     */
    constructor(bool _isLibrary) EIP712("OnchainID", "1") {
        if (_isLibrary) {
            _disableInitializers();
        } else {
            __Identity_init();
        }
    }

    /**
     * @notice Single-shot initializer. Sets the identity type, registers the supplied keys,
     *         and installs the supplied modules. Runs in the same frame as the proxy
     *         constructor, with no external calls.
     * @param _identityType The type of the identity (see {IdentityTypes}).
     * @param _keys Initial keys to register on the new identity.
     * @param _modules Initial modules to install on the new identity.
     */
    function initialize(
        uint256 _identityType,
        Structs.KeyParam[] calldata _keys,
        Structs.ModuleInstall[] calldata _modules
    ) external virtual initializer {
        // The account needs at least a validator (to verify signatures) or an executor
        // (to dispatch outbound calls). Without either it can't do anything useful.
        require(_hasValidatorOrExecutor(_modules), Errors.IdentityNoValidatorOrExecutor());

        _getIdentityMetadata().identityType = _identityType;
        __AccountERC7579_init();
        __Identity_init();

        // Install modules FIRST. The validator that holds the key registry must be installed and
        // enshrined before any key is seeded, because keys now live in that module (a self-call).
        // The validator's `onInstall(initData)` seeds the first MANAGEMENT key, so the registry is
        // usable the moment it is enshrined. Module install entries with a non-zero purpose grant
        // the module address a MODULE-type key with that purpose (e.g. the KeyApprovalModule
        // executor gets MANAGEMENT so it can dispatch self-targeted calls).
        for (uint256 i = 0; i < _modules.length; i++) {
            _installModule(_modules[i].moduleType, _modules[i].module, _modules[i].initData);

            if (_modules[i].moduleType == MODULE_TYPE_VALIDATOR) {
                // Enshrine the first validator seen as the account's registry module (set-once).
                _enshrineRegistryModule(_modules[i].module);
            }
        }

        // Grant module-purpose keys through the enshrined module, after it exists. Kept in a second
        // pass so the registry module is already set when the first grant runs.
        for (uint256 i = 0; i < _modules.length; i++) {
            if (_modules[i].purpose != 0) {
                IKeyRegistryModule(_registryModule())
                    .addKey(abi.encodePacked(_modules[i].module), "", _modules[i].purpose, KeyTypes.MODULE);
            }
        }

        // Seed the caller-supplied keys into the enshrined registry module.
        for (uint256 i = 0; i < _keys.length; i++) {
            Structs.KeyParam calldata key = _keys[i];
            IKeyRegistryModule(_registryModule()).addKey(key.signerData, key.clientData, key.purpose, key.keyType);
        }

        emit IdentityInitialized(_identityType);
    }

    /// @dev True when `modules` contains at least one validator or executor entry.
    function _hasValidatorOrExecutor(Structs.ModuleInstall[] calldata modules) private pure returns (bool) {
        for (uint256 i = 0; i < modules.length; i++) {
            if (modules[i].moduleType == MODULE_TYPE_VALIDATOR || modules[i].moduleType == MODULE_TYPE_EXECUTOR) {
                return true;
            }
        }
        return false;
    }

    /// @notice Returns the identity type set at initialization.
    /// @return The identity type as defined in {IdentityTypes}.
    function getIdentityType() external view returns (uint256) {
        return _getIdentityMetadata().identityType;
    }

    /// @notice ERC-7579 account identifier.
    function accountId() public view virtual override returns (string memory) {
        return "trex.onchainid.identity.v3.0.0";
    }

    /// @notice Current contract version.
    function version() external pure virtual returns (string memory) {
        return "3.0.0";
    }

    /// @notice ERC-165 surface. Returns true for the ERC-734 / ERC-735 / IIdentity selectors
    ///         even though the ERC-735 methods are served by an installed module via the
    ///         fallback handler — the interface contract is still honored at runtime.
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return (interfaceId == type(IERC734).interfaceId || interfaceId == type(IERC735).interfaceId
                || interfaceId == type(IIdentity).interfaceId || super.supportsInterface(interfaceId));
    }

    /**
     * @notice Internal initializer. Marks the KeyManager storage as initialized and flips
     *         the delegated-only guard on so direct calls to the implementation contract
     *         are rejected. No MANAGEMENT key is written here; the initial keys come from
     *         the caller-supplied array in {initialize}.
     */
    // solhint-disable-next-line func-name-mixedcase
    function __Identity_init() internal {
        KeyStorage storage ks = _getKeyStorage();
        require(!ks.initialized, Errors.InitialKeyAlreadySetup());
        ks.initialized = true;
        ks.canInteract = true;
    }

    /// @dev Returns the identity metadata storage at its ERC-7201 slot.
    function _getIdentityMetadata() internal pure returns (IdentityMetadata storage s) {
        bytes32 slot = _IDENTITY_METADATA_SLOT;
        assembly ("memory-safe") {
            s.slot := slot
        }
    }

}
