// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { SmartAccount } from "./SmartAccount.sol";
import { IERC734 } from "./interface/IERC734.sol";
import { IERC735 } from "./interface/IERC735.sol";
import { IIdentity } from "./interface/IIdentity.sol";
import { Errors } from "./libraries/Errors.sol";
import { KeyTypes } from "./libraries/KeyTypes.sol";
import { ERC734Validator } from "./modules/validators/ERC734Validator.sol";
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
 *      The key registry lives in the enshrined {ERC734Validator}, whose address is an immutable
 *      set at implementation deploy time — every identity behind the beacon shares it.
 *
 *      Storage layout uses ERC-7201 namespaced slots:
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

    /// @dev Release version. {accountId} and {version} both read this so they cannot drift
    ///      apart. The EIP-712 domain version in the constructor is separate on purpose: it is
    ///      baked into every stored claim signature and must not follow releases.
    string private constant _VERSION = "3.0.0";

    /// @dev ERC-7201 storage slot for identity-level metadata.
    bytes32 internal constant _IDENTITY_METADATA_SLOT =
        keccak256(abi.encode(uint256(keccak256(bytes("onchainid.identity.metadata"))) - 1)) & ~bytes32(uint256(0xff));

    /// @dev The enshrined ERC-734 registry module, fixed at implementation deploy time. Read
    ///      through the {registryModule} getter.
    address private immutable _registryModule;

    /// @dev The factory that deploys this identity, fixed at implementation deploy time. Read
    ///      through the {identityFactory} getter.
    address private immutable _identityFactory;

    /**
     * @notice Constructor of the Identity contract.
     * @param registryModule_ The {ERC734Validator} that holds the key and claim registries.
     * @param identityFactory_ The {IdentityFactory} that deploys identities of this implementation.
     * @dev The implementation is only ever used behind a BeaconProxy, so its own `Initializable`
     *      slot is locked here; proxies keep their storage untouched and can initialize.
     *
     *      The EIP-712 domain version stays at "1" regardless of {_VERSION}. Claim digests
     *      are rebuilt from the live domain on every read, so bumping it would invalidate
     *      every stored claim signature at once. Only change it as a deliberate migration
     *      that breaks old signatures.
     */
    constructor(address registryModule_, address identityFactory_) EIP712("OnchainID", "1") {
        require(registryModule_ != address(0), Errors.ZeroAddress());
        require(identityFactory_ != address(0), Errors.ZeroAddress());
        _registryModule = registryModule_;
        _identityFactory = identityFactory_;
        _disableInitializers();
    }

    /// @notice The enshrined ERC-734 registry module (the merged {ERC734Validator}). Fixed at
    ///         implementation deploy time; every identity behind the beacon shares it. Changing
    ///         the registry means deploying a new implementation and upgrading the beacon.
    function registryModule() public view override returns (address) {
        return _registryModule;
    }

    /// @notice The factory that deploys this identity. Fixed at implementation deploy time like
    ///         {registryModule}. The account uses it to require MANAGEMENT for the factory's
    ///         wallet-binding calls (linkAccount, revokeAccount, settlePendingCrossChainLink).
    function identityFactory() public view override returns (address) {
        return _identityFactory;
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

        // Install the supplied modules. The enshrined registry module is an immutable, so keys
        // can be written in any order relative to the installs. Module install entries with a
        // non-zero purpose grant the module address a MODULE-type key with that purpose (e.g.
        // the KeyApprovalModule executor gets MANAGEMENT so it can dispatch self-targeted calls).
        for (uint256 i = 0; i < _modules.length; i++) {
            _installModule(_modules[i].moduleType, _modules[i].module, _modules[i].initData);

            if (_modules[i].purpose != 0) {
                ERC734Validator(registryModule())
                    .addKey(abi.encodePacked(_modules[i].module), "", _modules[i].purpose, KeyTypes.MODULE);
            }
        }

        // Seed the caller-supplied keys through the keyHash check, so the deploy salt
        // commits to the keys actually registered.
        for (uint256 i = 0; i < _keys.length; i++) {
            Structs.KeyParam calldata key = _keys[i];
            _addKeyWithData(key.keyHash, key.purpose, key.keyType, key.signerData, key.clientData);
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

    /// @notice The Initializable version stored on this contract. On an implementation whose
    ///         constructor ran `_disableInitializers` this is `type(uint64).max`. The factory
    ///         reads it before a beacon upgrade to reject an unlocked implementation.
    function initializedVersion() external view returns (uint64) {
        return _getInitializedVersion();
    }

    /// @notice ERC-7579 account identifier.
    function accountId() public view virtual override returns (string memory) {
        return string.concat("trex.onchainid.identity.v", _VERSION);
    }

    /// @notice Current contract version.
    function version() external pure virtual returns (string memory) {
        return _VERSION;
    }

    /// @notice ERC-165 surface. Returns true for the ERC-734 / ERC-735 / IIdentity selectors
    ///         even though the ERC-735 methods are served by an installed module via the
    ///         fallback handler — the interface contract is still honored at runtime.
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return (interfaceId == type(IERC734).interfaceId || interfaceId == type(IERC735).interfaceId
                || interfaceId == type(IIdentity).interfaceId || super.supportsInterface(interfaceId));
    }

    /// @dev Returns the identity metadata storage at its ERC-7201 slot.
    function _getIdentityMetadata() internal pure returns (IdentityMetadata storage s) {
        bytes32 slot = _IDENTITY_METADATA_SLOT;
        assembly ("memory-safe") {
            s.slot := slot
        }
    }

}
