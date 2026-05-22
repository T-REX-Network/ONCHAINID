// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { SmartAccount } from "./SmartAccount.sol";
import { IERC734 } from "./interface/IERC734.sol";
import { IERC735 } from "./interface/IERC735.sol";
import { IIdentity } from "./interface/IIdentity.sol";
import { Errors } from "./libraries/Errors.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title Identity
 * @dev Smart-account identity. ERC-734 key registry lives here (inherited from {KeyManager} via
 *      {SmartAccount}); ERC-735 claim functionality is provided by an installed {ClaimsModule}
 *      reached through this account's ERC-7579 fallback handler.
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
 *
 *      The {IIdentity} interface continues to declare the ERC-735 selectors; calls to those
 *      selectors land on the installed ClaimsModule via fallback dispatch.
 */
contract Identity is Initializable, SmartAccount {

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
     * @param initialManagementKey The management key address at deployment.
     * @param _isLibrary True when deploying the implementation contract behind a proxy. In that
     *        case we lock the OZ `Initializable` slot via `_disableInitializers()` so the
     *        implementation can never be initialized directly; only proxies (which run the
     *        constructor in their own context with `_isLibrary == false`) can initialize.
     */
    constructor(address initialManagementKey, bool _isLibrary) EIP712("OnchainID", "1") {
        if (_isLibrary) {
            _disableInitializers();
        } else {
            __Identity_init(initialManagementKey);
        }
    }

    /**
     * @notice When using this contract as an implementation for a proxy, call this initializer
     *         with a delegatecall. Sets up the initial MANAGEMENT key and the identity type, and
     *         runs the ERC-7579 module-registry initializer.
     * @param initialManagementKey The ethereum address to be set as the management key of the ONCHAINID.
     * @param _identityType The type of the identity (see {IdentityTypes}).
     */
    function initialize(address initialManagementKey, uint256 _identityType) external virtual initializer {
        _getIdentityMetadata().identityType = _identityType;
        __AccountERC7579_init();
        __Identity_init(initialManagementKey);
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
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return (interfaceId == type(IERC165).interfaceId || interfaceId == type(IERC734).interfaceId
                || interfaceId == type(IERC735).interfaceId || interfaceId == type(IIdentity).interfaceId);
    }

    /**
     * @notice Internal initializer. Sets up the initial MANAGEMENT key, marks the KeyManager
     *         storage as initialized, and flips the delegated-only guard on so direct calls to
     *         the implementation contract are rejected.
     */
    // solhint-disable-next-line func-name-mixedcase
    function __Identity_init(address initialManagementKey) internal {
        require(initialManagementKey != address(0), Errors.ZeroAddress());
        KeyStorage storage ks = _getKeyStorage();
        require(!ks.initialized, Errors.InitialKeyAlreadySetup());
        ks.initialized = true;
        ks.canInteract = true;

        _setupInitialManagementKey(initialManagementKey);
    }

    /// @dev Returns the identity metadata storage at its ERC-7201 slot.
    function _getIdentityMetadata() internal pure returns (IdentityMetadata storage s) {
        bytes32 slot = _IDENTITY_METADATA_SLOT;
        assembly ("memory-safe") {
            s.slot := slot
        }
    }

}
