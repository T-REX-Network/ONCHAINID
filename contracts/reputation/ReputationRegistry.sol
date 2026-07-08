// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { AccessManaged } from "@openzeppelin/contracts/access/manager/AccessManaged.sol";

import { IIdentityFactory } from "../factory/IIdentityFactory.sol";
import { IIdentity } from "../interface/IIdentity.sol";
import { Errors } from "../libraries/Errors.sol";
import { IReputationRegistry } from "./IReputationRegistry.sol";

/// @title ReputationRegistry
/// @notice Per-identity reputation scores, plus per-type defaults.
///
///         Two writers, both gated by REPUTATION_MANAGER via the AccessManager:
///         * {setReputation} overwrites an identity's explicit entry.
///         * {setDefault} overwrites the default score for a given identity type.
///
///         One canonical read, {reputationOf}:
///         * Explicit entry (`setAt != 0`) returns its score, including `0`
///           (manager-revoked trust). This path bypasses the factory check
///           because the manager may want to score externally-deployed
///           identities by hand.
///         * No explicit entry returns `defaultFor[type]` only if the identity
///           was deployed by the factory (verified via the immutable
///           {IIdentityFactory} reference). Any address that was not deployed by
///           the factory and has no explicit entry reads `0`. This stops a
///           random contract from inheriting the CLAIM_ISSUER default just by
///           returning `5` from {getIdentityType}; only the factory can mint
///           that trust signal.
///
///         Storage is namespaced under ERC-7201 so a future proxy variant slots
///         in without a layout migration. v1 ships non-upgradeable.
contract ReputationRegistry is IReputationRegistry, AccessManaged {

    /// @notice The factory whose `isFactoryIdentity` view gates the default-tier
    ///         fallback. Immutable so the trust anchor is pinned at construction.
    IIdentityFactory public immutable factory;

    /// @dev EIP-7201 namespaced storage. All mutable state lives here so a
    ///      future upgradeable variant doesn't collide with inherited slots.
    /// @custom:storage-location erc7201:onchainid.ReputationRegistry
    struct ReputationRegistryStorage {
        /// @dev Per-identity explicit entry. `setAt == 0` means no entry exists,
        ///      and the lookup falls back to `defaultFor[type]`.
        mapping(address identity => Entry entry) reputation;
        /// @dev Per-type default. Applied lazily on read. Tunable by
        ///      REPUTATION_MANAGER. Stored `uint128` to match `Entry.score`.
        mapping(uint256 identityType => uint128 score) defaultFor;
        /// @dev Global threshold consumers compare against {reputationOf} when
        ///      deciding whether a claim-add auto-approves. Tunable by
        ///      REPUTATION_MANAGER.
        uint128 claimAddThreshold;
    }

    // keccak256(abi.encode(uint256(keccak256("onchainid.ReputationRegistry")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _REPUTATION_REGISTRY_STORAGE_SLOT =
        0xf14f9ea5236057e326d1c26ab089d99ae0165f5465c8413baa51d790a28f1500;

    function _storage() private pure returns (ReputationRegistryStorage storage $) {
        bytes32 slot = _REPUTATION_REGISTRY_STORAGE_SLOT;
        assembly {
            $.slot := slot
        }
    }

    /// @param initialAuthority AccessManager that backs every `restricted` write.
    /// @param identityFactory The IdentityFactory whose `isFactoryIdentity` view gates
    ///                        the default-tier fallback. Reverts the deploy on zero.
    constructor(address initialAuthority, address identityFactory) AccessManaged(initialAuthority) {
        require(initialAuthority != address(0), Errors.ZeroAddress());
        require(identityFactory != address(0), Errors.ZeroAddress());
        factory = IIdentityFactory(identityFactory);
    }

    /// @inheritdoc IReputationRegistry
    function setReputation(address identity, uint128 newScore) external restricted {
        require(identity != address(0), Errors.ZeroAddress());
        Entry storage entry = _storage().reputation[identity];
        uint128 previousScore = entry.score;
        entry.score = newScore;
        // block.timestamp fits comfortably in uint64; uint128 is overkill but
        // keeps the (score, setAt) pair packed in one slot.
        // forge-lint: disable-next-line(unsafe-typecast)
        entry.setAt = uint128(block.timestamp);
        emit ReputationSet(identity, previousScore, newScore, msg.sender);
    }

    /// @inheritdoc IReputationRegistry
    function setDefault(uint256 identityType, uint128 newDefault) external restricted {
        uint128 previousDefault = _storage().defaultFor[identityType];
        _storage().defaultFor[identityType] = newDefault;
        emit DefaultSet(identityType, previousDefault, newDefault);
    }

    /// @inheritdoc IReputationRegistry
    function setClaimAddThreshold(uint128 newThreshold) external restricted {
        uint128 previousThreshold = _storage().claimAddThreshold;
        _storage().claimAddThreshold = newThreshold;
        emit ClaimAddThresholdSet(previousThreshold, newThreshold);
    }

    /// @inheritdoc IReputationRegistry
    function reputationOf(address identity) external view returns (uint128) {
        Entry storage entry = _storage().reputation[identity];
        if (entry.setAt != 0) {
            return entry.score;
        }
        // Lazy fallback: gated on factory membership so an arbitrary contract
        // that self-declares its type cannot inherit a default. Manager-set
        // entries above bypass this gate by design.
        if (!factory.isFactoryIdentity(identity)) {
            return 0;
        }
        uint256 identityType = IIdentity(identity).getIdentityType();
        return _storage().defaultFor[identityType];
    }

    /// @inheritdoc IReputationRegistry
    function entryOf(address identity) external view returns (uint128 score, uint128 setAt) {
        Entry storage entry = _storage().reputation[identity];
        return (entry.score, entry.setAt);
    }

    /// @inheritdoc IReputationRegistry
    function defaultFor(uint256 identityType) external view returns (uint128) {
        return _storage().defaultFor[identityType];
    }

    /// @inheritdoc IReputationRegistry
    function claimAddThreshold() external view returns (uint128) {
        return _storage().claimAddThreshold;
    }

}
