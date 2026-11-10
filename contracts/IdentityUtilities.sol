// SPDX-License-Identifier: GPL-3.0
//
// ONCHAINID Smart Contracts
// Digital identities for the T-REX ecosystem.
//
// Copyright (C) 2026 Digital Asset Operational Services ISAC Ltd. ("T-REX Network")
//
// This file is part of the ONCHAINID smart contract suite.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.27;

import { IClaimIssuer } from "./interface/IClaimIssuer.sol";
import { IIdentity } from "./interface/IIdentity.sol";
import { IIdentityUtilities } from "./interface/IIdentityUtilities.sol";
import { Structs } from "./storage/Structs.sol";
import {
    AccessManagedUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import { LowLevelCall } from "@openzeppelin/contracts/utils/LowLevelCall.sol";

/**
 * @title IdentityUtilities
 * @notice Contract for registering and retrieving structured topic schemas using encoded string arrays.
 * @dev Topic writes and upgrades are `restricted`: the AccessManager that governs the rest of the
 * stack decides who may call them. Topics define field names and types using ABI-encoded
 * `string[]` arrays.
 */
contract IdentityUtilities is IIdentityUtilities, AccessManagedUpgradeable, UUPSUpgradeable {

    /// @custom:storage-location erc7201:onchainid.IdentityUtilities
    struct UtilitiesStorage {
        mapping(uint256 topicId => TopicInfo) topics;
    }

    // keccak256(abi.encode(uint256(keccak256("onchainid.IdentityUtilities")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _UTILITIES_STORAGE_SLOT =
        keccak256(abi.encode(uint256(keccak256(bytes("onchainid.IdentityUtilities"))) - 1)) & ~bytes32(uint256(0xff));

    /// @notice Disables initializers on the implementation contract
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the contract with the AccessManager that gates its writes.
     * @param initialAuthority The AccessManager shared by the whole stack
     */
    function initialize(address initialAuthority) external initializer {
        __AccessManaged_init(initialAuthority);
    }

    /**
     * @inheritdoc IIdentityUtilities
     */
    function addTopic(
        uint256 topicId,
        string calldata name,
        bytes calldata encodedFieldNames,
        bytes calldata encodedFieldTypes
    ) external override restricted {
        require(bytes(name).length > 0, "Empty topic name");
        require(_store().topics[topicId].encodedFieldNames.length == 0, "Topic already exists");
        _validateFieldArrays(encodedFieldNames, encodedFieldTypes);

        _store().topics[topicId] =
            TopicInfo({ name: name, encodedFieldNames: encodedFieldNames, encodedFieldTypes: encodedFieldTypes });

        emit TopicAdded(topicId, name, encodedFieldNames, encodedFieldTypes, msg.sender);
    }

    /**
     * @inheritdoc IIdentityUtilities
     */
    function updateTopic(
        uint256 topicId,
        string calldata name,
        bytes calldata encodedFieldNames,
        bytes calldata encodedFieldTypes
    ) external override restricted {
        require(_store().topics[topicId].encodedFieldNames.length != 0, "Topic does not exist");
        require(bytes(name).length > 0, "Empty topic name");
        _validateFieldArrays(encodedFieldNames, encodedFieldTypes);

        _store().topics[topicId] =
            TopicInfo({ name: name, encodedFieldNames: encodedFieldNames, encodedFieldTypes: encodedFieldTypes });

        emit TopicUpdated(topicId, name, encodedFieldNames, encodedFieldTypes, msg.sender);
    }

    /**
     * @inheritdoc IIdentityUtilities
     */
    function removeTopic(uint256 topicId) external override restricted {
        require(_store().topics[topicId].encodedFieldNames.length != 0, "Topic does not exist");
        delete _store().topics[topicId];
        emit TopicRemoved(topicId, msg.sender);
    }

    /**
     * @inheritdoc IIdentityUtilities
     */
    function getTopic(uint256 topicId) external view override returns (TopicInfo memory) {
        return _store().topics[topicId];
    }

    /**
     * @inheritdoc IIdentityUtilities
     */
    function getSchema(uint256 topicId)
        external
        view
        override
        returns (string[] memory fieldNames, string[] memory fieldTypes)
    {
        if (_store().topics[topicId].encodedFieldNames.length == 0) {
            return (new string[](0), new string[](0));
        }
        fieldNames = abi.decode(_store().topics[topicId].encodedFieldNames, (string[]));
        fieldTypes = abi.decode(_store().topics[topicId].encodedFieldTypes, (string[]));
    }

    /**
     * @notice Returns decoded field names for a given topic ID
     * @param topicId The ID of the topic
     * @return string[] Array of field names
     */
    function getFieldNames(uint256 topicId) external view returns (string[] memory) {
        if (_store().topics[topicId].encodedFieldNames.length == 0) {
            return new string[](0);
        }
        return abi.decode(_store().topics[topicId].encodedFieldNames, (string[]));
    }

    /**
     * @notice Returns decoded field types for a given topic ID
     * @param topicId The ID of the topic
     * @return string[] Array of field types
     */
    function getFieldTypes(uint256 topicId) external view returns (string[] memory) {
        if (_store().topics[topicId].encodedFieldTypes.length == 0) {
            return new string[](0);
        }
        return abi.decode(_store().topics[topicId].encodedFieldTypes, (string[]));
    }

    /**
     * @notice Returns an array of TopicInfo structs for the given topic IDs
     * @param topicIds Array of topic IDs to get TopicInfo structs for
     * @return TopicInfo[] Array of TopicInfo structs corresponding to the input topic IDs
     */
    function getTopicInfos(uint256[] calldata topicIds) external view returns (TopicInfo[] memory) {
        TopicInfo[] memory topics = new TopicInfo[](topicIds.length);
        for (uint256 i = 0; i < topicIds.length; i++) {
            topics[i] = _store().topics[topicIds[i]];
        }
        return topics;
    }

    /**
     * @notice Gets comprehensive claim information for an identity across multiple topics
     * @param identity The identity contract address
     * @param topicIds Array of topic IDs to check
     * @return result Array of claim information structs
     */
    function getClaimsWithTopicInfo(address identity, uint256[] calldata topicIds)
        external
        view
        returns (ClaimInfo[] memory result)
    {
        uint256 totalClaims = _countTotalClaims(identity, topicIds);
        result = new ClaimInfo[](totalClaims);
        uint256 resultIndex = 0;

        for (uint256 i = 0; i < topicIds.length; i++) {
            uint256 topicId = topicIds[i];
            TopicInfo memory topicInfo = _store().topics[topicId];
            bytes32[] memory claimIds = IIdentity(identity).getClaimIdsByTopic(topicId);
            for (uint256 j = 0; j < claimIds.length; j++) {
                result[resultIndex] = _buildClaimInfo(identity, topicId, topicInfo, claimIds[j]);
                resultIndex++;
            }
        }
    }

    /**
     * @dev Required override for UUPS upgradability authorization
     * @param newImplementation Address of the new implementation
     */
    function _authorizeUpgrade(address newImplementation) internal override restricted { }

    function _countTotalClaims(address identity, uint256[] calldata topicIds) internal view returns (uint256 total) {
        for (uint256 i = 0; i < topicIds.length; i++) {
            bytes32[] memory claimIds = IIdentity(identity).getClaimIdsByTopic(topicIds[i]);
            total += claimIds.length;
        }
    }

    /// @dev Asks the issuer with a low-level call, so one issuer that returns nothing or a
    ///      malformed bool cannot make the whole listing revert. Only an answer of exactly 1 is valid.
    function _isClaimValid(
        address identity,
        uint256 topicId,
        address issuer,
        bytes memory signature,
        Structs.ClaimData memory data
    ) internal view returns (bool) {
        if (issuer == address(0)) return false;

        bytes memory isClaimValidCall =
            abi.encodeCall(IClaimIssuer.isClaimValid, (IIdentity(identity), topicId, signature, data));
        (bool callSucceeded, bytes32 answer,) = LowLevelCall.staticcallReturn64Bytes(issuer, isClaimValidCall);
        bool answeredOneWord = LowLevelCall.returnDataSize() >= 32;

        if (!callSucceeded) return false;
        if (!answeredOneWord) return false;
        return answer == bytes32(uint256(1));
    }

    function _buildClaimInfo(address identity, uint256 topicId, TopicInfo memory topicInfo, bytes32 claimId)
        internal
        view
        returns (ClaimInfo memory info)
    {
        (,
            // topic - not used
            uint256 scheme,
            address issuer,
            bytes memory signature,
            Structs.ClaimData memory data,
            string memory uri
        ) = IIdentity(identity).getClaim(claimId);

        bool isValid = _isClaimValid(identity, topicId, issuer, signature, data);

        info = ClaimInfo({
            topic: topicInfo,
            isValid: isValid,
            claimId: claimId,
            scheme: scheme,
            issuer: issuer,
            signature: signature,
            data: data,
            uri: uri
        });
    }

    /**
     * @dev Validates that encoded field names/types match in length and content.
     * @param encodedNames ABI-encoded string[] of field names
     * @param encodedTypes ABI-encoded string[] of field types
     */
    function _validateFieldArrays(bytes memory encodedNames, bytes memory encodedTypes) internal pure {
        string[] memory names = abi.decode(encodedNames, (string[]));
        string[] memory types_ = abi.decode(encodedTypes, (string[]));
        require(names.length == types_.length, "Field name/type count mismatch");

        for (uint256 i = 0; i < names.length; i++) {
            require(bytes(names[i]).length > 0, "Empty field name");
            require(bytes(types_[i]).length > 0, "Empty field type");
        }
    }

    /// @dev Returns the utilities storage at its ERC-7201 slot.
    function _store() private pure returns (UtilitiesStorage storage store) {
        bytes32 slot = _UTILITIES_STORAGE_SLOT;
        assembly ("memory-safe") {
            store.slot := slot
        }
    }

}
