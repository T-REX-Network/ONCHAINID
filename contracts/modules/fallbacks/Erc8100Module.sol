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

import { Identity } from "../../Identity.sol";
import { IClaimIssuer } from "../../interface/IClaimIssuer.sol";
import { IERC735 } from "../../interface/IERC735.sol";
import { IIdentity } from "../../interface/IIdentity.sol";
import { IIdentityUtilities } from "../../interface/IIdentityUtilities.sol";
import { IXMLRepresentableState } from "../../interface/IRepresentableState.sol";
import { Errors } from "../../libraries/Errors.sol";
import { Structs } from "../../storage/Structs.sol";
import { ERC734Validator } from "../validators/ERC734Validator.sol";
import { IERC7579Module, MODULE_TYPE_FALLBACK } from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";

/**
 * @title Erc8100Module
 * @notice ERC-8100 fallback module. Installed on an identity, it gives that identity a static XML
 *         template plus the zero-argument list getters the template binds, so an off-chain renderer
 *         can produce one XML document of the identity at one block with `eth_call` only.
 *
 *         Every function here is reached through the identity's ERC-7579 fallback, so `msg.sender`
 *         is the identity being reported. The module keeps no storage.
 *
 *         Reported claim topics are the topics with a schema in {IIdentityUtilities}. The report
 *         grows when a schema is registered and shrinks when one is removed. A claim under a topic
 *         without a schema is not reported. Each claim costs two reads through the identity plus one
 *         call to its issuer, so the number of registered schemas is the size knob.
 *
 *         The claim payload is returned raw. The schema registry plus one ABI decode off-chain turns
 *         it into named fields; decoding on-chain would be the hardest code in this contract.
 *
 */
contract Erc8100Module is IERC7579Module, IXMLRepresentableState {

    using Strings for uint256;

    /// @notice One ERC-734 key. `purposes` is the comma-separated purpose list in the order the
    ///         purposes were granted, e.g. "1,3".
    struct Key {
        bytes32 keyHash;
        uint256 keyType;
        string purposes;
    }

    /// @notice One ERC-735 claim. `status`: 0 unknown (issuer unreachable), 1 valid, 2 invalid.
    struct Claim {
        bytes32 claimId;
        uint256 topic;
        uint256 scheme;
        address issuer;
        uint256 issuedAt;
        uint256 validUntil;
        bytes32 metadataHash;
        bytes payload;
        string uri;
        uint256 status;
    }

    uint256 private constant _STATUS_UNKNOWN = 0;
    uint256 private constant _STATUS_VALID = 1;
    uint256 private constant _STATUS_INVALID = 2;

    /// @notice The topic schema registry. Its registered topic ids are the topics this module represents.
    IIdentityUtilities public immutable identityUtilities;

    constructor(IIdentityUtilities _identityUtilities) {
        require(address(_identityUtilities) != address(0), Errors.ZeroAddress());
        identityUtilities = _identityUtilities;
    }

    // ---------------------------------------------------------------------------------------------
    // ERC-7579 module lifecycle
    // ---------------------------------------------------------------------------------------------

    /// @inheritdoc IERC7579Module
    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_FALLBACK;
    }

    /// @inheritdoc IERC7579Module
    function onInstall(bytes calldata) external pure { }

    /// @inheritdoc IERC7579Module
    function onUninstall(bytes calldata) external pure { }

    // ---------------------------------------------------------------------------------------------
    // ERC-8100 template
    // ---------------------------------------------------------------------------------------------

    /// @inheritdoc IXMLRepresentableState
    /// @dev `getIdentityType()` is a real function on the identity; the others are this module's
    ///      fallbacks. `ValidUntil` stays a number because 0 means "no expiry".
    function stateXmlTemplate() external pure returns (string memory) {
        return string.concat(
            "<Identity xmlns='urn:onchainid:identity:1.0' xmlns:evmstate='urn:evm:state:1.0'",
            " evmstate:chain-id='' evmstate:contract-address='' evmstate:block-number=''>",
            "<Type evmstate:call='getIdentityType()(uint256)'/>",
            "<ClaimTopics evmstate:call='claimTopics()(uint256[])' evmstate:item-element='Topic'>",
            "<Topic evmstate:item-field='0'/></ClaimTopics>",
            "<Keys evmstate:call='keys()(tuple(bytes32,uint256,string)[])' evmstate:item-element='Key'>",
            "<Key><Hash evmstate:item-field='0' evmstate:format='hex'/><Type evmstate:item-field='1'/>",
            "<Purposes evmstate:item-field='2'/></Key></Keys>",
            "<Claims evmstate:call='claims()",
            "(tuple(bytes32,uint256,uint256,address,uint256,uint256,bytes32,bytes,string,uint256)[])'",
            " evmstate:item-element='Claim'>",
            "<Claim><Id evmstate:item-field='0' evmstate:format='hex'/><Topic evmstate:item-field='1'/>",
            "<Scheme evmstate:item-field='2'/><Issuer evmstate:item-field='3' evmstate:format='address'/>",
            "<IssuedAt evmstate:item-field='4' evmstate:format='iso8601-datetime'/><ValidUntil evmstate:item-field='5'/>",
            "<MetadataHash evmstate:item-field='6' evmstate:format='hex'/><Payload evmstate:item-field='7' evmstate:format='hex'/>",
            "<Uri evmstate:item-field='8'/><Status evmstate:item-field='9'/></Claim></Claims>",
            "</Identity>"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // Lists bound by the template
    // ---------------------------------------------------------------------------------------------

    /// @notice The claim topics this module reports: every topic with a registered schema.
    function claimTopics() public view returns (uint256[] memory) {
        return identityUtilities.getTopicIds();
    }

    /// @notice Every key of the calling identity with its purposes. Use the `(start, end)`
    ///         overload for identities with many keys.
    function keys() external view returns (Key[] memory) {
        return keys(0, type(uint64).max);
    }

    /// @notice Keys of the calling identity in the index range `[start, end)`. `end` past the
    ///         count returns the available tail.
    function keys(uint256 start, uint256 end) public view returns (Key[] memory rows) {
        address identity = msg.sender;
        bytes32[] memory keyHashes = _registry(identity).getKeys(identity, start, end);
        rows = new Key[](keyHashes.length);
        for (uint256 i = 0; i < keyHashes.length; i++) {
            rows[i] = _key(identity, keyHashes[i]);
        }
    }

    /// @notice Every claim of the calling identity under a reported topic. Use the `(start, end)`
    ///         overload for identities with many claims.
    function claims() external view returns (Claim[] memory) {
        return claims(0, type(uint64).max);
    }

    /// @notice Claims of the calling identity in the index range `[start, end)` of the list
    ///         ordered by topic then by claim. `end` past the count returns the available tail.
    function claims(uint256 start, uint256 end) public view returns (Claim[] memory rows) {
        address identity = msg.sender;
        bytes32[] memory claimIds = _page(_allClaimIds(identity), start, end);
        rows = new Claim[](claimIds.length);
        for (uint256 i = 0; i < claimIds.length; i++) {
            rows[i] = _claim(identity, claimIds[i]);
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Keys
    // ---------------------------------------------------------------------------------------------

    function _key(address identity, bytes32 keyHash) private view returns (Key memory) {
        (uint256[] memory purposes, uint256 keyType,) = _registry(identity).getKey(identity, keyHash);
        return Key({ keyHash: keyHash, keyType: keyType, purposes: _joinPurposes(purposes) });
    }

    /// @dev "1,3" for purposes [1, 3]: the first purpose, then ",next" for each remaining one.
    function _joinPurposes(uint256[] memory purposes) private pure returns (string memory joined) {
        if (purposes.length == 0) return "";
        joined = purposes[0].toString();
        for (uint256 i = 1; i < purposes.length; i++) {
            joined = string.concat(joined, ",", purposes[i].toString());
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Claims
    // ---------------------------------------------------------------------------------------------

    /// @dev The claim ids under every reported topic, read through the identity's own fallback.
    function _allClaimIds(address identity) private view returns (bytes32[] memory claimIds) {
        uint256[] memory topics = claimTopics();
        claimIds = new bytes32[](_countClaims(identity, topics));
        uint256 filled = 0;
        for (uint256 i = 0; i < topics.length; i++) {
            bytes32[] memory idsForTopic = IERC735(identity).getClaimIdsByTopic(topics[i]);
            for (uint256 j = 0; j < idsForTopic.length; j++) {
                claimIds[filled] = idsForTopic[j];
                filled++;
            }
        }
    }

    function _countClaims(address identity, uint256[] memory topics) private view returns (uint256 total) {
        for (uint256 i = 0; i < topics.length; i++) {
            total += IERC735(identity).getClaimIdsByTopic(topics[i]).length;
        }
    }

    function _claim(address identity, bytes32 claimId) private view returns (Claim memory) {
        (
            uint256 topic,
            uint256 scheme,
            address issuer,
            bytes memory signature,
            Structs.ClaimData memory data,
            string memory uri
        ) = IERC735(identity).getClaim(claimId);

        return Claim({
            claimId: claimId,
            topic: topic,
            scheme: scheme,
            issuer: issuer,
            issuedAt: data.issuedAt,
            validUntil: data.validUntil,
            metadataHash: data.metadataHash,
            payload: data.payload,
            uri: uri,
            status: _claimStatus(identity, topic, issuer, signature, data)
        });
    }

    /// @dev Asks the issuer. A revert is reported as unknown, never as invalid.
    function _claimStatus(
        address identity,
        uint256 topic,
        address issuer,
        bytes memory signature,
        Structs.ClaimData memory data
    ) private view returns (uint256) {
        if (issuer == address(0)) return _STATUS_UNKNOWN;
        try IClaimIssuer(issuer).isClaimValid(IIdentity(identity), topic, signature, data) returns (bool valid) {
            if (valid) return _STATUS_VALID;
            return _STATUS_INVALID;
        } catch {
            return _STATUS_UNKNOWN;
        }
    }

    /// @dev The slice `[start, end)` of `ids`, clamped to the list: `end` past the length returns
    ///      the tail, `start` past the length returns nothing.
    function _page(bytes32[] memory ids, uint256 start, uint256 end) private pure returns (bytes32[] memory page) {
        bool endPastTheList = end > ids.length;
        if (endPastTheList) end = ids.length;
        bool startPastTheEnd = start > end;
        if (startPastTheEnd) start = end;

        page = new bytes32[](end - start);
        for (uint256 i = 0; i < page.length; i++) {
            page[i] = ids[start + i];
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Shared
    // ---------------------------------------------------------------------------------------------

    function _registry(address identity) private view returns (ERC734Validator) {
        return ERC734Validator(Identity(payable(identity)).registryModule());
    }

}
