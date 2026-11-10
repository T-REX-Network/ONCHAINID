// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { MockOutOfRangeClaimIssuer } from "../mocks/MockOutOfRangeClaimIssuer.sol";
import { MockSilentClaimIssuer } from "../mocks/MockSilentClaimIssuer.sol";
import { Constants } from "../utils/Constants.sol";
import {
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { IERC735 } from "contracts/interface/IERC735.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { IXMLRepresentableState } from "contracts/interface/IRepresentableState.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Erc8100Module } from "contracts/modules/fallbacks/Erc8100Module.sol";

/// @notice The ERC-8100 module, exercised the way a renderer uses it: every call goes to the
///         identity address and lands on the module through the fallback.
contract Erc8100ModuleTest is OnchainIDSetup {

    Erc8100Module internal module;

    /// The identity address typed as the module, so calls dispatch through the fallback.
    Erc8100Module internal aliceState;

    function setUp() public override {
        super.setUp();

        module = new Erc8100Module();
        _installOnAlice();
        aliceState = Erc8100Module(address(aliceIdentity));
    }

    // ---- lifecycle ----

    function test_isModuleType_AcceptsFallbackOnly() public view {
        assertTrue(module.isModuleType(MODULE_TYPE_FALLBACK));
        assertFalse(module.isModuleType(MODULE_TYPE_VALIDATOR));
        assertFalse(module.isModuleType(MODULE_TYPE_EXECUTOR));
    }

    function test_supportsInterface_AdvertisesIXMLRepresentableStateOnlyWhileInstalled() public {
        bytes4 interfaceId = type(IXMLRepresentableState).interfaceId;
        assertTrue(aliceIdentity.supportsInterface(interfaceId));

        vm.prank(alice);
        aliceIdentity.uninstallModule(
            MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(IXMLRepresentableState.stateXmlTemplate.selector)
        );
        assertFalse(aliceIdentity.supportsInterface(interfaceId));
    }

    // ---- template ----

    function test_stateXmlTemplate_NamesEveryInstalledSelector() public view {
        string memory template = aliceState.stateXmlTemplate();

        assertTrue(_contains(template, "xmlns:evmstate='urn:evm:state:1.0'"));
        assertTrue(_contains(template, "evmstate:call='getIdentityType()(uint256)'"));
        assertTrue(_contains(template, "evmstate:call='stateClaimTopics()(uint256[])'"));
        assertTrue(_contains(template, "evmstate:call='stateKeys()(tuple(bytes32,uint256,string)[])'"));
        assertTrue(_contains(template, "evmstate:call='stateClaims()"));
    }

    // ---- topics ----

    function test_stateClaimTopics_ListsTheTopicsTheIdentityHoldsClaimsFor() public {
        uint256[] memory topics = aliceState.stateClaimTopics();
        assertEq(topics.length, 1, "alice starts with the fixture claim only");
        assertEq(topics[0], Constants.CLAIM_TOPIC_666);

        _addClaim42ToAlice();
        assertEq(aliceState.stateClaimTopics().length, 2, "a claim under a new topic adds the topic");

        vm.prank(alice);
        IERC735(address(aliceIdentity)).removeClaim(aliceClaim666.id);
        topics = aliceState.stateClaimTopics();
        assertEq(topics.length, 1, "removing the last claim of a topic drops the topic");
        assertEq(topics[0], Constants.CLAIM_TOPIC_42);
    }

    // ---- keys ----

    function test_stateKeys_ListsEachKeyOnceWithItsPurposes() public {
        vm.prank(alice);
        aliceIdentity.addKeyWithData(
            ClaimSignerHelper.addressToKey(carol), KeyPurposes.ACTION, KeyTypes.ECDSA, abi.encodePacked(carol), ""
        );
        address queueModule = address(onchainidSetup.keyApprovalModule);

        Erc8100Module.Key[] memory rows = aliceState.stateKeys();

        // alice, carol, david and the execution queue module's own MANAGEMENT key.
        assertEq(rows.length, 4);
        assertEq(_purposesOf(rows, ClaimSignerHelper.addressToKey(alice)), "1");
        assertEq(_purposesOf(rows, ClaimSignerHelper.addressToKey(david)), "2");
        // Purposes are listed in the order they were granted: carol got CLAIM_SIGNER, then ACTION.
        assertEq(_purposesOf(rows, ClaimSignerHelper.addressToKey(carol)), "3,2");
        assertEq(_purposesOf(rows, ClaimSignerHelper.addressToKey(queueModule)), "1");
        assertEq(_keyTypeOf(rows, ClaimSignerHelper.addressToKey(queueModule)), KeyTypes.MODULE);
        assertEq(_keyTypeOf(rows, ClaimSignerHelper.addressToKey(alice)), KeyTypes.ECDSA);
    }

    function test_stateKeys_PaginatesOverTheKeyList() public view {
        Erc8100Module.Key[] memory all = aliceState.stateKeys();
        Erc8100Module.Key[] memory firstTwo = aliceState.stateKeys(0, 2);
        Erc8100Module.Key[] memory tail = aliceState.stateKeys(2, 100);

        assertEq(all.length, 4);
        assertEq(firstTwo.length, 2);
        assertEq(tail.length, 2);
        assertEq(firstTwo[0].keyHash, all[0].keyHash);
        assertEq(tail[0].keyHash, all[2].keyHash);
    }

    // ---- claims ----

    function test_stateClaims_ReturnsClaim666AsValidWithItsRawPayload() public view {
        Erc8100Module.Claim[] memory rows = aliceState.stateClaims();

        assertEq(rows.length, 1);
        assertEq(rows[0].claimId, aliceClaim666.id);
        assertEq(rows[0].topic, Constants.CLAIM_TOPIC_666);
        assertEq(rows[0].scheme, aliceClaim666.scheme);
        assertEq(rows[0].issuer, address(claimIssuer));
        assertEq(rows[0].issuedAt, aliceClaim666.data.issuedAt);
        assertEq(rows[0].validUntil, aliceClaim666.data.validUntil);
        assertEq(rows[0].metadataHash, aliceClaim666.data.metadataHash);
        assertEq(rows[0].payload, hex"0042");
        assertEq(rows[0].uri, aliceClaim666.uri);
        assertEq(rows[0].status, 1);
    }

    function test_stateClaims_ReportsUnknownStatusWhenTheIssuerReverts() public {
        vm.mockCallRevert(address(claimIssuer), IIdentity.isClaimValid.selector, "down");

        Erc8100Module.Claim[] memory rows = aliceState.stateClaims();

        assertEq(rows.length, 1);
        assertEq(rows[0].status, 0);
    }

    function test_stateClaims_ReportsUnknownStatusWhenTheIssuerReturnsNothing() public {
        _replaceIssuerIsClaimValidHandler(address(new MockSilentClaimIssuer()));

        Erc8100Module.Claim[] memory rows = aliceState.stateClaims();

        assertEq(rows.length, 1, "the snapshot still lists the claim");
        assertEq(rows[0].status, 0, "an issuer that returns nothing is unknown");
    }

    function test_stateClaims_ReportsUnknownStatusWhenTheIssuerAnswersNeitherTrueNorFalse() public {
        _replaceIssuerIsClaimValidHandler(address(new MockOutOfRangeClaimIssuer()));

        Erc8100Module.Claim[] memory rows = aliceState.stateClaims();

        assertEq(rows.length, 1, "the snapshot still lists the claim");
        assertEq(rows[0].status, 0, "an answer of 2 is unknown, not valid");
    }

    function test_stateClaims_ReportsInvalidWhenTheIssuerSaysSo() public {
        vm.mockCall(address(claimIssuer), IIdentity.isClaimValid.selector, abi.encode(false));

        Erc8100Module.Claim[] memory rows = aliceState.stateClaims();

        assertEq(rows[0].status, 2);
    }

    function test_stateClaims_ReportsEveryClaimTheIdentityHolds() public {
        _addClaim42ToAlice();

        Erc8100Module.Claim[] memory rows = aliceState.stateClaims();

        assertEq(rows.length, 2, "both claims are reported, whatever schemas exist");
        assertEq(rows[0].topic, Constants.CLAIM_TOPIC_666);
        assertEq(rows[1].topic, Constants.CLAIM_TOPIC_42);
    }

    function test_stateClaims_PaginatesWithinATopic() public {
        _addClaim42ToAlice();

        Erc8100Module.Claim[] memory topic666Rows = aliceState.stateClaims(Constants.CLAIM_TOPIC_666, 0, 10);
        Erc8100Module.Claim[] memory topic42Rows = aliceState.stateClaims(Constants.CLAIM_TOPIC_42, 0, 10);
        assertEq(topic666Rows.length, 1, "one claim under topic 666");
        assertEq(topic666Rows[0].topic, Constants.CLAIM_TOPIC_666);
        assertEq(topic42Rows.length, 1, "one claim under topic 42");
        assertEq(topic42Rows[0].claimId, aliceState.stateClaims()[1].claimId, "same row as the full list");
        assertEq(aliceState.stateClaims(Constants.CLAIM_TOPIC_42, 0, 1).length, 1, "end inside the set");
        assertEq(aliceState.stateClaims(Constants.CLAIM_TOPIC_42, 1, 10).length, 0, "start past the set");
    }

    function test_stateClaims_ReturnsNoRowsWhenTheIdentityHoldsNoClaim() public {
        vm.prank(alice);
        IERC735(address(aliceIdentity)).removeClaim(aliceClaim666.id);

        assertEq(aliceState.stateClaims().length, 0, "alice holds no claim any more");
    }

    // ---- helpers ----

    function _installOnAlice() internal {
        vm.startPrank(alice);
        _installFallback(Erc8100Module.stateXmlTemplate.selector);
        _installFallback(Erc8100Module.stateClaimTopics.selector);
        _installFallback(bytes4(keccak256("stateKeys()")));
        _installFallback(bytes4(keccak256("stateKeys(uint256,uint256)")));
        _installFallback(bytes4(keccak256("stateClaims()")));
        _installFallback(bytes4(keccak256("stateClaims(uint256,uint256,uint256)")));
        vm.stopPrank();
    }

    function _installFallback(bytes4 selector) internal {
        aliceIdentity.installModule(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(selector));
    }

    function _addClaim42ToAlice() internal {
        ClaimSignerHelper.Claim memory claim42 = ClaimSignerHelper.buildClaim(
            claimIssuerOwnerPk,
            claimIssuerOwner,
            address(aliceIdentity),
            address(claimIssuer),
            Constants.CLAIM_TOPIC_42,
            hex"1234",
            "https://example.com/42"
        );
        vm.prank(alice);
        IERC735(address(aliceIdentity))
            .addClaim(claim42.topic, claim42.scheme, claim42.issuer, claim42.signature, claim42.data, claim42.uri);
    }

    /// @dev The issuer's MANAGEMENT key swaps the handler that answers `isClaimValid` on the
    ///      issuer identity. No grant from alice is needed, which is why alice cannot opt out.
    function _replaceIssuerIsClaimValidHandler(address handler) internal {
        bytes memory selector = abi.encodePacked(IIdentity.isClaimValid.selector);
        vm.startPrank(claimIssuerOwner);
        claimIssuer.uninstallModule(MODULE_TYPE_FALLBACK, address(onchainidSetup.signatureValidator), selector);
        claimIssuer.installModule(MODULE_TYPE_FALLBACK, handler, selector);
        vm.stopPrank();
    }

    function _purposesOf(Erc8100Module.Key[] memory rows, bytes32 keyHash) internal pure returns (string memory) {
        for (uint256 i = 0; i < rows.length; i++) {
            if (rows[i].keyHash == keyHash) return rows[i].purposes;
        }
        revert("key not listed");
    }

    function _keyTypeOf(Erc8100Module.Key[] memory rows, bytes32 keyHash) internal pure returns (uint256) {
        for (uint256 i = 0; i < rows.length; i++) {
            if (rows[i].keyHash == keyHash) return rows[i].keyType;
        }
        revert("key not listed");
    }

    function _contains(string memory text, string memory needle) internal pure returns (bool) {
        return vm.indexOf(text, needle) != type(uint256).max;
    }

}
