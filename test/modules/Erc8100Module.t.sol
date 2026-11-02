// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ClaimSignerHelper } from "../helpers/ClaimSignerHelper.sol";
import { OnchainIDSetup } from "../helpers/OnchainIDSetup.sol";
import { Constants } from "../utils/Constants.sol";
import {
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import { IdentityUtilities } from "contracts/IdentityUtilities.sol";
import { IERC735 } from "contracts/interface/IERC735.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { IIdentityUtilities } from "contracts/interface/IIdentityUtilities.sol";
import { IXMLRepresentableState } from "contracts/interface/IRepresentableState.sol";
import { Errors } from "contracts/libraries/Errors.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Erc8100Module } from "contracts/modules/fallbacks/Erc8100Module.sol";
import { IdentityUtilitiesProxy } from "contracts/proxy/IdentityUtilitiesProxy.sol";

/// @notice The ERC-8100 module, exercised the way a renderer uses it: every call goes to the
///         identity address and lands on the module through the fallback.
contract Erc8100ModuleTest is OnchainIDSetup {

    IdentityUtilities internal utilities;
    Erc8100Module internal module;

    /// The identity address typed as the module, so calls dispatch through the fallback.
    Erc8100Module internal aliceState;

    function setUp() public override {
        super.setUp();

        // The harness's AccessManager governs the registry; `deployer` holds its ADMIN_ROLE.
        IdentityUtilities implementation = new IdentityUtilities();
        utilities = IdentityUtilities(
            address(new IdentityUtilitiesProxy(address(implementation), address(onchainidSetup.accessManager)))
        );
        _registerSchema(Constants.CLAIM_TOPIC_666, "Demo", "code", "bytes");

        module = new Erc8100Module(IIdentityUtilities(address(utilities)));
        _installOnAlice();
        aliceState = Erc8100Module(address(aliceIdentity));
    }

    // ---- lifecycle ----

    function test_constructor_RevertWhen_TheRegistryIsZero() public {
        vm.expectRevert(Errors.ZeroAddress.selector);
        new Erc8100Module(IIdentityUtilities(address(0)));
    }

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
        assertTrue(_contains(template, "evmstate:call='claimTopics()(uint256[])'"));
        assertTrue(_contains(template, "evmstate:call='keys()(tuple(bytes32,uint256,string)[])'"));
        assertTrue(_contains(template, "evmstate:call='claims()"));
    }

    // ---- topics ----

    function test_claimTopics_MirrorsTheRegisteredSchemas() public {
        uint256[] memory topics = aliceState.claimTopics();
        assertEq(topics.length, 1);
        assertEq(topics[0], Constants.CLAIM_TOPIC_666);

        _registerSchema(Constants.CLAIM_TOPIC_42, "ISIN", "isin", "string");
        assertEq(aliceState.claimTopics().length, 2);

        vm.prank(deployer);
        utilities.removeTopic(Constants.CLAIM_TOPIC_666);
        topics = aliceState.claimTopics();
        assertEq(topics.length, 1);
        assertEq(topics[0], Constants.CLAIM_TOPIC_42);
    }

    // ---- keys ----

    function test_keys_ListsEachKeyOnceWithItsPurposes() public {
        vm.prank(alice);
        aliceIdentity.addKeyWithData(
            ClaimSignerHelper.addressToKey(carol), KeyPurposes.ACTION, KeyTypes.ECDSA, abi.encodePacked(carol), ""
        );
        address queueModule = address(onchainidSetup.keyApprovalModule);

        Erc8100Module.Key[] memory rows = aliceState.keys();

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

    function test_keys_PaginatesOverTheKeyList() public view {
        Erc8100Module.Key[] memory all = aliceState.keys();
        Erc8100Module.Key[] memory firstTwo = aliceState.keys(0, 2);
        Erc8100Module.Key[] memory tail = aliceState.keys(2, 100);

        assertEq(all.length, 4);
        assertEq(firstTwo.length, 2);
        assertEq(tail.length, 2);
        assertEq(firstTwo[0].keyHash, all[0].keyHash);
        assertEq(tail[0].keyHash, all[2].keyHash);
    }

    // ---- claims ----

    function test_claims_ReturnsClaim666AsValidWithItsRawPayload() public view {
        Erc8100Module.Claim[] memory rows = aliceState.claims();

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

    function test_claims_ReportsUnknownStatusWhenTheIssuerReverts() public {
        vm.mockCallRevert(address(claimIssuer), IIdentity.isClaimValid.selector, "down");

        Erc8100Module.Claim[] memory rows = aliceState.claims();

        assertEq(rows.length, 1);
        assertEq(rows[0].status, 0);
    }

    function test_claims_ReportsInvalidWhenTheIssuerSaysSo() public {
        vm.mockCall(address(claimIssuer), IIdentity.isClaimValid.selector, abi.encode(false));

        Erc8100Module.Claim[] memory rows = aliceState.claims();

        assertEq(rows[0].status, 2);
    }

    function test_claims_SkipsClaimsWhoseTopicHasNoSchema() public {
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

        Erc8100Module.Claim[] memory rows = aliceState.claims();

        assertEq(rows.length, 1);
        assertEq(rows[0].topic, Constants.CLAIM_TOPIC_666);
    }

    function test_claims_PaginatesAcrossTopics() public {
        _registerSchema(Constants.CLAIM_TOPIC_42, "ISIN", "isin", "string");
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

        assertEq(aliceState.claims().length, 2);
        assertEq(aliceState.claims(0, 1).length, 1);
        assertEq(aliceState.claims(1, 10).length, 1);
        assertEq(aliceState.claims(5, 10).length, 0);
        assertEq(aliceState.claims(1, 10)[0].claimId, aliceState.claims()[1].claimId);
    }

    function test_claims_ReturnsNoRowsWhenNoSchemaIsRegistered() public {
        vm.prank(deployer);
        utilities.removeTopic(Constants.CLAIM_TOPIC_666);

        assertEq(aliceState.claims().length, 0);
    }

    // ---- helpers ----

    function _installOnAlice() internal {
        vm.startPrank(alice);
        _installFallback(Erc8100Module.stateXmlTemplate.selector);
        _installFallback(Erc8100Module.claimTopics.selector);
        _installFallback(bytes4(keccak256("keys()")));
        _installFallback(bytes4(keccak256("keys(uint256,uint256)")));
        _installFallback(bytes4(keccak256("claims()")));
        _installFallback(bytes4(keccak256("claims(uint256,uint256)")));
        vm.stopPrank();
    }

    function _installFallback(bytes4 selector) internal {
        aliceIdentity.installModule(MODULE_TYPE_FALLBACK, address(module), abi.encodePacked(selector));
    }

    function _registerSchema(uint256 topicId, string memory name, string memory fieldName, string memory fieldType)
        internal
    {
        string[] memory names = new string[](1);
        names[0] = fieldName;
        string[] memory types = new string[](1);
        types[0] = fieldType;
        vm.prank(deployer);
        utilities.addTopic(topicId, name, abi.encode(names), abi.encode(types));
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
