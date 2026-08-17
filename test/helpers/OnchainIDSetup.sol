// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Constants } from "../utils/Constants.sol";
import { ClaimSignerHelper } from "./ClaimSignerHelper.sol";
import { IdentityHelper } from "./IdentityHelper.sol";
import { UpgradeableBeacon } from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import { Identity } from "contracts/Identity.sol";
import { IdentityFactory } from "contracts/factory/IdentityFactory.sol";
import { IIdentity } from "contracts/interface/IIdentity.sol";
import { IdentityTypes } from "contracts/libraries/IdentityTypes.sol";
import { KeyPurposes } from "contracts/libraries/KeyPurposes.sol";
import { KeyTypes } from "contracts/libraries/KeyTypes.sol";
import { Structs } from "contracts/storage/Structs.sol";
import { Test } from "forge-std/Test.sol";

/// @notice Base test contract providing full OnchainID infrastructure
contract OnchainIDSetup is Test {

    // Infrastructure
    IdentityHelper.OnchainIDSetup public onchainidSetup;

    // Standard test addresses with private keys
    address public deployer;
    uint256 public deployerPk;

    address public claimIssuerOwner;
    uint256 public claimIssuerOwnerPk;

    address public alice;
    uint256 public alicePk;

    address public bob;
    uint256 public bobPk;

    address public carol;
    uint256 public carolPk;

    address public david;
    uint256 public davidPk;

    address public tokenOwner;
    uint256 public tokenOwnerPk;

    // Deployed identities
    Identity public aliceIdentity;
    Identity public bobIdentity;
    Identity public claimIssuer; // Identity with the claim module installed (was a standalone ClaimIssuer)

    // Pre-built claim
    ClaimSignerHelper.Claim public aliceClaim666;

    function setUp() public virtual {
        // Create labeled addresses with known private keys
        (deployer, deployerPk) = makeAddrAndKey("deployer");
        (claimIssuerOwner, claimIssuerOwnerPk) = makeAddrAndKey("claimIssuerOwner");
        (alice, alicePk) = makeAddrAndKey("alice");
        (bob, bobPk) = makeAddrAndKey("bob");
        (carol, carolPk) = makeAddrAndKey("carol");
        (david, davidPk) = makeAddrAndKey("david");
        (tokenOwner, tokenOwnerPk) = makeAddrAndKey("tokenOwner");

        // Deploy factory infrastructure (as deployer)
        vm.startPrank(deployer);
        onchainidSetup = IdentityHelper.deployFactory(deployer);
        vm.stopPrank();

        // ClaimIssuer is now just an Identity with type CLAIM_ISSUER and the claim module installed.
        vm.prank(deployer);
        Structs.KeyParam[] memory issuerKeys = new Structs.KeyParam[](2);
        issuerKeys[0] = Structs.KeyParam({
            keyHash: keccak256(abi.encodePacked(claimIssuerOwner)),
            purpose: KeyPurposes.MANAGEMENT,
            keyType: KeyTypes.ECDSA,
            signerData: abi.encodePacked(claimIssuerOwner),
            clientData: ""
        });
        issuerKeys[1] = Structs.KeyParam({
            keyHash: ClaimSignerHelper.addressToKey(claimIssuerOwner),
            purpose: KeyPurposes.CLAIM_SIGNER,
            keyType: KeyTypes.ECDSA,
            signerData: abi.encodePacked(claimIssuerOwner),
            clientData: ""
        });
        address claimIssuerAddr = onchainidSetup.idFactory
            .createIdentityFor(claimIssuerOwner, IdentityTypes.CLAIM_ISSUER, "claimIssuer", issuerKeys);
        claimIssuer = Identity(payable(claimIssuerAddr));

        // No validator install on the issuer: the merged module's `isClaimValid` verifies the
        // claim signature directly via `SignatureChecker` (ERC-7913 dispatch). It does not
        // round-trip through any installed validator on the issuer.

        // Create alice identity via factory
        vm.prank(deployer);
        Structs.KeyParam[] memory aliceKeys = new Structs.KeyParam[](1);
        aliceKeys[0] = Structs.KeyParam({
            keyHash: keccak256(abi.encodePacked(alice)),
            purpose: KeyPurposes.MANAGEMENT,
            keyType: KeyTypes.ECDSA,
            signerData: abi.encodePacked(alice),
            clientData: ""
        });
        address aliceIdentityAddr =
            onchainidSetup.idFactory.createIdentityFor(alice, IdentityTypes.INDIVIDUAL, "alice", aliceKeys);
        aliceIdentity = Identity(payable(aliceIdentityAddr));

        // The merged ERC734Validator is already installed as a validator by `legacyQueueModules`
        // during `initialize`, and `alice` is seeded as its MANAGEMENT key from the `_keys` array.
        // The registry (keys) now lives entirely in that one module, reached by the account via
        // fallback for external reads and via a staticcall for its own auth gates.

        // Add carol as CLAIM_SIGNER and david as ACTION key on alice's identity. These go through
        // the account write path (`addKeyWithData`), which forwards into the enshrined module.
        vm.startPrank(alice);
        aliceIdentity.addKeyWithData(
            ClaimSignerHelper.addressToKey(carol), KeyPurposes.CLAIM_SIGNER, KeyTypes.ECDSA, abi.encodePacked(carol), ""
        );
        aliceIdentity.addKeyWithData(
            ClaimSignerHelper.addressToKey(david), KeyPurposes.ACTION, KeyTypes.ECDSA, abi.encodePacked(david), ""
        );
        vm.stopPrank();

        // Build and add alice's claim 666
        aliceClaim666 = ClaimSignerHelper.buildClaim(
            claimIssuerOwnerPk,
            claimIssuerOwner,
            address(aliceIdentity),
            address(claimIssuer),
            Constants.CLAIM_TOPIC_666,
            hex"0042",
            "https://example.com"
        );

        vm.prank(alice);
        IIdentity(address(aliceIdentity))
            .addClaim(
                aliceClaim666.topic,
                aliceClaim666.scheme,
                aliceClaim666.issuer,
                aliceClaim666.signature,
                aliceClaim666.data,
                aliceClaim666.uri
            );

        // Create bob identity via factory
        vm.prank(deployer);
        Structs.KeyParam[] memory bobKeys = new Structs.KeyParam[](1);
        bobKeys[0] = Structs.KeyParam({
            keyHash: keccak256(abi.encodePacked(bob)),
            purpose: KeyPurposes.MANAGEMENT,
            keyType: KeyTypes.ECDSA,
            signerData: abi.encodePacked(bob),
            clientData: ""
        });
        address bobIdentityAddr =
            onchainidSetup.idFactory.createIdentityFor(bob, IdentityTypes.INDIVIDUAL, "bob", bobKeys);
        bobIdentity = Identity(payable(bobIdentityAddr));

        // Create token identity
        vm.prank(deployer);
        Structs.KeyParam[] memory tokenKeys = new Structs.KeyParam[](1);
        tokenKeys[0] = Structs.KeyParam({
            keyHash: keccak256(abi.encodePacked(tokenOwner)),
            purpose: KeyPurposes.MANAGEMENT,
            keyType: KeyTypes.ECDSA,
            signerData: abi.encodePacked(tokenOwner),
            clientData: ""
        });
        // ASSET is a single-binding type: the sole-management check is skipped.
        onchainidSetup.idFactory
            .createIdentityFor(Constants.TOKEN_ADDRESS, IdentityTypes.ASSET, "tokenOwner", tokenKeys);
    }

    // ---- Convenience getters ----

    function getIdFactory() public view returns (IdentityFactory) {
        return onchainidSetup.idFactory;
    }

    function getBeacon() public view returns (UpgradeableBeacon) {
        return onchainidSetup.beacon;
    }

    function getIdentityImplementation() public view returns (Identity) {
        return onchainidSetup.identityImplementation;
    }

}
