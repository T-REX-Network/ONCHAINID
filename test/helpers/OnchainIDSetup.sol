// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Constants } from "../utils/Constants.sol";
import { ClaimSignerHelper } from "./ClaimSignerHelper.sol";
import { IdentityHelper } from "./IdentityHelper.sol";
import { UpgradeableBeacon } from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { InteroperableAddress } from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
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

    bytes32 internal constant _CREATE_FOR_TYPEHASH =
        keccak256("CreateIdentityFor(bytes account,bytes32 keysHash,uint256 nonce,uint256 expiry)");

    /// @dev Sign a createIdentityFor approval for a signable identity type. `_account` (the
    ///      wallet the identity is being deployed for) signs over the exact key set with its
    ///      own key. Returns a 65-byte EOA signature the factory verifies via SignatureChecker.
    function _signCreateFor(
        uint256 signerPk,
        address account,
        Structs.KeyParam[] memory keys,
        uint256 nonce,
        uint256 expiry
    ) internal view returns (bytes memory) {
        bytes memory envelope = InteroperableAddress.formatEvmV1(block.chainid, account);
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("IdentityFactory")),
                keccak256(bytes("1")),
                block.chainid,
                address(onchainidSetup.idFactory)
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(_CREATE_FOR_TYPEHASH, keccak256(envelope), keccak256(abi.encode(keys)), nonce, expiry)
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        return abi.encodePacked(r, s, v);
    }

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
        uint256 issuerExpiry = block.timestamp + 1 hours;
        uint256 issuerNonce =
            onchainidSetup.idFactory.nonceForAccount(InteroperableAddress.formatEvmV1(block.chainid, claimIssuerOwner));
        address claimIssuerAddr = onchainidSetup.idFactory
            .createIdentityFor(
                claimIssuerOwner,
                IdentityTypes.CLAIM_ISSUER,
                "claimIssuer",
                issuerKeys,
                IdentityHelper.legacyQueueModules(
                    address(onchainidSetup.keyApprovalModule), address(onchainidSetup.signatureValidator)
                ),
                _signCreateFor(claimIssuerOwnerPk, claimIssuerOwner, issuerKeys, issuerNonce, issuerExpiry),
                issuerNonce,
                issuerExpiry
            );
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
        uint256 aliceExpiry = block.timestamp + 1 hours;
        uint256 aliceNonce =
            onchainidSetup.idFactory.nonceForAccount(InteroperableAddress.formatEvmV1(block.chainid, alice));
        address aliceIdentityAddr = onchainidSetup.idFactory
            .createIdentityFor(
                alice,
                IdentityTypes.INDIVIDUAL,
                "alice",
                aliceKeys,
                IdentityHelper.legacyQueueModules(
                    address(onchainidSetup.keyApprovalModule), address(onchainidSetup.signatureValidator)
                ),
                _signCreateFor(alicePk, alice, aliceKeys, aliceNonce, aliceExpiry),
                aliceNonce,
                aliceExpiry
            );
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
        uint256 bobExpiry = block.timestamp + 1 hours;
        uint256 bobNonce =
            onchainidSetup.idFactory.nonceForAccount(InteroperableAddress.formatEvmV1(block.chainid, bob));
        address bobIdentityAddr = onchainidSetup.idFactory
            .createIdentityFor(
                bob,
                IdentityTypes.INDIVIDUAL,
                "bob",
                bobKeys,
                IdentityHelper.legacyQueueModules(
                    address(onchainidSetup.keyApprovalModule), address(onchainidSetup.signatureValidator)
                ),
                _signCreateFor(bobPk, bob, bobKeys, bobNonce, bobExpiry),
                bobNonce,
                bobExpiry
            );
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
        // ASSET is a single-binding type: signature/nonce/expiry are ignored.
        onchainidSetup.idFactory
            .createIdentityFor(
                Constants.TOKEN_ADDRESS,
                IdentityTypes.ASSET,
                "tokenOwner",
                tokenKeys,
                IdentityHelper.legacyQueueModules(
                    address(onchainidSetup.keyApprovalModule), address(onchainidSetup.signatureValidator)
                ),
                "",
                0,
                0
            );
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
