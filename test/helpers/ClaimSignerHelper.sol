// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IIdentity } from "contracts/interface/IIdentity.sol";
import { Structs } from "contracts/storage/Structs.sol";
import { Vm } from "forge-std/Vm.sol";

/// @notice Helper library for building and signing claims in tests.
/// @dev    Signature wire format: `abi.encode(bytes signer, bytes rawSig)` where `signer`
///         follows ERC-7913 (`len==20` for EOA / ERC-1271; `len>20` for verifier(20) || key(rest)).
///         The claim is signed against the nested EIP-712 struct
///         `Claim(uint256 topic,address subject,ClaimData data)` with
///         `ClaimData(uint256 issuedAt,uint256 validUntil,bytes32 metadataHash,bytes payload)`.
///         `metadataHash` must commit to the scheme and uri the claim is added with.
library ClaimSignerHelper {

    struct Claim {
        address identity;
        address issuer;
        uint256 topic;
        uint256 scheme;
        Structs.ClaimData data;
        bytes signature;
        string uri;
        bytes32 id;
    }

    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function computeClaimId(address issuer, uint256 topic) internal pure returns (bytes32) {
        return keccak256(abi.encode(issuer, topic));
    }

    function addressToKey(address addr) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(addr));
    }

    /// @notice The scheme+uri commitment `_addClaim` checks `ClaimData.metadataHash` against.
    function metadataHash(uint256 scheme, string memory uri) internal pure returns (bytes32) {
        return keccak256(abi.encode(scheme, keccak256(bytes(uri))));
    }

    /// @notice Signs a claim using the issuer contract's EIP-712 domain.
    function signClaim(
        uint256 signerPk,
        address signerAddr,
        address issuerContract,
        address identity,
        uint256 topic,
        Structs.ClaimData memory data
    ) internal view returns (bytes memory) {
        bytes32 digest = IIdentity(issuerContract).getClaimHash(identity, topic, data);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        bytes memory rawSig = abi.encodePacked(r, s, v);
        bytes memory signer = abi.encodePacked(signerAddr);
        return abi.encode(signer, rawSig);
    }

    /// @notice Convenience overload: `issuedAt = block.timestamp`, no expiry, committed to
    ///         scheme 1 and an empty uri.
    function signClaim(
        uint256 signerPk,
        address signerAddr,
        address issuerContract,
        address identity,
        uint256 topic,
        bytes memory payload
    ) internal view returns (bytes memory) {
        Structs.ClaimData memory data = Structs.ClaimData({
            issuedAt: block.timestamp, validUntil: 0, metadataHash: metadataHash(1, ""), payload: payload
        });
        return signClaim(signerPk, signerAddr, issuerContract, identity, topic, data);
    }

    /// @notice Builds a complete Claim struct with computed id and EIP-712 signature.
    function buildClaim(
        uint256 signerPk,
        address signerAddr,
        address identityAddr,
        address issuerAddr,
        uint256 topic,
        bytes memory payload,
        string memory uri
    ) internal view returns (Claim memory claim) {
        claim.identity = identityAddr;
        claim.issuer = issuerAddr;
        claim.topic = topic;
        claim.scheme = 1;
        claim.data = Structs.ClaimData({
            issuedAt: block.timestamp, validUntil: 0, metadataHash: metadataHash(1, uri), payload: payload
        });
        claim.uri = uri;
        claim.id = computeClaimId(issuerAddr, topic);
        claim.signature = signClaim(signerPk, signerAddr, issuerAddr, identityAddr, topic, claim.data);
    }

}
