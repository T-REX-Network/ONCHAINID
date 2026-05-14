// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IdFactory } from "../factory/IdFactory.sol";
import { Errors } from "../libraries/Errors.sol";
import { Structs } from "../storage/Structs.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title Gateway
 * @notice Signature-gated entry point for the OnchainID Factory.
 * @dev Validates signed deployment requests from approved signers with optional expiry.
 *      Signatures follow EIP-712: signers use `eth_signTypedData_v4`, wallets render a
 *      structured prompt instead of an opaque hash.
 */
contract Gateway is Ownable, EIP712 {

    using ECDSA for bytes32;

    /// @dev EIP-712 typehash for a deployment authorization. Mirrors `deployIdentityWithSalt`'s
    ///      signed fields. The `keys` and `modules` arrays are encoded by hashing each element
    ///      under its own typehash and concatenating those hashes, per the EIP-712 array rule.
    bytes32 private constant _DEPLOY_TYPEHASH = keccak256(
        "Deploy(address identityOwner,uint256 identityType,string salt,KeyParam[] keys,ModuleInstall[] modules,uint256 signatureExpiry)KeyParam(bytes32 keyHash,uint256 purpose,uint256 keyType,bytes signerData,bytes clientData)ModuleInstall(uint256 moduleType,address module,bytes initData)"
    );

    bytes32 private constant _KEY_PARAM_TYPEHASH = keccak256(
        "KeyParam(bytes32 keyHash,uint256 purpose,uint256 keyType,bytes signerData,bytes clientData)"
    );

    bytes32 private constant _MODULE_INSTALL_TYPEHASH = keccak256(
        "ModuleInstall(uint256 moduleType,address module,bytes initData)"
    );

    /// @notice The IdFactory contract this Gateway operates.
    IdFactory public immutable idFactory;

    /// @notice Mapping of approved signer addresses that can authorize ONCHAINID deployments.
    mapping(address => bool) public approvedSigners;

    /// @notice Mapping of revoked signatures to prevent replay.
    mapping(bytes => bool) public revokedSignatures;

    /// @dev Emitted when a signer is approved to authorize deployments.
    event SignerApproved(address indexed signer);

    /// @dev Emitted when a signer's approval is revoked.
    event SignerRevoked(address indexed signer);

    /// @dev Emitted when a deployment signature is revoked.
    event SignatureRevoked(bytes indexed signature);

    /// @dev Emitted when a previously revoked signature is re-approved.
    event SignatureApproved(bytes indexed signature);

    /**
     * @notice Constructor for the ONCHAINID Factory Gateway.
     * @param idFactoryAddress the address of the factory to operate (the Gateway must be owner of the Factory).
     * @param signersToApprove initial list of approved signers (max 10).
     */
    constructor(address idFactoryAddress, address[] memory signersToApprove)
        Ownable(msg.sender)
        EIP712("OnchainIDGateway", "1")
    {
        require(idFactoryAddress != address(0), Errors.ZeroAddress());
        require(signersToApprove.length <= 10, Errors.TooManySigners());

        for (uint256 i = 0; i < signersToApprove.length; i++) {
            approvedSigners[signersToApprove[i]] = true;
        }

        idFactory = IdFactory(idFactoryAddress);
    }

    /**
     * @notice Approve a signer to authorize ONCHAINID deployments.
     * @param signer the signer address to approve.
     */
    function approveSigner(address signer) external onlyOwner {
        require(signer != address(0), Errors.ZeroAddress());
        require(!approvedSigners[signer], Errors.SignerAlreadyApproved(signer));
        approvedSigners[signer] = true;
        emit SignerApproved(signer);
    }

    /**
     * @notice Revoke a signer's authorization for ONCHAINID deployments.
     * @param signer the signer address to revoke.
     */
    function revokeSigner(address signer) external onlyOwner {
        require(signer != address(0), Errors.ZeroAddress());
        require(approvedSigners[signer], Errors.SignerAlreadyNotApproved(signer));
        delete approvedSigners[signer];
        emit SignerRevoked(signer);
    }

    /**
     * @notice Deploy an ONCHAINID via the factory with a signed authorization.
     * @dev The operation must be signed by an approved signer. The frontend builds
     *      the full key list (any purposes, any key types) and ERC-7579 modules.
     *      The signed message includes all parameters to prevent tampering.
     * @param identityOwner the wallet address to link to the identity.
     * @param identityType the identity type (see IdentityTypes library).
     * @param salt the salt for CREATE2 deployment.
     * @param keys the full list of keys with purposes, types, and signer data — built by the frontend.
     * @param modules the ERC-7579 modules to install during creation — built by the frontend.
     * @param signatureExpiry block timestamp when the signature expires (0 = no expiry).
     * @param signature the signed authorization from an approved signer.
     * @return the address of the deployed identity.
     */
    function deployIdentityWithSalt(
        address identityOwner,
        uint256 identityType,
        string memory salt,
        Structs.KeyParam[] calldata keys,
        Structs.ModuleInstall[] calldata modules,
        uint256 signatureExpiry,
        bytes calldata signature
    ) external returns (address) {
        require(identityOwner != address(0), Errors.ZeroAddress());
        require(signatureExpiry == 0 || block.timestamp <= signatureExpiry, Errors.ExpiredSignature(signature));

        {
            bytes32 digest = _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        _DEPLOY_TYPEHASH,
                        identityOwner,
                        identityType,
                        keccak256(bytes(salt)),
                        _hashKeyParams(keys),
                        _hashModuleInstalls(modules),
                        signatureExpiry
                    )
                )
            );
            address signer = digest.recover(signature);

            require(approvedSigners[signer], Errors.UnapprovedSigner(signer));
            require(!revokedSignatures[signature], Errors.RevokedSignature(signature));
        }

        return idFactory.createIdentity(identityOwner, identityType, salt, keys, modules);
    }

    /// @notice The EIP-712 domain separator used by `deployIdentityWithSalt`. Off-chain signers
    ///         can fetch this directly instead of recomputing the domain themselves.
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @dev Hashes a `KeyParam[]` per EIP-712's array encoding: keccak256 of the concatenation
    ///      of each element's struct hash.
    function _hashKeyParams(Structs.KeyParam[] calldata keys) private pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](keys.length);
        for (uint256 i = 0; i < keys.length; i++) {
            hashes[i] = keccak256(
                abi.encode(
                    _KEY_PARAM_TYPEHASH,
                    keys[i].keyHash,
                    keys[i].purpose,
                    keys[i].keyType,
                    keccak256(keys[i].signerData),
                    keccak256(keys[i].clientData)
                )
            );
        }
        return keccak256(abi.encodePacked(hashes));
    }

    /// @dev Hashes a `ModuleInstall[]` per EIP-712's array encoding.
    function _hashModuleInstalls(Structs.ModuleInstall[] calldata modules) private pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](modules.length);
        for (uint256 i = 0; i < modules.length; i++) {
            hashes[i] = keccak256(
                abi.encode(
                    _MODULE_INSTALL_TYPEHASH,
                    modules[i].moduleType,
                    modules[i].module,
                    keccak256(modules[i].initData)
                )
            );
        }
        return keccak256(abi.encodePacked(hashes));
    }

    /**
     * @notice Deploy an ONCHAINID using the identityOwner address as salt. No signature required.
     * @dev Convenience method for self-service deployment. Anyone can call this on behalf of
     *      any identityOwner. The frontend builds the full key list and modules.
     * @param identityOwner the wallet address to link and use as salt.
     * @param identityType the identity type (see IdentityTypes library).
     * @param keys the full list of keys with purposes, types, and signer data — built by the frontend.
     * @param modules the ERC-7579 modules to install during creation — built by the frontend.
     * @return the address of the deployed identity.
     */
    function deployIdentityForWallet(
        address identityOwner,
        uint256 identityType,
        Structs.KeyParam[] calldata keys,
        Structs.ModuleInstall[] calldata modules
    ) external returns (address) {
        require(identityOwner != address(0), Errors.ZeroAddress());
        return idFactory.createIdentity(identityOwner, identityType, Strings.toHexString(identityOwner), keys, modules);
    }

    /**
     * @notice Revoke a signature to prevent it from being used for deployment.
     * @param signature the signature to revoke.
     */
    function revokeSignature(bytes calldata signature) external onlyOwner {
        require(!revokedSignatures[signature], Errors.SignatureAlreadyRevoked(signature));
        revokedSignatures[signature] = true;
        emit SignatureRevoked(signature);
    }

    /**
     * @notice Remove a signature from the revoke list, allowing it to be used again.
     * @param signature the signature to re-approve.
     */
    function approveSignature(bytes calldata signature) external onlyOwner {
        require(revokedSignatures[signature], Errors.SignatureNotRevoked(signature));
        delete revokedSignatures[signature];
        emit SignatureApproved(signature);
    }

    /**
     * @notice Transfer the ownership of the factory to a new owner.
     * @param newOwner the new owner of the factory.
     */
    function transferFactoryOwnership(address newOwner) external onlyOwner {
        idFactory.transferOwnership(newOwner);
    }

    /**
     * @notice Call any function on the factory. Owner-only escape hatch.
     *
     * @dev WARNING: this is a raw, unrestricted passthrough to the underlying `IdFactory`. The
     *      Gateway owner can invoke any factory function with arbitrary calldata, bypassing
     *      every Gateway-level check (signer approval, signature expiry, signature revocation).
     *      Intended for operational recovery and migrations only. Anyone auditing Gateway
     *      permissions should treat the Gateway owner as having full factory authority.
     *
     * @param data the calldata to forward to the factory.
     */
    function callFactory(bytes memory data) external onlyOwner {
        (bool success,) = address(idFactory).call(data);
        require(success, Errors.CallToFactoryFailed());
    }

}
