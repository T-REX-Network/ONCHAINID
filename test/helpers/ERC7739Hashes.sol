// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IERC5267 } from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @notice The hashes a key signs so that an identity accepts its signature over ERC-1271. The
///         identity binds every signature to its own EIP-712 domain, following ERC-7739: the
///         app's hash is nested inside a `PersonalSign` or `TypedDataSign` struct.
library ERC7739Hashes {

    bytes32 internal constant PERSONAL_SIGN_TYPEHASH = keccak256("PersonalSign(bytes prefixed)");

    /// @notice What a key signs so that `account` accepts its signature of `hash` as a personal
    ///         message. The resulting signature is passed to the account as is.
    function personalSign(address account, bytes32 hash) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(PERSONAL_SIGN_TYPEHASH, hash));
        return MessageHashUtils.toTypedDataHash(domainSeparator(account), structHash);
    }

    /// @notice What a key signs so that `account` accepts its signature of an app's typed data.
    ///         `contentsType` is the app's EIP-712 type, such as "Mail(uint256 id)", and
    ///         `contentsName` its name ("Mail"). The signature is then wrapped with
    ///         `ERC7739Utils.encodeTypedDataSig`.
    function typedDataSign(
        address account,
        bytes32 appSeparator,
        bytes32 contentsHash,
        string memory contentsName,
        string memory contentsType
    ) internal view returns (bytes32) {
        bytes32 typehash = keccak256(
            abi.encodePacked(
                "TypedDataSign(",
                contentsName,
                " contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                contentsType
            )
        );
        (, string memory name, string memory version, uint256 chainId, address verifyingContract, bytes32 salt,) =
            IERC5267(account).eip712Domain();
        bytes32 structHash = keccak256(
            abi.encodePacked(
                typehash,
                contentsHash,
                abi.encode(keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract, salt)
            )
        );
        return MessageHashUtils.toTypedDataHash(appSeparator, structHash);
    }

    function domainSeparator(address account) internal view returns (bytes32) {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
        ) = IERC5267(account).eip712Domain();
        return MessageHashUtils.toDomainSeparator(fields, name, version, chainId, verifyingContract, salt);
    }

}
