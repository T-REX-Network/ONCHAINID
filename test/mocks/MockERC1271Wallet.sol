// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @notice Minimal ERC-1271 wallet backed by an EOA signer. Used in tests to exercise the
///         ERC-1271 path in `IdentityFactory.linkAccount` via OZ `SignatureChecker`.
contract MockERC1271Wallet is IERC1271 {

    bytes4 internal constant _MAGIC_VALUE = 0x1626ba7e; // bytes4(keccak256("isValidSignature(bytes32,bytes)"))

    address public immutable owner;

    constructor(address signer) {
        owner = signer;
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash, bytes memory signature) external view override returns (bytes4) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == owner) {
            return _MAGIC_VALUE;
        }
        return 0xffffffff;
    }

}
