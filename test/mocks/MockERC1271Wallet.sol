// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// Minimal ERC-1271 smart wallet: validates by recovering the signature and checking it matches `owner`.
// Used by IdFactory tests to exercise the SignatureChecker ERC-1271 branch.
contract MockERC1271Wallet {

    bytes4 internal constant _ERC1271_MAGIC_VALUE = 0x1626ba7e;

    address public immutable owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == owner) {
            return _ERC1271_MAGIC_VALUE;
        }
        return 0xffffffff;
    }

}
