// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import { ERC7579Validator } from "contracts/modules/validators/ERC7579Validator.sol";

/// @title MockStockECDSAValidator (test-only)
/// @notice Test mock demonstrating that a "stock" ERC-7579 validator — one that has
///         zero ONCHAINID awareness, no ERC-734 lookups, and a plain 65-byte ECDSA
///         signature wire format — drops into a SmartAccount without any adapter.
///         The account performs no ERC-734 purpose check on the user-op path: an
///         installed validator is trusted to scope its own signers, so whoever this
///         mock accepts can act for the account.
/// @dev Shape mirrors OpenZeppelin's ERC7579ECDSAValidator (see the vendored
///      openzeppelin-accounts package). Not a shipping contract.
contract MockStockECDSAValidator is ERC7579Validator {

    mapping(address account => address signer) private _signers;

    event SignerSet(address indexed account, address signer);

    /// @dev Reads a 20-byte packed address from `data` as the per-account signer.
    ///      Matches OZ convention: `abi.encodePacked(address signer)`.
    function onInstall(bytes calldata data) public virtual override {
        require(data.length >= 20, "invalid signer");
        address newSigner = address(bytes20(data[:20]));
        require(newSigner != address(0), "zero signer");
        _signers[msg.sender] = newSigner;
        emit SignerSet(msg.sender, newSigner);
    }

    function onUninstall(
        bytes calldata /* data */
    )
        public
        virtual
        override
    {
        delete _signers[msg.sender];
        emit SignerSet(msg.sender, address(0));
    }

    function signer(address account) public view returns (address) {
        return _signers[account];
    }

    /// @dev Plain 65-byte ECDSA signature over `hash`. Zero wrapping, zero ERC-734.
    function _rawERC7579Validation(address account, bytes32 hash, bytes calldata signature)
        internal
        view
        virtual
        override
        returns (bool)
    {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        return err == ECDSA.RecoverError.NoError && recovered == _signers[account];
    }

}
