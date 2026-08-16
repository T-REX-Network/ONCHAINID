// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

import { Identity } from "contracts/Identity.sol";

/// @notice Identity implementation reporting a bumped EIP-712 version, simulating an upgrade
///         that changes the signing domain.
contract ShiftedDomainIdentity is Identity {

    constructor(address registryModule_, address identityFactory_) Identity(registryModule_, identityFactory_) { }

    function eip712Domain()
        public
        view
        override
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        return (hex"0f", "OnchainID", "2", block.chainid, address(this), bytes32(0), new uint256[](0));
    }

}
