// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

/// @notice Mock identity whose initialize always reverts, causing IdentityProxy CREATE3 to fail.
///         It still answers the factory's beacon shape check (same factory, locked initializers,
///         a registry module) so the revert happens at deploy time, not at beacon setup.
contract RevertingIdentity {

    address private immutable _identityFactory;
    address private immutable _registryModule;

    constructor(address identityFactory_, address registryModule_) {
        _identityFactory = identityFactory_;
        _registryModule = registryModule_;
    }

    function identityFactory() external view returns (address) {
        return _identityFactory;
    }

    function registryModule() external view returns (address) {
        return _registryModule;
    }

    function initializedVersion() external pure returns (uint64) {
        return type(uint64).max;
    }

    function initialize(address) external pure {
        revert("forced revert");
    }

}
